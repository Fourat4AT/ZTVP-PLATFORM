param(
    [Parameter(Mandatory=$true)]
    [string]$ExternalEmail,

    [string]$GuestDisplayNamePrefix = "ZTVP ID-C-005 External Guest",

    [string]$InviteRedirectUrl = "https://portal.azure.com",

    [switch]$SendInvitationMessage
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "User.Invite.All",
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "AuditLog.Read.All"
)

function Get-ZTVPValue {
    param([object]$Object, [string]$Name)

    if ($null -eq $Object) { return $null }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ([string]$key -eq $Name) { return $Object[$key] }
        }
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }

    return $null
}

function ConvertTo-ZTVPArray {
    param([object]$Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return @($Value) }
    return @($Value)
}

function Ensure-ZTVPGraphConnection {
    param([string[]]$Scopes)

    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    $needReconnect = $false

    if (-not $ctx) {
        $needReconnect = $true
    }
    else {
        $currentScopes = @()

        if ($ctx.Scopes) {
            $currentScopes = @($ctx.Scopes | ForEach-Object { $_.ToLower() })
        }

        foreach ($scope in $Scopes) {
            if ($currentScopes -notcontains $scope.ToLower()) {
                $needReconnect = $true
            }
        }
    }

    if ($needReconnect) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
        Connect-MgGraph -Scopes $Scopes -NoWelcome | Out-Null
        $ctx = Get-MgContext
    }

    return $ctx
}

function Invoke-ZTVPPagedGraphQuery {
    param([string]$Uri, [int]$MaxPages = 10)

    $items = @()
    $page = 0
    $nextUri = $Uri

    while ($nextUri -and $page -lt $MaxPages) {
        $page++
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri
        $value = Get-ZTVPValue -Object $response -Name "value"

        if ($value) { $items += @($value) }

        $nextLink = Get-ZTVPValue -Object $response -Name "@odata.nextLink"

        if ([string]::IsNullOrWhiteSpace([string]$nextLink)) {
            $nextUri = $null
        }
        else {
            $nextUri = [string]$nextLink
        }
    }

    return $items
}

function Test-ZTVPEmail {
    param([string]$Email)

    return ($Email -match "^[^@\s]+@[^@\s]+\.[^@\s]+$")
}

function Get-ZTVPExistingGuestByMail {
    param([string]$Email)

    $safeEmail = $Email.Replace("'", "''")
    $filter = "mail eq '$safeEmail'"
    $encoded = [System.Uri]::EscapeDataString($filter)
    $uri = "https://graph.microsoft.com/v1.0/users?`$filter=$encoded&`$select=id,userPrincipalName,displayName,mail,userType,externalUserState"

    try {
        return @(Invoke-ZTVPPagedGraphQuery -Uri $uri -MaxPages 3)
    }
    catch {
        return @()
    }
}

function Get-ZTVPUserFresh {
    param([string]$UserId)

    if ([string]::IsNullOrWhiteSpace($UserId)) { return $null }

    try {
        return Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$UserId?`$select=id,userPrincipalName,displayName,mail,userType,externalUserState,createdDateTime"
    }
    catch {
        return $null
    }
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-005"
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null

$statePath = Join-Path $stateDir "guest-state.json"
$prepareResultPath = Join-Path $stateDir "guest-prepare-result.json"

if (Test-Path $statePath) {
    $existingState = Get-Content $statePath -Raw | ConvertFrom-Json

    if ($existingState.cleanup.status -ne "Completed") {
        throw "An active ID-C-005 guest run already exists. Cleanup the active run before creating a new one."
    }
}

if (-not (Test-ZTVPEmail -Email $ExternalEmail)) {
    throw "ExternalEmail does not look like a valid email address."
}

$existingGuests = @(Get-ZTVPExistingGuestByMail -Email $ExternalEmail)

if ($existingGuests.Count -gt 0) {
    $existingSummary = @($existingGuests | Select-Object id,userPrincipalName,displayName,mail,userType,externalUserState)

    $result = [PSCustomObject]@{
        ok = $false
        status = "EXTERNAL_GUEST_ALREADY_EXISTS"
        message = "A user/guest object with this mail address already exists. Use a fresh external test address or cleanup the existing guest manually."
        existing_objects = @($existingSummary)
    }

    $result | ConvertTo-Json -Depth 30 | Set-Content -Path $prepareResultPath -Encoding UTF8

    throw $result.message
}

$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$guestDisplayName = "$GuestDisplayNamePrefix $runId"

$inviteBody = @{
    invitedUserEmailAddress = $ExternalEmail
    invitedUserDisplayName = $guestDisplayName
    inviteRedirectUrl = $InviteRedirectUrl
    sendInvitationMessage = [bool]$SendInvitationMessage.IsPresent
} | ConvertTo-Json -Depth 20

$invite = Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/invitations" `
    -Body $inviteBody `
    -ContentType "application/json"

$inviteRedeemUrl = [string](Get-ZTVPValue -Object $invite -Name "inviteRedeemUrl")
$invitedUser = Get-ZTVPValue -Object $invite -Name "invitedUser"

$guestUserId = [string](Get-ZTVPValue -Object $invitedUser -Name "id")
$guestUpn = [string](Get-ZTVPValue -Object $invitedUser -Name "userPrincipalName")

Start-Sleep -Seconds 5

$freshUser = Get-ZTVPUserFresh -UserId $guestUserId

if ($null -ne $freshUser) {
    $guestUpn = [string](Get-ZTVPValue -Object $freshUser -Name "userPrincipalName")
    $guestDisplayName = [string](Get-ZTVPValue -Object $freshUser -Name "displayName")
}

$state = [PSCustomObject]@{
    scenario_id = "ID-C-005"
    scenario_name = "External Guest Admin Portal Block Validation"
    run_id = $runId
    prepared_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    connected_account = $ctx.Account

    external_identity = [PSCustomObject]@{
        external_email = $ExternalEmail
        consultant_controls_this_account = $true
    }

    guest_user = [PSCustomObject]@{
        id = $guestUserId
        user_principal_name = $guestUpn
        display_name = $guestDisplayName
        mail = if ($freshUser) { Get-ZTVPValue -Object $freshUser -Name "mail" } else { $null }
        user_type = if ($freshUser) { Get-ZTVPValue -Object $freshUser -Name "userType" } else { "Guest" }
        external_user_state = if ($freshUser) { Get-ZTVPValue -Object $freshUser -Name "externalUserState" } else { $null }
        created_by_ztvp = $true
        must_be_deleted_after_test = $true
    }

    invitation = [PSCustomObject]@{
        invite_redeem_url = $inviteRedeemUrl
        invite_redirect_url = $InviteRedirectUrl
        send_invitation_message = [bool]$SendInvitationMessage.IsPresent
    }

    admin_portal_attempt = [PSCustomObject]@{
        target_url = "https://portal.azure.com"
        expected_secure_result = "Guest access to Azure/admin portal is blocked by Conditional Access or platform controls."
    }

    cleanup = [PSCustomObject]@{
        status = "Pending"
        cleaned_at = $null
        action = $null
    }
}

$state | ConvertTo-Json -Depth 80 | Set-Content -Path $statePath -Encoding UTF8

$result = [PSCustomObject]@{
    ok = $true
    status = "ID_C_005_GUEST_INVITED"
    run_id = $runId
    external_email = $ExternalEmail
    guest_user_id = $guestUserId
    guest_user_principal_name = $guestUpn
    guest_display_name = $guestDisplayName
    invite_redeem_url = $inviteRedeemUrl
    admin_portal_url = "https://portal.azure.com"
    state_path = $statePath
}

$result | ConvertTo-Json -Depth 80 | Set-Content -Path $prepareResultPath -Encoding UTF8

Write-Host ""
Write-Host "ID-C-005 external guest invited"
Write-Host "Run ID: $runId"
Write-Host "External email: $ExternalEmail"
Write-Host "Guest user: $guestUpn"
Write-Host "Guest user id: $guestUserId"
Write-Host "Invite redeem URL: $inviteRedeemUrl"
Write-Host "Admin portal URL: https://portal.azure.com"
Write-Host "State: $statePath"
Write-Host ""
