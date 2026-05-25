param(
    [string]$DecoyAliasPrefix = "ztvp-idc004-oauthconsent",
    [string]$DecoyDisplayName = "ZTVP ID-C-004 OAuth Consent Decoy User",
    [string]$AppDisplayNamePrefix = "ZTVP ID-C-004 OAuth Consent Test App",
    [string]$UsageLocation = "TN",
    [string]$RequestedScope = "https://graph.microsoft.com/User.Read"
)

$ErrorActionPreference = "Stop"


trap {
    try {
        $errorDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-004"
        New-Item -ItemType Directory -Path $errorDir -Force | Out-Null

        $errorPath = Join-Path $errorDir "prepare-error.json"

        $errorReport = [PSCustomObject]@{
            ok = $false
            scenario_id = "ID-C-004"
            failed_at = (Get-Date).ToString("s")
            error_message = $_.Exception.Message
            position_message = $_.InvocationInfo.PositionMessage
            script_stack_trace = $_.ScriptStackTrace
        }

        $errorReport |
            ConvertTo-Json -Depth 30 |
            Set-Content -Path $errorPath -Encoding UTF8

        Write-Host ""
        Write-Host "ID-C-004 PREPARATION ERROR"
        Write-Host "Error report: $errorPath"
        Write-Host "Message: $($_.Exception.Message)"
        Write-Host ""
    }
    catch {}

    throw
}



Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Application.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All",
    "AuditLog.Read.All"
)

$GraphAppId = "00000003-0000-0000-c000-000000000000"
$UserReadScopeId = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
$RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"

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

function New-ZTVPStrongPassword {
    $chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789!@#$%*-_+=".ToCharArray()
    $bytes = New-Object byte[] 30
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()

    $password = -join ($bytes | ForEach-Object {
        $chars[$_ % $chars.Length]
    })

    return "$password" + "Aa1!"
}

function Get-ZTVPDefaultDomain {
    $orgResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization?`$select=id,displayName,verifiedDomains"
    $orgItems = @(Get-ZTVPValue -Object $orgResponse -Name "value")

    if ($orgItems.Count -eq 0) {
        throw "Could not read organization details from Microsoft Graph."
    }

    $tenant = $orgItems[0]
    $domains = @(Get-ZTVPValue -Object $tenant -Name "verifiedDomains")

    $onMicrosoftDomain = $null
    $defaultDomain = $null
    $firstDomain = $null

    foreach ($domain in $domains) {
        $name = [string](Get-ZTVPValue -Object $domain -Name "name")

        if ([string]::IsNullOrWhiteSpace($firstDomain)) {
            $firstDomain = $name
        }

        if ($name -like "*.onmicrosoft.com" -and [string]::IsNullOrWhiteSpace($onMicrosoftDomain)) {
            $onMicrosoftDomain = $name
        }

        if ((Get-ZTVPValue -Object $domain -Name "isDefault") -eq $true) {
            $defaultDomain = $name
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($onMicrosoftDomain)) { return $onMicrosoftDomain }
    if (-not [string]::IsNullOrWhiteSpace($defaultDomain)) { return $defaultDomain }
    if (-not [string]::IsNullOrWhiteSpace($firstDomain)) { return $firstDomain }

    throw "No verified tenant domain was found."
}

function New-ZTVPFreshUpn {
    param([string]$Prefix, [string]$Domain)

    $safePrefix = $Prefix.ToLower() -replace "[^a-z0-9._-]", "-"
    $safePrefix = $safePrefix -replace "-+", "-"

    if ([string]::IsNullOrWhiteSpace($safePrefix)) {
        $safePrefix = "ztvp-idc004-oauthconsent"
    }

    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    $chars = (48..57) + (97..122)
    $suffix = -join ($chars | Get-Random -Count 5 | ForEach-Object { [char]$_ })

    return "$safePrefix-$timestamp-$suffix@$Domain"
}

function New-ZTVPDecoyUser {
    param(
        [string]$UserPrincipalName,
        [string]$DisplayName,
        [string]$Password,
        [string]$UsageLocation
    )

    $mailNickname = $UserPrincipalName.Split("@")[0]
    $mailNickname = $mailNickname -replace "[^a-zA-Z0-9._-]", ""

    $body = @{
        accountEnabled = $true
        displayName = $DisplayName
        mailNickname = $mailNickname
        userPrincipalName = $UserPrincipalName
        usageLocation = $UsageLocation
        passwordProfile = @{
            forceChangePasswordNextSignIn = $false
            password = $Password
        }
    } | ConvertTo-Json -Depth 20

    return Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users" -Body $body -ContentType "application/json"
}

function New-ZTVPOAuthTestApplication {
    param(
        [string]$DisplayName,
        [string]$RedirectUri
    )

    $body = @{
        displayName = $DisplayName
        signInAudience = "AzureADMyOrg"
        publicClient = @{
            redirectUris = @($RedirectUri)
        }
        requiredResourceAccess = @(
            @{
                resourceAppId = $GraphAppId
                resourceAccess = @(
                    @{
                        id = $UserReadScopeId
                        type = "Scope"
                    }
                )
            }
        )
    } | ConvertTo-Json -Depth 50

    return Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications" -Body $body -ContentType "application/json"
}

function Get-ZTVPServicePrincipalByAppId {
    param([string]$AppId)

    $filter = "appId eq '$AppId'"
    $encoded = [System.Uri]::EscapeDataString($filter)
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$encoded"

    $items = @(Invoke-ZTVPPagedGraphQuery -Uri $uri -MaxPages 3)

    if ($items.Count -gt 0) {
        return $items[0]
    }

    return $null
}

function New-ZTVPServicePrincipalForApp {
    param([string]$AppId)

    $existing = Get-ZTVPServicePrincipalByAppId -AppId $AppId

    if ($null -ne $existing) {
        return $existing
    }

    $body = @{
        appId = $AppId
    } | ConvertTo-Json -Depth 10

    for ($i = 0; $i -lt 10; $i++) {
        try {
            return Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" -Body $body -ContentType "application/json"
        }
        catch {
            Start-Sleep -Seconds 3

            $existing = Get-ZTVPServicePrincipalByAppId -AppId $AppId

            if ($null -ne $existing) {
                return $existing
            }
        }
    }

    throw "Could not create or find service principal for appId $AppId"
}

function New-ZTVPConsentUrl {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$RedirectUri,
        [string]$Scope,
        [string]$State
    )

    $encodedRedirect = [System.Uri]::EscapeDataString($RedirectUri)
    $encodedScope = [System.Uri]::EscapeDataString($Scope)
    $encodedState = [System.Uri]::EscapeDataString($State)

    return "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?client_id=$ClientId&response_type=code&redirect_uri=$encodedRedirect&response_mode=query&scope=$encodedScope&prompt=consent&state=$encodedState"
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-004"
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null

$statePath = Join-Path $stateDir "consent-state.json"
$secretOncePath = Join-Path $stateDir "decoy-secret-once.json"
$prepareResultPath = Join-Path $stateDir "prepare-result.json"

if (Test-Path $statePath) {
    $existingState = Get-Content $statePath -Raw | ConvertFrom-Json

    if ($existingState.cleanup.status -ne "Completed") {
        throw "An active ID-C-004 run already exists. Cleanup the active run before generating a new one."
    }
}

$domain = Get-ZTVPDefaultDomain
$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$upn = New-ZTVPFreshUpn -Prefix $DecoyAliasPrefix -Domain $domain
$password = New-ZTVPStrongPassword

$appDisplayName = "$AppDisplayNamePrefix $runId"

$user = New-ZTVPDecoyUser `
    -UserPrincipalName $upn `
    -DisplayName $DecoyDisplayName `
    -Password $password `
    -UsageLocation $UsageLocation

$userId = [string](Get-ZTVPValue -Object $user -Name "id")
$userUpn = [string](Get-ZTVPValue -Object $user -Name "userPrincipalName")

$app = New-ZTVPOAuthTestApplication -DisplayName $appDisplayName -RedirectUri $RedirectUri
$appObjectId = [string](Get-ZTVPValue -Object $app -Name "id")
$appId = [string](Get-ZTVPValue -Object $app -Name "appId")

$servicePrincipal = New-ZTVPServicePrincipalForApp -AppId $appId
$servicePrincipalId = [string](Get-ZTVPValue -Object $servicePrincipal -Name "id")

$consentUrl = New-ZTVPConsentUrl `
    -TenantId $ctx.TenantId `
    -ClientId $appId `
    -RedirectUri $RedirectUri `
    -Scope $RequestedScope `
    -State $runId

$state = [PSCustomObject]@{
    scenario_id = "ID-C-004"
    scenario_name = "OAuth App Consent Exposure Validation"
    run_id = $runId
    prepared_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    connected_account = $ctx.Account
    decoy_user = [PSCustomObject]@{
        id = $userId
        user_principal_name = $userUpn
        display_name = $DecoyDisplayName
        usage_location = $UsageLocation
        created_by_ztvp = $true
        must_be_deleted_after_test = $true
    }
    test_application = [PSCustomObject]@{
        app_object_id = $appObjectId
        app_id = $appId
        display_name = $appDisplayName
        service_principal_id = $servicePrincipalId
        redirect_uri = $RedirectUri
        requested_scope = $RequestedScope
        graph_permission = "User.Read"
        client_secret_created = $false
    }
    consent_attempt = [PSCustomObject]@{
        consent_url = $consentUrl
        expected_secure_result = "User consent is blocked or administrator approval is required."
    }
    cleanup = [PSCustomObject]@{
        status = "Pending"
        cleaned_at = $null
        action = $null
    }
}

$secretOnce = [PSCustomObject]@{
    user_principal_name = $userUpn
    temporary_password = $password
    warning = "This password is shown once. It is not needed by ZTVP after the manual consent attempt."
}

$state | ConvertTo-Json -Depth 80 | Set-Content -Path $statePath -Encoding UTF8
$secretOnce | ConvertTo-Json -Depth 20 | Set-Content -Path $secretOncePath -Encoding UTF8

$result = [PSCustomObject]@{
    ok = $true
    status = "ID_C_004_PREPARED"
    run_id = $runId
    decoy_user = $userUpn
    app_display_name = $appDisplayName
    app_id = $appId
    service_principal_id = $servicePrincipalId
    consent_url = $consentUrl
    requested_scope = $RequestedScope
    state_path = $statePath
    password_available_once = $true
}

$result | ConvertTo-Json -Depth 80 | Set-Content -Path $prepareResultPath -Encoding UTF8

Write-Host ""
Write-Host "ID-C-004 OAuth consent validation prepared"
Write-Host "Run ID: $runId"
Write-Host "Decoy user: $userUpn"
Write-Host "Test app: $appDisplayName"
Write-Host "App ID: $appId"
Write-Host "Requested scope: $RequestedScope"
Write-Host "Consent URL: $consentUrl"
Write-Host "State: $statePath"
Write-Host ""
