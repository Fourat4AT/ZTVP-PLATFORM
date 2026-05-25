param(
    [switch]$DisableUserInsteadOfDelete
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Application.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All"
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

function Test-ZTVPNotFound {
    param([string]$Message)

    return (
        $Message -match "404" -or
        $Message -match "not found" -or
        $Message -match "does not exist" -or
        $Message -match "Request_ResourceNotFound" -or
        $Message -match "ResourceNotFound"
    )
}

function Get-ZTVPOAuthPermissionGrants {
    param([string]$ServicePrincipalId)

    if ([string]::IsNullOrWhiteSpace($ServicePrincipalId)) {
        return @()
    }

    $filter = "clientId eq '$ServicePrincipalId'"
    $encoded = [System.Uri]::EscapeDataString($filter)
    $uri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=$encoded"

    try {
        return @(Invoke-ZTVPPagedGraphQuery -Uri $uri -MaxPages 10)
    }
    catch {
        return @()
    }
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-004"
$historyDir = Join-Path $stateDir "history"
$statePath = Join-Path $stateDir "consent-state.json"
$secretOncePath = Join-Path $stateDir "decoy-secret-once.json"
$cleanupPath = Join-Path $stateDir "cleanup-result.json"

New-Item -ItemType Directory -Path $historyDir -Force | Out-Null

if (-not (Test-Path $statePath)) {
    $result = [PSCustomObject]@{
        scenario_id = "ID-C-004"
        cleaned_at = (Get-Date).ToString("s")
        cleanup_status = "AlreadyClean"
        message = "No active ID-C-004 state file was found."
    }

    $result | ConvertTo-Json -Depth 20 | Set-Content -Path $cleanupPath -Encoding UTF8

    Write-Host "No active ID-C-004 state was found."
    exit 0
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

$userId = [string]$state.decoy_user.id
$userUpn = [string]$state.decoy_user.user_principal_name
$appObjectId = [string]$state.test_application.app_object_id
$appId = [string]$state.test_application.app_id
$servicePrincipalId = [string]$state.test_application.service_principal_id

$grantCleanupRows = @()
$appCleanup = [PSCustomObject]@{ attempted = $false; success = $false; error = $null }
$spCleanup = [PSCustomObject]@{ attempted = $false; success = $false; error = $null }
$userCleanup = [PSCustomObject]@{ attempted = $false; action = $null; success = $false; error = $null }

$grants = @(Get-ZTVPOAuthPermissionGrants -ServicePrincipalId $servicePrincipalId)

foreach ($grant in $grants) {
    $grantId = [string](Get-ZTVPValue -Object $grant -Name "id")
    $row = [PSCustomObject]@{
        id = $grantId
        attempted = $false
        success = $false
        error = $null
    }

    if (-not [string]::IsNullOrWhiteSpace($grantId)) {
        try {
            $row.attempted = $true
            Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$grantId" | Out-Null
            $row.success = $true
        }
        catch {
            $row.error = $_.Exception.Message
        }
    }

    $grantCleanupRows += $row
}

try {
    if (-not [string]::IsNullOrWhiteSpace($servicePrincipalId)) {
        $spCleanup.attempted = $true
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$servicePrincipalId" | Out-Null
        $spCleanup.success = $true
    }
}
catch {
    $message = $_.Exception.Message

    if (Test-ZTVPNotFound -Message $message) {
        $spCleanup.success = $true
    }
    else {
        $spCleanup.error = $message
    }
}

try {
    if (-not [string]::IsNullOrWhiteSpace($appObjectId)) {
        $appCleanup.attempted = $true
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/applications/$appObjectId" | Out-Null
        $appCleanup.success = $true
    }
}
catch {
    $message = $_.Exception.Message

    if (Test-ZTVPNotFound -Message $message) {
        $appCleanup.success = $true
    }
    else {
        $appCleanup.error = $message
    }
}

try {
    if (-not [string]::IsNullOrWhiteSpace($userId)) {
        try {
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$userId/invalidateAllRefreshTokens" | Out-Null
        }
        catch {}

        $userCleanup.attempted = $true

        if ($DisableUserInsteadOfDelete) {
            $body = @{ accountEnabled = $false } | ConvertTo-Json -Depth 5
            Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/users/$userId" -Body $body -ContentType "application/json" | Out-Null
            $userCleanup.action = "Disabled"
            $userCleanup.success = $true
        }
        else {
            Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/users/$userId" | Out-Null
            $userCleanup.action = "Deleted"
            $userCleanup.success = $true
        }
    }
}
catch {
    $message = $_.Exception.Message

    if (Test-ZTVPNotFound -Message $message) {
        $userCleanup.action = "AlreadyDeleted"
        $userCleanup.success = $true
    }
    else {
        $userCleanup.action = if ($DisableUserInsteadOfDelete) { "DisableFailed" } else { "DeleteFailed" }
        $userCleanup.success = $false
        $userCleanup.error = $message
    }
}

$grantCleanupOk = $true

foreach ($row in $grantCleanupRows) {
    if ($row.success -ne $true) {
        $grantCleanupOk = $false
    }
}

$cleanupOk = ($grantCleanupOk -eq $true -and $appCleanup.success -eq $true -and $userCleanup.success -eq $true)
$cleanupStatus = if ($cleanupOk) { "Completed" } else { "PartialOrFailed" }

try {
    $state.cleanup.status = $cleanupStatus
    $state.cleanup.cleaned_at = (Get-Date).ToString("s")
    $state.cleanup.action = "OAuth grant cleanup, app cleanup, user cleanup"
}
catch {}

$runId = if ($state.run_id) { $state.run_id } else { Get-Date -Format "yyyyMMdd-HHmmss" }
$archivePath = Join-Path $historyDir "consent-state-$runId.json"

try {
    $state | ConvertTo-Json -Depth 80 | Set-Content -Path $archivePath -Encoding UTF8
}
catch {}

if ($cleanupOk) {
    Remove-Item $statePath -Force -ErrorAction SilentlyContinue
    Remove-Item $secretOncePath -Force -ErrorAction SilentlyContinue
}

$result = [PSCustomObject]@{
    scenario_id = "ID-C-004"
    run_id = $runId
    cleaned_at = (Get-Date).ToString("s")
    cleanup_status = $cleanupStatus
    decoy_user = [PSCustomObject]@{
        id = $userId
        user_principal_name = $userUpn
    }
    test_application = [PSCustomObject]@{
        app_object_id = $appObjectId
        app_id = $appId
        service_principal_id = $servicePrincipalId
    }
    grant_cleanup = @($grantCleanupRows)
    service_principal_cleanup = $spCleanup
    application_cleanup = $appCleanup
    user_cleanup = $userCleanup
    local_secret_file_deleted = (-not (Test-Path $secretOncePath))
}

$result | ConvertTo-Json -Depth 80 | Set-Content -Path $cleanupPath -Encoding UTF8

Write-Host ""
Write-Host "ID-C-004 cleanup completed"
Write-Host "User: $userUpn"
Write-Host "OAuth grants cleaned: $grantCleanupOk"
Write-Host "Service principal cleanup: $($spCleanup.success)"
Write-Host "Application cleanup: $($appCleanup.success)"
Write-Host "User cleanup action: $($userCleanup.action)"
Write-Host "User cleanup success: $($userCleanup.success)"
Write-Host "Cleanup status: $cleanupStatus"
Write-Host ""
