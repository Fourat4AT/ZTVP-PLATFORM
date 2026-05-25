param(
    [switch]$DisableInsteadOfDelete
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "User.ReadWrite.All",
    "Directory.ReadWrite.All"
)

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

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-003"
$historyDir = Join-Path $stateDir "history"
$statePath = Join-Path $stateDir "decoy-state.json"
$secretOncePath = Join-Path $stateDir "decoy-secret-once.json"
$secretPrivatePath = Join-Path $stateDir "decoy-secret-private.json"
$cleanupPath = Join-Path $stateDir "decoy-cleanup-result.json"

New-Item -ItemType Directory -Path $historyDir -Force | Out-Null

if (-not (Test-Path $statePath)) {
    $result = [PSCustomObject]@{
        scenario_id = "ID-C-003"
        cleaned_at = (Get-Date).ToString("s")
        cleanup_status = "AlreadyClean"
        message = "No active decoy state file was found."
    }

    $result | ConvertTo-Json -Depth 20 | Set-Content -Path $cleanupPath -Encoding UTF8

    Write-Host "No active ID-C-003 decoy state was found."
    exit 0
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

$userId = [string]$state.decoy_user.id
$userUpn = [string]$state.decoy_user.user_principal_name
$skuId = [string]$state.license.sku_id

$licenseCleanup = [PSCustomObject]@{
    attempted = $false
    success = $false
    error = $null
}

$userCleanup = [PSCustomObject]@{
    attempted = $false
    action = $null
    success = $false
    error = $null
}

try {
    if (-not [string]::IsNullOrWhiteSpace($userId) -and -not [string]::IsNullOrWhiteSpace($skuId)) {
        $licenseCleanup.attempted = $true

        $body = @{
            addLicenses = @()
            removeLicenses = @($skuId)
        } | ConvertTo-Json -Depth 20

        Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/users/$userId/assignLicense" `
            -Body $body `
            -ContentType "application/json" | Out-Null

        $licenseCleanup.success = $true
    }
}
catch {
    $licenseCleanup.error = $_.Exception.Message
}

try {
    if (-not [string]::IsNullOrWhiteSpace($userId)) {
        try {
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$userId/invalidateAllRefreshTokens" | Out-Null
        }
        catch {}

        $userCleanup.attempted = $true

        if ($DisableInsteadOfDelete) {
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
        $userCleanup.action = if ($DisableInsteadOfDelete) { "DisableFailed" } else { "DeleteFailed" }
        $userCleanup.success = $false
        $userCleanup.error = $message
    }
}

$cleanupStatus = if ($userCleanup.success) { "Completed" } else { "Failed" }

$cleanupResult = [PSCustomObject]@{
    scenario_id = "ID-C-003"
    run_id = $state.run_id
    cleaned_at = (Get-Date).ToString("s")
    cleanup_status = $cleanupStatus
    decoy_user = [PSCustomObject]@{
        id = $userId
        user_principal_name = $userUpn
    }
    license_cleanup = $licenseCleanup
    user_cleanup = $userCleanup
    local_secret_files_deleted = $false
}

try {
    $state.cleanup.status = $cleanupStatus
    $state.cleanup.cleaned_at = (Get-Date).ToString("s")
    $state.cleanup.action = $userCleanup.action
}
catch {}

$runId = if ($state.run_id) { $state.run_id } else { Get-Date -Format "yyyyMMdd-HHmmss" }
$archivePath = Join-Path $historyDir "decoy-state-$runId.json"

try {
    $state | ConvertTo-Json -Depth 50 | Set-Content -Path $archivePath -Encoding UTF8
}
catch {}

if ($userCleanup.success) {
    Remove-Item $statePath -Force -ErrorAction SilentlyContinue
    Remove-Item $secretOncePath -Force -ErrorAction SilentlyContinue
    Remove-Item $secretPrivatePath -Force -ErrorAction SilentlyContinue
    $cleanupResult.local_secret_files_deleted = $true
}

$cleanupResult | ConvertTo-Json -Depth 50 | Set-Content -Path $cleanupPath -Encoding UTF8

Write-Host ""
Write-Host "ID-C-003 cleanup completed"
Write-Host "User: $userUpn"
Write-Host "License removed: $($licenseCleanup.success)"
Write-Host "User cleanup action: $($userCleanup.action)"
Write-Host "User cleanup success: $($userCleanup.success)"
Write-Host "Local secret files deleted: $($cleanupResult.local_secret_files_deleted)"
Write-Host "Cleanup status: $cleanupStatus"
Write-Host ""
