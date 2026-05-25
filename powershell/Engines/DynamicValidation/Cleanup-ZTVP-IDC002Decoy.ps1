param(
    [switch]$DisableInsteadOfDelete
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "User.ReadWrite.All",
    "Directory.ReadWrite.All"
)

function Test-ZTVPNotFound {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) { return $false }

    return (
        $Message -match "404" -or
        $Message -match "not found" -or
        $Message -match "does not exist" -or
        $Message -match "Request_ResourceNotFound" -or
        $Message -match "ResourceNotFound"
    )
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

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-002"
$historyDir = Join-Path $stateDir "history"
$statePath = Join-Path $stateDir "decoy-state.json"
$secretPath = Join-Path $stateDir "decoy-secret-once.json"
$publicPath = Join-Path $stateDir "device-code-challenge-public.json"
$privatePath = Join-Path $stateDir "device-code-challenge-private.json"
$cleanupPath = Join-Path $stateDir "decoy-cleanup-result.json"

New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
New-Item -ItemType Directory -Path $historyDir -Force | Out-Null

if (-not (Test-Path $statePath)) {
    $result = [PSCustomObject]@{
        scenario_id = "ID-C-002"
        cleaned_at = (Get-Date).ToString("s")
        cleanup_status = "AlreadyClean"
        message = "No active decoy state file was found."
    }

    $result | ConvertTo-Json -Depth 20 | Set-Content -Path $cleanupPath -Encoding UTF8

    Write-Host ""
    Write-Host "No active ID-C-002 decoy state was found."
    Write-Host "Local state is already clean."
    Write-Host ""

    exit 0
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

$userId = [string]$state.decoy_user.id
$userUpn = [string]$state.decoy_user.user_principal_name

$userCleanup = [PSCustomObject]@{
    attempted = $true
    action = $null
    success = $false
    error = $null
}

try {
    if (-not [string]::IsNullOrWhiteSpace($userId)) {
        try {
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$userId/invalidateAllRefreshTokens" | Out-Null
        }
        catch {}
    }

    if ([string]::IsNullOrWhiteSpace($userId)) {
        throw "Decoy user ID was missing from state."
    }

    if ($DisableInsteadOfDelete) {
        $body = @{
            accountEnabled = $false
        } | ConvertTo-Json -Depth 5

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
catch {
    $message = $_.Exception.Message

    if (Test-ZTVPNotFound -Message $message) {
        $userCleanup.action = "AlreadyDeleted"
        $userCleanup.success = $true
        $userCleanup.error = $null
    }
    else {
        $userCleanup.action = if ($DisableInsteadOfDelete) { "DisableFailed" } else { "DeleteFailed" }
        $userCleanup.success = $false
        $userCleanup.error = $message
    }
}

$cleanupStatus = if ($userCleanup.success) { "Completed" } else { "Failed" }

$cleanupResult = [PSCustomObject]@{
    scenario_id = "ID-C-002"
    run_id = $state.run_id
    cleaned_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    connected_account = $ctx.Account
    cleanup_status = $cleanupStatus
    decoy_user = [PSCustomObject]@{
        id = $userId
        user_principal_name = $userUpn
    }
    user_cleanup = $userCleanup
}

$cleanupResult | ConvertTo-Json -Depth 30 | Set-Content -Path $cleanupPath -Encoding UTF8

try {
    $state.cleanup.status = $cleanupStatus
    $state.cleanup.cleaned_at = (Get-Date).ToString("s")
    $state.cleanup.action = $userCleanup.action
}
catch {}

$runId = if ($state.run_id) { $state.run_id } else { Get-Date -Format "yyyyMMdd-HHmmss" }
$archivePath = Join-Path $historyDir "decoy-state-$runId.json"

try {
    $state | ConvertTo-Json -Depth 40 | Set-Content -Path $archivePath -Encoding UTF8
}
catch {}

if ($userCleanup.success) {
    Remove-Item $statePath -Force -ErrorAction SilentlyContinue
    Remove-Item $secretPath -Force -ErrorAction SilentlyContinue
    Remove-Item $publicPath -Force -ErrorAction SilentlyContinue
    Remove-Item $privatePath -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "ID-C-002 cleanup completed"
Write-Host "User: $userUpn"
Write-Host "Action: $($userCleanup.action)"
Write-Host "Success: $($userCleanup.success)"
Write-Host "Cleanup status: $cleanupStatus"
Write-Host "Cleanup report: $cleanupPath"
Write-Host ""
