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

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-005"
$historyDir = Join-Path $stateDir "history"
$statePath = Join-Path $stateDir "guest-state.json"
$cleanupPath = Join-Path $stateDir "guest-cleanup-result.json"

New-Item -ItemType Directory -Path $historyDir -Force | Out-Null

if (-not (Test-Path $statePath)) {
    $result = [PSCustomObject]@{
        scenario_id = "ID-C-005"
        cleaned_at = (Get-Date).ToString("s")
        cleanup_status = "AlreadyClean"
        message = "No active ID-C-005 guest state file was found."
    }

    $result | ConvertTo-Json -Depth 20 | Set-Content -Path $cleanupPath -Encoding UTF8

    Write-Host "No active ID-C-005 guest state was found."
    exit 0
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

$userId = [string]$state.guest_user.id
$userUpn = [string]$state.guest_user.user_principal_name
$externalEmail = [string]$state.external_identity.external_email

$userCleanup = [PSCustomObject]@{
    attempted = $false
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

try {
    $state.cleanup.status = $cleanupStatus
    $state.cleanup.cleaned_at = (Get-Date).ToString("s")
    $state.cleanup.action = $userCleanup.action
}
catch {}

$runId = if ($state.run_id) { $state.run_id } else { Get-Date -Format "yyyyMMdd-HHmmss" }
$archivePath = Join-Path $historyDir "guest-state-$runId.json"

try {
    $state | ConvertTo-Json -Depth 80 | Set-Content -Path $archivePath -Encoding UTF8
}
catch {}

if ($userCleanup.success) {
    Remove-Item $statePath -Force -ErrorAction SilentlyContinue

    $attemptWindowPath = Join-Path $stateDir "guest-attempt-window.json"
    Remove-Item $attemptWindowPath -Force -ErrorAction SilentlyContinue
}

$result = [PSCustomObject]@{
    scenario_id = "ID-C-005"
    run_id = $runId
    cleaned_at = (Get-Date).ToString("s")
    cleanup_status = $cleanupStatus
    guest_user = [PSCustomObject]@{
        id = $userId
        user_principal_name = $userUpn
        external_email = $externalEmail
    }
    user_cleanup = $userCleanup
    state_file_deleted = (-not (Test-Path $statePath))
}

$result | ConvertTo-Json -Depth 80 | Set-Content -Path $cleanupPath -Encoding UTF8

Write-Host ""
Write-Host "ID-C-005 cleanup completed"
Write-Host "External email: $externalEmail"
Write-Host "Guest user: $userUpn"
Write-Host "User cleanup action: $($userCleanup.action)"
Write-Host "User cleanup success: $($userCleanup.success)"
Write-Host "Cleanup status: $cleanupStatus"
Write-Host ""
