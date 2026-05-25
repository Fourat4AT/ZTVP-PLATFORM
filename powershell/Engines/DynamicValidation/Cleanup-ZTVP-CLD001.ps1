param()

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "Sites.ReadWrite.All",
    "Files.ReadWrite.All"
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
        Connect-MgGraph -Scopes $Scopes -ContextScope CurrentUser -NoWelcome | Out-Null
    }
}

function Test-ZTVPNotFound {
    param([string]$Message)

    return (
        $Message -match "404" -or
        $Message -match "not found" -or
        $Message -match "does not exist" -or
        $Message -match "itemNotFound" -or
        $Message -match "ResourceNotFound"
    )
}

Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$scenarioDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\CLD-C-001"
$historyDir = Join-Path $scenarioDir "history"
$statePath = Join-Path $scenarioDir "cld001-state.json"
$cleanupPath = Join-Path $scenarioDir "cld001-cleanup-result.json"

New-Item -ItemType Directory -Path $historyDir -Force | Out-Null

if (-not (Test-Path $statePath)) {
    $result = [PSCustomObject]@{
        scenario_id = "CLD-C-001"
        cleanup_status = "AlreadyClean"
        message = "No active CLD-C-001 state file was found."
        cleaned_at = (Get-Date).ToString("s")
    }

    $result | ConvertTo-Json -Depth 30 | Set-Content -Path $cleanupPath -Encoding UTF8
    Write-Host "No active CLD-C-001 state file was found."
    exit 0
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

$driveId = [string]$state.drive.id
$folderId = [string]$state.test_object.folder_id
$fileId = [string]$state.test_object.file_id
$permissionId = $null

if ($state.anonymous_permission) {
    $permissionId = [string]$state.anonymous_permission.permission_id
}

$actions = @()
$errors = @()

if (-not [string]::IsNullOrWhiteSpace($permissionId) -and -not [string]::IsNullOrWhiteSpace($fileId)) {
    try {
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/items/$fileId/permissions/$permissionId" | Out-Null
        $actions += "Deleted anonymous permission."
    }
    catch {
        $msg = $_.Exception.Message

        if (Test-ZTVPNotFound -Message $msg) {
            $actions += "Anonymous permission was already removed."
        }
        else {
            $errors += "Permission cleanup failed: $msg"
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($folderId)) {
    try {
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/items/$folderId" | Out-Null
        $actions += "Deleted temporary test folder and file."
    }
    catch {
        $msg = $_.Exception.Message

        if (Test-ZTVPNotFound -Message $msg) {
            $actions += "Temporary test folder was already removed."
        }
        else {
            $errors += "Folder cleanup failed: $msg"
        }
    }
}

$status = if ($errors.Count -eq 0) { "Completed" } else { "Failed" }

$runId = if ($state.run_id) { $state.run_id } else { Get-Date -Format "yyyyMMdd-HHmmss" }
$archivePath = Join-Path $historyDir "cld001-state-$runId.json"

try {
    $state | ConvertTo-Json -Depth 80 | Set-Content -Path $archivePath -Encoding UTF8
}
catch {}

if ($status -eq "Completed") {
    Remove-Item $statePath -Force -ErrorAction SilentlyContinue
}

$result = [PSCustomObject]@{
    scenario_id = "CLD-C-001"
    run_id = $runId
    cleaned_at = (Get-Date).ToString("s")
    cleanup_status = $status
    actions = @($actions)
    errors = @($errors)
    state_file_deleted = (-not (Test-Path $statePath))
}

$result | ConvertTo-Json -Depth 80 | Set-Content -Path $cleanupPath -Encoding UTF8

Write-Host ""
Write-Host "CLD-C-001 cleanup completed"
Write-Host "Status: $status"
Write-Host "Actions: $($actions -join '; ')"
Write-Host "Errors: $($errors -join '; ')"
Write-Host ""
