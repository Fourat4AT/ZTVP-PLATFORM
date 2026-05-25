param()

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "Sites.ReadWrite.All",
    "Files.ReadWrite.All",
    "Directory.Read.All"
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

function Write-ZTVPJson {
    param([string]$Path, [object]$Object)

    $Object |
        ConvertTo-Json -Depth 100 |
        Set-Content -Path $Path -Encoding UTF8
}

Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "APP-C-003"
$historyDir = Join-Path $scenarioDir "history"
$statePath = Join-Path $scenarioDir "appc003-state.json"
$cleanupPath = Join-Path $scenarioDir "appc003-cleanup-result.json"

New-Item -ItemType Directory -Path $historyDir -Force | Out-Null

if (-not (Test-Path $statePath)) {
    $result = [PSCustomObject]@{
        scenario_id = "APP-C-003"
        cleanup_status = "AlreadyClean"
        message = "No active APP-C-003 state file was found."
        cleaned_at = (Get-Date).ToString("s")
    }

    Write-ZTVPJson -Path $cleanupPath -Object $result
    Write-Host "No active APP-C-003 state file was found."
    exit 0
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

$driveId = [string]$state.drive.id
$folderId = [string]$state.test_object.folder_id
$fileId = [string]$state.test_object.file_id
$permissionId = [string]$state.anonymous_public_link_attempt.permission_id
$runId = [string]$state.run_id

$actions = @()
$errors = @()

if (-not [string]::IsNullOrWhiteSpace($permissionId) -and -not [string]::IsNullOrWhiteSpace($fileId)) {
    try {
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/items/$fileId/permissions/$permissionId" | Out-Null
        $actions += "Deleted anonymous public sharing permission."
    }
    catch {
        $msg = $_.Exception.Message

        if (Test-ZTVPNotFound -Message $msg) {
            $actions += "Anonymous public sharing permission was already removed."
        }
        else {
            $errors += "Could not delete anonymous permission: $msg"
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($folderId)) {
    try {
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/items/$folderId" | Out-Null
        $actions += "Deleted temporary dummy folder and file."
    }
    catch {
        $msg = $_.Exception.Message

        if (Test-ZTVPNotFound -Message $msg) {
            $actions += "Temporary dummy folder/file was already removed."
        }
        else {
            $errors += "Could not delete temporary dummy folder/file: $msg"
        }
    }
}

$status = if ($errors.Count -eq 0) { "Completed" } else { "Failed" }

$archivePath = Join-Path $historyDir "appc003-state-$runId.json"

try {
    $state | ConvertTo-Json -Depth 100 | Set-Content -Path $archivePath -Encoding UTF8
}
catch {}

if ($status -eq "Completed") {
    Remove-Item $statePath -Force -ErrorAction SilentlyContinue
}

$result = [PSCustomObject]@{
    scenario_id = "APP-C-003"
    run_id = $runId
    cleaned_at = (Get-Date).ToString("s")
    cleanup_status = $status
    actions = @($actions)
    errors = @($errors)
    state_file_deleted = (-not (Test-Path $statePath))
}

Write-ZTVPJson -Path $cleanupPath -Object $result

Write-Host ""
Write-Host "APP-C-003 emergency cleanup completed"
Write-Host "Status: $status"
Write-Host "Actions: $($actions -join '; ')"
Write-Host "Errors: $($errors -join '; ')"
Write-Host ""
