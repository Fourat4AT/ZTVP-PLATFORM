param()

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "User.ReadWrite.All",
    "Application.ReadWrite.All",
    "Directory.Read.All"
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
        $ctx = Get-MgContext
    }

    return $ctx
}

function Write-ZTVPJson {
    param([string]$Path, [object]$Object)

    $Object | ConvertTo-Json -Depth 100 | Set-Content -Path $Path -Encoding UTF8
}

function Test-ZTVPNotFound {
    param([string]$Message)

    return (
        $Message -match "404" -or
        $Message -match "not found" -or
        $Message -match "Request_ResourceNotFound" -or
        $Message -match "ResourceNotFound"
    )
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "APP-DV-007"
$historyDir = Join-Path $scenarioDir "history"
$statePath = Join-Path $scenarioDir "appdv007-state.json"
$cleanupPath = Join-Path $scenarioDir "appdv007-cleanup-result.json"
$preparePath = Join-Path $scenarioDir "appdv007-prepare-result.json"

New-Item -ItemType Directory -Path $historyDir -Force | Out-Null

if (-not (Test-Path $statePath)) {
    $result = [PSCustomObject]@{
        scenario_id = "APP-DV-007"
        cleanup_status = "AlreadyClean"
        message = "No active APP-DV-007 state file was found."
        cleaned_at = (Get-Date).ToString("s")
    }

    Write-ZTVPJson -Path $cleanupPath -Object $result
    Write-Host "No active APP-DV-007 state file was found."
    exit 0
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

$runId = [string]$state.run_id
$decoyUserId = [string]$state.decoy_user.id
$decoyUpn = [string]$state.decoy_user.user_principal_name
$appObjectId = [string]$state.app_probe.app_object_id

$actions = @()
$errors = @()

if (-not [string]::IsNullOrWhiteSpace($appObjectId)) {
    try {
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/applications/$appObjectId" | Out-Null
        $actions += "Deleted temporary APP-DV-007 app registration."
    }
    catch {
        $msg = $_.Exception.Message
        if (Test-ZTVPNotFound -Message $msg) {
            $actions += "Temporary APP-DV-007 app registration was already removed."
        }
        else {
            $errors += "Could not delete temporary APP-DV-007 app registration: $msg"
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($decoyUserId)) {
    try {
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/users/$decoyUserId" | Out-Null
        $actions += "Deleted APP-DV-007 decoy user."
    }
    catch {
        $msg = $_.Exception.Message
        if (Test-ZTVPNotFound -Message $msg) {
            $actions += "APP-DV-007 decoy user was already removed."
        }
        else {
            $errors += "Could not delete APP-DV-007 decoy user: $msg"
        }
    }
}

$status = if ($errors.Count -eq 0) { "Completed" } else { "Failed" }

$archivePath = Join-Path $historyDir "appdv007-state-$runId.json"

try {
    $state | ConvertTo-Json -Depth 100 | Set-Content -Path $archivePath -Encoding UTF8
}
catch {}

if ($status -eq "Completed") {
    Remove-Item $statePath -Force -ErrorAction SilentlyContinue
    Remove-Item $preparePath -Force -ErrorAction SilentlyContinue
}

$result = [PSCustomObject]@{
    scenario_id = "APP-DV-007"
    run_id = $runId
    decoy_user_principal_name = $decoyUpn
    cleanup_admin_account = $ctx.Account
    cleaned_at = (Get-Date).ToString("s")
    cleanup_status = $status
    actions = @($actions)
    errors = @($errors)
    state_file_deleted = (-not (Test-Path $statePath))
}

Write-ZTVPJson -Path $cleanupPath -Object $result

Write-Host ""
Write-Host "APP-DV-007 cleanup completed."
Write-Host "Status: $status"
Write-Host "Actions: $($actions -join '; ')"
Write-Host "Errors: $($errors -join '; ')"
Write-Host ""
