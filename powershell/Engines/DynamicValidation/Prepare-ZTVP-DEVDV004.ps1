param(
    [string]$UserPrefix = "ztvp-devdv004-decoy",
    [string]$DisplayName = "ZTVP DEV-DV-004 Sandbox Device Registration Decoy User",
    [string]$TenantDomain = ""
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "User.ReadWrite.All",
    "Directory.Read.All"
)

function Ensure-ZTVPGraphConnection {
    param([string[]]$Scopes)

    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    $needReconnect = $false

    if (-not $ctx) { $needReconnect = $true }
    else {
        $currentScopes = @()
        if ($ctx.Scopes) { $currentScopes = @($ctx.Scopes | ForEach-Object { $_.ToLower() }) }

        foreach ($scope in $Scopes) {
            if ($currentScopes -notcontains $scope.ToLower()) { $needReconnect = $true }
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

function New-ZTVPPassword {
    $suffix = [Guid]::NewGuid().ToString("N").Substring(0, 14)
    return "ZTVP!" + $suffix + "aA9"
}

function New-ZTVPRandomSuffix {
    $chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    $bytes = New-Object byte[] 5
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)

    $out = ""
    foreach ($b in $bytes) { $out += $chars[$b % $chars.Length] }

    return $out
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "DEV-DV-004"
$historyDir = Join-Path $scenarioDir "history"

New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null
New-Item -ItemType Directory -Path $historyDir -Force | Out-Null

$statePath = Join-Path $scenarioDir "devdv004-state.json"
$preparePath = Join-Path $scenarioDir "devdv004-prepare-result.json"

if (Test-Path $statePath) {
    throw "An active DEV-DV-004 state file exists. Run cleanup before preparing a new decoy."
}

$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$suffix = New-ZTVPRandomSuffix

if ([string]::IsNullOrWhiteSpace($TenantDomain)) {
    $org = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization"
    $domains = @($org.value[0].verifiedDomains)
    $defaultDomain = $domains | Where-Object { $_.isDefault -eq $true } | Select-Object -First 1

    if (-not $defaultDomain) {
        throw "Could not auto-detect tenant default domain. Provide TenantDomain manually."
    }

    $TenantDomain = [string]$defaultDomain.name
}

$mailNickname = "$UserPrefix-$runId-$suffix" -replace "[^a-zA-Z0-9-]", ""
$upn = "$mailNickname@$TenantDomain"
$password = New-ZTVPPassword

$userBody = @{
    accountEnabled = $true
    displayName = $DisplayName
    mailNickname = $mailNickname
    userPrincipalName = $upn
    passwordProfile = @{
        forceChangePasswordNextSignIn = $false
        password = $password
    }
} | ConvertTo-Json -Depth 20

$user = Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/users" `
    -Body $userBody `
    -ContentType "application/json"

$state = [PSCustomObject]@{
    scenario_id = "DEV-DV-004"
    display_id = "DEV-DV-004"
    scenario_name = "Sandbox Device Registration Abuse Probe"
    mode = "Windows Sandbox Device Registration Validation"
    run_id = $runId
    prepared_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    operator_account = $ctx.Account
    tenant_domain = $TenantDomain
    validation_window_start_utc = $null
    sandbox = [PSCustomObject]@{
        launched = $false
        launched_at = $null
        wsb_path = $null
    }
    decoy_user = [PSCustomObject]@{
        id = $user.id
        user_principal_name = $upn
        display_name = $DisplayName
        temporary_password = $password
        created_by_ztvp = $true
    }
    detected_device = $null
}

Write-ZTVPJson -Path $statePath -Object $state

$result = [PSCustomObject]@{
    scenario_id = "DEV-DV-004"
    status = "DECOY_READY"
    tenant_id = $ctx.TenantId
    operator_account = $ctx.Account
    decoy_user_principal_name = $upn
    decoy_temporary_password = $password
    message = "Decoy user created. Next step: start validation window and launch Windows Sandbox."
    state_path = $statePath
    prepared_at = (Get-Date).ToString("s")
}

Write-ZTVPJson -Path $preparePath -Object $result

Write-Host ""
Write-Host "DEV-DV-004 decoy user prepared."
Write-Host "Tenant ID: $($ctx.TenantId)"
Write-Host "Decoy UPN: $upn"
Write-Host "Temporary password: $password"
Write-Host ""
