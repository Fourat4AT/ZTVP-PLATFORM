param(
    [string]$UserPrefix = "ztvp-idv006-decoy",
    [string]$DisplayName = "ZTVP ID-DV-006 Sign-in Risk Decoy User",
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
$scenarioDir = Join-Path $reportRoot "ID-DV-006"
$historyDir = Join-Path $scenarioDir "history"
New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null
New-Item -ItemType Directory -Path $historyDir -Force | Out-Null

$statePath = Join-Path $scenarioDir "idv006-state.json"
$preparePath = Join-Path $scenarioDir "idv006-prepare-result.json"

if (Test-Path $statePath) {
    throw "An active ID-DV-006 state file exists. Run cleanup before preparing a new decoy."
}

$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$suffix = New-ZTVPRandomSuffix

if ([string]::IsNullOrWhiteSpace($TenantDomain)) {
    $org = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization"
    $domains = @($org.value[0].verifiedDomains)
    $defaultDomain = $domains | Where-Object { $_.isDefault -eq $true } | Select-Object -First 1
    if (-not $defaultDomain) { throw "Could not auto-detect tenant default domain. Provide TenantDomain manually." }
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

$user = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users" -Body $userBody -ContentType "application/json"

$state = [PSCustomObject]@{
    scenario_id = "ID-DV-006"
    display_id = "ID-DV-006"
    scenario_name = "Sign-in Risk Conditional Access Validation"
    mode = "Decoy sign-in risk + Conditional Access evidence active run"
    run_id = $runId
    prepared_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    admin_account = $ctx.Account
    tenant_domain = $TenantDomain
    evidence_start_utc = $null
    decoy_user = [PSCustomObject]@{
        id = $user.id
        user_principal_name = $upn
        display_name = $DisplayName
        temporary_password = $password
        created_by_ztvp = $true
    }
}

Write-ZTVPJson -Path $statePath -Object $state

$result = [PSCustomObject]@{
    scenario_id = "ID-DV-006"
    status = "DECOY_READY"
    tenant_id = $ctx.TenantId
    admin_account = $ctx.Account
    decoy_user_principal_name = $upn
    decoy_temporary_password = $password
    tenant_domain = $TenantDomain
    message = "Decoy user created. Press 'Start evidence window' before performing the risky sign-in test, then sign in with this decoy."
    state_path = $statePath
    prepared_at = (Get-Date).ToString("s")
}

Write-ZTVPJson -Path $preparePath -Object $result

Write-Host ""
Write-Host "ID-DV-006 decoy user prepared."
Write-Host "Tenant ID: $($ctx.TenantId)"
Write-Host "Decoy UPN: $upn"
Write-Host "Temporary password: $password"
Write-Host "Press 'Start evidence window', then run the risky sign-in test as this decoy."
Write-Host ""
