param(
    [string]$UserPrefix = "ztvp-appdv001-decoy",
    [string]$DisplayName = "ZTVP APP-DV-001 Enterprise App Assignment Decoy User",
    [string]$TenantDomain = ""
)

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

function New-ZTVPPassword {
    $suffix = [Guid]::NewGuid().ToString("N").Substring(0, 14)
    return "ZTVP!" + $suffix + "aA9"
}

function New-ZTVPRandomSuffix {
    $chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    $bytes = New-Object byte[] 5
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)

    $out = ""
    foreach ($b in $bytes) {
        $out += $chars[$b % $chars.Length]
    }

    return $out
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "APP-DV-001"
$historyDir = Join-Path $scenarioDir "history"

New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null
New-Item -ItemType Directory -Path $historyDir -Force | Out-Null

$statePath = Join-Path $scenarioDir "appdv001-state.json"
$preparePath = Join-Path $scenarioDir "appdv001-prepare-result.json"

if (Test-Path $statePath) {
    throw "An active APP-DV-001 state file exists. Run cleanup before preparing a new decoy."
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

# 1. Create the decoy standard user (intentionally NOT assigned to the controlled app).
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

# 2. Create the controlled enterprise application (app registration) as a public client
#    so the decoy user can attempt a real interactive sign-in to it.
$appDisplayName = "ZTVP-APP-DV-001-AssignmentEnforcement-App-$runId"

$appBody = @{
    displayName = $appDisplayName
    signInAudience = "AzureADMyOrg"
    publicClient = @{
        redirectUris = @("http://localhost")
    }
} | ConvertTo-Json -Depth 20

$application = Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/applications" `
    -Body $appBody `
    -ContentType "application/json"

$appId = [string]$application.appId
$appObjectId = [string]$application.id

# 3. Create the service principal and require user assignment so unassigned users are blocked.
$spBody = @{
    appId = $appId
} | ConvertTo-Json -Depth 20

$servicePrincipal = Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" `
    -Body $spBody `
    -ContentType "application/json"

$spObjectId = [string]$servicePrincipal.id

$spPatchBody = @{
    appRoleAssignmentRequired = $true
} | ConvertTo-Json -Depth 20

Invoke-MgGraphRequest `
    -Method PATCH `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId" `
    -Body $spPatchBody `
    -ContentType "application/json" | Out-Null

$state = [PSCustomObject]@{
    scenario_id = "APP-DV-001"
    display_id = "APP-DV-001"
    scenario_name = "Enterprise App Assignment Enforcement Probe"
    mode = "Three-Step Managed Decoy Enterprise App Sign-in"
    run_id = $runId
    prepared_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    admin_account = $ctx.Account
    tenant_domain = $TenantDomain
    decoy_user = [PSCustomObject]@{
        id = $user.id
        user_principal_name = $upn
        display_name = $DisplayName
        temporary_password = $password
        assigned_to_app = $false
        created_by_ztvp = $true
    }
    target_app = [PSCustomObject]@{
        display_name = $appDisplayName
        app_id = $appId
        app_object_id = $appObjectId
        service_principal_id = $spObjectId
        app_role_assignment_required = $true
        created_by_ztvp = $true
    }
    assignment_probe = [PSCustomObject]@{
        attempted = $false
        access_granted = $null
        assignment_required_blocked = $null
        connected_account = $null
        error_message = $null
    }
}

Write-ZTVPJson -Path $statePath -Object $state

$result = [PSCustomObject]@{
    scenario_id = "APP-DV-001"
    status = "DECOY_READY"
    tenant_id = $ctx.TenantId
    admin_account = $ctx.Account
    decoy_user_principal_name = $upn
    decoy_temporary_password = $password
    decoy_assigned_to_app = $false
    target_app_display_name = $appDisplayName
    target_app_id = $appId
    target_app_role_assignment_required = $true
    tenant_domain = $TenantDomain
    password_visible_for_probe = $true
    message = "Decoy user and controlled assignment-required enterprise app created. Use this UPN and password in Step 2 when Microsoft login asks."
    state_path = $statePath
    prepared_at = (Get-Date).ToString("s")
}

Write-ZTVPJson -Path $preparePath -Object $result

Write-Host ""
Write-Host "APP-DV-001 decoy user and controlled enterprise app prepared."
Write-Host "Tenant ID: $($ctx.TenantId)"
Write-Host "Decoy UPN: $upn"
Write-Host "Temporary password: $password"
Write-Host "Target app: $appDisplayName ($appId)"
Write-Host "Assignment required: True. The decoy user is intentionally NOT assigned."
Write-Host "Use this decoy account in Step 2."
Write-Host ""
