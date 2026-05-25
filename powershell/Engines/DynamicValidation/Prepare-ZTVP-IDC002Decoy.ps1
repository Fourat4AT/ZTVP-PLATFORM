param(
    [string]$DecoyAliasPrefix = "ztvp-idc002-devicecode",
    [string]$DisplayName = "ZTVP ID-C-002 Device Code Decoy User"
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "User.ReadWrite.All",
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
        Connect-MgGraph -Scopes $Scopes -NoWelcome | Out-Null
        $ctx = Get-MgContext
    }

    return $ctx
}

function New-ZTVPStrongPassword {
    $chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789!@#$%*-_+=".ToCharArray()
    $bytes = New-Object byte[] 30
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()

    $password = -join ($bytes | ForEach-Object {
        $chars[$_ % $chars.Length]
    })

    return "$password" + "Aa1!"
}

function Get-ZTVPDefaultDomain {
    $orgResponse = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains'
    $orgItems = @(Get-ZTVPValue -Object $orgResponse -Name "value")

    if ($orgItems.Count -eq 0) {
        throw "Could not read organization details from Microsoft Graph."
    }

    $tenant = $orgItems[0]
    $domains = @(Get-ZTVPValue -Object $tenant -Name "verifiedDomains")

    $onMicrosoftDomain = $null
    $defaultDomain = $null
    $firstDomain = $null

    foreach ($domain in $domains) {
        $name = [string](Get-ZTVPValue -Object $domain -Name "name")

        if ([string]::IsNullOrWhiteSpace($firstDomain)) {
            $firstDomain = $name
        }

        if ($name -like "*.onmicrosoft.com" -and [string]::IsNullOrWhiteSpace($onMicrosoftDomain)) {
            $onMicrosoftDomain = $name
        }

        $isDefault = Get-ZTVPValue -Object $domain -Name "isDefault"

        if ($isDefault -eq $true) {
            $defaultDomain = $name
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($onMicrosoftDomain)) { return $onMicrosoftDomain }
    if (-not [string]::IsNullOrWhiteSpace($defaultDomain)) { return $defaultDomain }
    if (-not [string]::IsNullOrWhiteSpace($firstDomain)) { return $firstDomain }

    throw "No verified tenant domain was found."
}

function New-ZTVPFreshUpn {
    param([string]$Prefix, [string]$Domain)

    $safePrefix = $Prefix.ToLower() -replace "[^a-z0-9._-]", "-"
    $safePrefix = $safePrefix -replace "-+", "-"

    if ([string]::IsNullOrWhiteSpace($safePrefix)) {
        $safePrefix = "ztvp-idc002-devicecode"
    }

    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    $chars = (48..57) + (97..122)
    $suffix = -join ($chars | Get-Random -Count 5 | ForEach-Object { [char]$_ })

    return "$safePrefix-$timestamp-$suffix@$Domain"
}

function New-ZTVPDecoyUser {
    param(
        [string]$UserPrincipalName,
        [string]$DisplayName,
        [string]$Password
    )

    $mailNickname = $UserPrincipalName.Split("@")[0]
    $mailNickname = $mailNickname -replace "[^a-zA-Z0-9._-]", ""

    $body = @{
        accountEnabled = $true
        displayName = $DisplayName
        mailNickname = $mailNickname
        userPrincipalName = $UserPrincipalName
        passwordProfile = @{
            forceChangePasswordNextSignIn = $false
            password = $Password
        }
    } | ConvertTo-Json -Depth 20

    return Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users" -Body $body -ContentType "application/json"
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes
$domain = Get-ZTVPDefaultDomain
$upn = New-ZTVPFreshUpn -Prefix $DecoyAliasPrefix -Domain $domain
$password = New-ZTVPStrongPassword
$user = New-ZTVPDecoyUser -UserPrincipalName $upn -DisplayName $DisplayName -Password $password

$userId = [string](Get-ZTVPValue -Object $user -Name "id")
$userUpn = [string](Get-ZTVPValue -Object $user -Name "userPrincipalName")
$userDisplayName = [string](Get-ZTVPValue -Object $user -Name "displayName")

$runId = Get-Date -Format "yyyyMMdd-HHmmss"

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-002"
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null

$statePath = Join-Path $stateDir "decoy-state.json"
$secretPath = Join-Path $stateDir "decoy-secret-once.json"
$resultPath = Join-Path $stateDir "decoy-prepare-result.json"

$state = [PSCustomObject]@{
    scenario_id = "ID-C-002"
    scenario_name = "Device Code Flow Block Validation"
    run_id = $runId
    lifecycle = "FreshUserPerRun"
    state_version = 1
    prepared_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    connected_account = $ctx.Account
    decoy_user = [PSCustomObject]@{
        id = $userId
        user_principal_name = $userUpn
        display_name = $userDisplayName
        created_by_ztvp = $true
        must_be_deleted_after_test = $true
        domain = $domain
    }
    device_code_challenge = $null
    cleanup = [PSCustomObject]@{
        status = "Pending"
        cleaned_at = $null
        action = $null
    }
}

$state | ConvertTo-Json -Depth 30 | Set-Content -Path $statePath -Encoding UTF8

$secret = [PSCustomObject]@{
    user_principal_name = $userUpn
    temporary_password = $password
    force_change_password_next_signin = $false
    warning = "This password is shown once by ZTVP. Copy it now. The decoy user must be deleted after the test."
}

$secret | ConvertTo-Json -Depth 10 | Set-Content -Path $secretPath -Encoding UTF8

$result = [PSCustomObject]@{
    ok = $true
    created = $true
    lifecycle = "FreshUserPerRun"
    run_id = $runId
    user_principal_name = $userUpn
    user_id = $userId
    state_path = $statePath
    secret_available_once = $true
}

$result | ConvertTo-Json -Depth 30 | Set-Content -Path $resultPath -Encoding UTF8

Write-Host ""
Write-Host "ID-C-002 fresh device-code decoy user created"
Write-Host "UPN: $userUpn"
Write-Host "Run ID: $runId"
Write-Host "State: $statePath"
Write-Host ""
