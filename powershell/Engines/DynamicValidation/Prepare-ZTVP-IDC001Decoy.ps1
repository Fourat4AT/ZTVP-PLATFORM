param(
    [string]$DecoyAliasPrefix = "ztvp-idc001-decoy",

    [string]$DisplayName = "ZTVP ID-C-001 Decoy Privileged User",

    [switch]$AssignRole,

    [string]$RoleName = "Security Reader"
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "User.ReadWrite.All",
    "Directory.Read.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory"
)

$AllowedRoles = @(
    "Directory Reader",
    "Reports Reader",
    "Security Reader",
    "Global Reader",
    "Conditional Access Administrator"
)

if ($AssignRole -and ($AllowedRoles -notcontains $RoleName)) {
    throw "Role '$RoleName' is not allowed for this validation profile. Allowed roles: $($AllowedRoles -join ', ')"
}

function Get-ZTVPValue {
    param(
        [object]$Object,
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ([string]$key -eq $Name) {
                return $Object[$key]
            }
        }
    }

    $property = $Object.PSObject.Properties[$Name]

    if ($property) {
        return $property.Value
    }

    return $null
}

function Ensure-ZTVPGraphConnection {
    param(
        [string[]]$Scopes
    )

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
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch {}

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

    if (-not [string]::IsNullOrWhiteSpace($onMicrosoftDomain)) {
        return $onMicrosoftDomain
    }

    if (-not [string]::IsNullOrWhiteSpace($defaultDomain)) {
        return $defaultDomain
    }

    if (-not [string]::IsNullOrWhiteSpace($firstDomain)) {
        return $firstDomain
    }

    throw "No verified tenant domain was found."
}

function Get-ZTVPUserByUpn {
    param(
        [string]$UserPrincipalName
    )

    $safeUpn = $UserPrincipalName.Replace("'", "''")
    $filter = [System.Uri]::EscapeDataString("userPrincipalName eq '$safeUpn'")
    $uri = "https://graph.microsoft.com/v1.0/users?`$filter=$filter&`$select=id,userPrincipalName,displayName,accountEnabled"

    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $users = @(Get-ZTVPValue -Object $response -Name "value")

    if ($users.Count -gt 0) {
        return $users[0]
    }

    return $null
}

function New-ZTVPFreshUpn {
    param(
        [string]$Prefix,
        [string]$Domain
    )

    $safePrefix = $Prefix.ToLower() -replace "[^a-z0-9._-]", "-"
    $safePrefix = $safePrefix -replace "-+", "-"

    if ([string]::IsNullOrWhiteSpace($safePrefix)) {
        $safePrefix = "ztvp-idc001-decoy"
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

function Add-ZTVPDirectoryRoleAssignment {
    param(
        [string]$PrincipalId,
        [string]$RoleName
    )

    $roleAliases = @($RoleName)
    if ($RoleName -eq "Directory Reader") {
        $roleAliases += "Directory Readers"
    }

    $roles = @()
    foreach ($candidateName in @($roleAliases | Select-Object -Unique)) {
        $safeRoleName = $candidateName.Replace("'", "''")
        $filter = [System.Uri]::EscapeDataString("displayName eq '$safeRoleName'")
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=$filter"
        $roleResponse = Invoke-MgGraphRequest -Method GET -Uri $uri
        $roles = @(Get-ZTVPValue -Object $roleResponse -Name "value")
        if ($roles.Count -gt 0) { break }
    }

    if ($roles.Count -eq 0 -and $RoleName -eq "Directory Reader") {
        $templateFilter = [System.Uri]::EscapeDataString("templateId eq '88d8e3e3-8f55-4a1e-953a-9b9898b8876b'")
        $templateUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=$templateFilter"
        $roleResponse = Invoke-MgGraphRequest -Method GET -Uri $templateUri
        $roles = @(Get-ZTVPValue -Object $roleResponse -Name "value")
    }

    if ($roles.Count -eq 0) {
        throw "Role definition was not found: $RoleName. Tried aliases: $($roleAliases -join ', ')"
    }

    $role = $roles[0]
    $roleId = [string](Get-ZTVPValue -Object $role -Name "id")
    $resolvedRoleName = [string](Get-ZTVPValue -Object $role -Name "displayName")
    if ([string]::IsNullOrWhiteSpace($resolvedRoleName)) { $resolvedRoleName = $RoleName }

    $assignmentBody = @{
        principalId = $PrincipalId
        roleDefinitionId = $roleId
        directoryScopeId = "/"
    } | ConvertTo-Json -Depth 10

    try {
        $assignment = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" -Body $assignmentBody -ContentType "application/json"

        return [PSCustomObject]@{
            assigned = $true
            role_name = $RoleName
            resolved_role_name = $resolvedRoleName
            role_definition_id = $roleId
            assignment_id = Get-ZTVPValue -Object $assignment -Name "id"
            error = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            assigned = $false
            role_name = $RoleName
            resolved_role_name = $resolvedRoleName
            role_definition_id = $roleId
            assignment_id = $null
            error = $_.Exception.Message
        }
    }
}

function Get-ZTVPRoleProfile {
    param(
        [string]$RoleName,
        [bool]$AssignRole
    )

    if (-not $AssignRole) {
        return [PSCustomObject]@{
            profile = "No directory role"
            description = "Fresh decoy user created without directory role assignment."
            sensitivity = "None"
        }
    }

    switch ($RoleName) {
        "Directory Reader" {
            return [PSCustomObject]@{
                profile = "Low privilege directory visibility"
                description = "Read-only directory role."
                sensitivity = "Low"
            }
        }

        "Reports Reader" {
            return [PSCustomObject]@{
                profile = "Low privilege reporting visibility"
                description = "Read-only reporting role."
                sensitivity = "Low"
            }
        }

        "Security Reader" {
            return [PSCustomObject]@{
                profile = "Recommended privileged reader"
                description = "Recommended default. Security-sensitive read-only privileged role."
                sensitivity = "Medium"
            }
        }

        "Global Reader" {
            return [PSCustomObject]@{
                profile = "Broad privileged reader"
                description = "Broad read-only tenant visibility."
                sensitivity = "Medium"
            }
        }

        "Conditional Access Administrator" {
            return [PSCustomObject]@{
                profile = "Advanced policy administrator"
                description = "Advanced validation role. Use only in approved test scope."
                sensitivity = "High"
            }
        }

        default {
            return [PSCustomObject]@{
                profile = "Unknown role"
                description = "Unknown role profile."
                sensitivity = "Unknown"
            }
        }
    }
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$domain = Get-ZTVPDefaultDomain

$DecoyUserPrincipalName = New-ZTVPFreshUpn -Prefix $DecoyAliasPrefix -Domain $domain

$existingUser = Get-ZTVPUserByUpn -UserPrincipalName $DecoyUserPrincipalName

if ($null -ne $existingUser) {
    throw "Generated decoy UPN already exists. Run again to generate a new unique user."
}

$password = New-ZTVPStrongPassword
$user = New-ZTVPDecoyUser -UserPrincipalName $DecoyUserPrincipalName -DisplayName $DisplayName -Password $password

$userId = [string](Get-ZTVPValue -Object $user -Name "id")
$userUpn = [string](Get-ZTVPValue -Object $user -Name "userPrincipalName")
$userDisplayName = [string](Get-ZTVPValue -Object $user -Name "displayName")

$roleProfile = Get-ZTVPRoleProfile -RoleName $RoleName -AssignRole ([bool]$AssignRole)

$roleResult = [PSCustomObject]@{
    assigned = $false
    role_name = if ($AssignRole) { $RoleName } else { "None" }
    role_definition_id = $null
    assignment_id = $null
    error = if ($AssignRole) { $null } else { "Role assignment was not requested." }
}

if ($AssignRole) {
    $roleResult = Add-ZTVPDirectoryRoleAssignment -PrincipalId $userId -RoleName $RoleName
}

$runId = Get-Date -Format "yyyyMMdd-HHmmss"

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-001"
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null

$statePath = Join-Path $stateDir "decoy-state.json"
$secretPath = Join-Path $stateDir "decoy-secret-once.json"
$resultPath = Join-Path $stateDir "decoy-prepare-result.json"

$state = [PSCustomObject]@{
    scenario_id = "ID-C-001"
    run_id = $runId
    lifecycle = "FreshUserPerRun"
    state_version = 3
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
    role_profile = $roleProfile
    role_assignment = $roleResult
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
    role_profile = $roleProfile
    role_assignment = $roleResult
    state_path = $statePath
    secret_available_once = $true
}

$result | ConvertTo-Json -Depth 30 | Set-Content -Path $resultPath -Encoding UTF8

Write-Host ""
Write-Host "ID-C-001 fresh decoy user created"
Write-Host "UPN: $userUpn"
Write-Host "Run ID: $runId"
Write-Host "Role selected: $($roleResult.role_name)"
Write-Host "Role assigned: $($roleResult.assigned)"
Write-Host "State: $statePath"
Write-Host ""
