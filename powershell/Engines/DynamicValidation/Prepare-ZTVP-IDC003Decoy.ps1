param(
    [string]$DecoyAliasPrefix = "ztvp-idc003-legacyauth",
    [string]$DisplayName = "ZTVP ID-C-003 Legacy Auth Decoy User",
    [string]$UsageLocation = "TN"
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Organization.Read.All"
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

function ConvertTo-ZTVPArray {
    param([object]$Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return @($Value) }
    return @($Value)
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

function Invoke-ZTVPPagedGraphQuery {
    param([string]$Uri, [int]$MaxPages = 10)

    $items = @()
    $page = 0
    $nextUri = $Uri

    while ($nextUri -and $page -lt $MaxPages) {
        $page++
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri
        $value = Get-ZTVPValue -Object $response -Name "value"

        if ($value) { $items += @($value) }

        $nextLink = Get-ZTVPValue -Object $response -Name "@odata.nextLink"

        if ([string]::IsNullOrWhiteSpace([string]$nextLink)) {
            $nextUri = $null
        }
        else {
            $nextUri = [string]$nextLink
        }
    }

    return $items
}

function New-ZTVPStrongPassword {
    $chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789!@#$%*-_+=".ToCharArray()
    $bytes = New-Object byte[] 30
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
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

        if ((Get-ZTVPValue -Object $domain -Name "isDefault") -eq $true) {
            $defaultDomain = $name
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($onMicrosoftDomain)) { return $onMicrosoftDomain }
    if (-not [string]::IsNullOrWhiteSpace($defaultDomain)) { return $defaultDomain }
    if (-not [string]::IsNullOrWhiteSpace($firstDomain)) { return $firstDomain }

    throw "No verified tenant domain was found."
}

function Get-ZTVPExchangeCapableSku {
    $skus = @(Invoke-ZTVPPagedGraphQuery -Uri "https://graph.microsoft.com/v1.0/subscribedSkus" -MaxPages 5)
    $candidates = @()

    foreach ($sku in $skus) {
        $skuId = [string](Get-ZTVPValue -Object $sku -Name "skuId")
        $skuPartNumber = [string](Get-ZTVPValue -Object $sku -Name "skuPartNumber")
        $capabilityStatus = [string](Get-ZTVPValue -Object $sku -Name "capabilityStatus")
        $consumedUnits = [int](Get-ZTVPValue -Object $sku -Name "consumedUnits")

        $prepaidUnits = Get-ZTVPValue -Object $sku -Name "prepaidUnits"
        $enabledUnits = 0

        try { $enabledUnits = [int](Get-ZTVPValue -Object $prepaidUnits -Name "enabled") } catch {}

        $availableUnits = [Math]::Max(0, $enabledUnits - $consumedUnits)
        $servicePlans = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $sku -Name "servicePlans"))

        $exchangePlans = @()

        foreach ($plan in $servicePlans) {
            $planName = [string](Get-ZTVPValue -Object $plan -Name "servicePlanName")
            $planStatus = [string](Get-ZTVPValue -Object $plan -Name "provisioningStatus")

            if ($planName -match "EXCHANGE") {
                $exchangePlans += [PSCustomObject]@{
                    servicePlanName = $planName
                    provisioningStatus = $planStatus
                }
            }
        }

        if ($exchangePlans.Count -gt 0 -and $capabilityStatus -eq "Enabled" -and $availableUnits -gt 0) {
            $priority = 50

            if ($skuPartNumber -match "SPE_E5|ENTERPRISEPREMIUM|M365_E5|E5") {
                $priority = 10
            }
            elseif ($skuPartNumber -match "E3|ENTERPRISEPACK") {
                $priority = 20
            }
            elseif ($skuPartNumber -match "EXCHANGE") {
                $priority = 30
            }

            $candidates += [PSCustomObject]@{
                skuId = $skuId
                skuPartNumber = $skuPartNumber
                capabilityStatus = $capabilityStatus
                enabledUnits = $enabledUnits
                consumedUnits = $consumedUnits
                availableUnits = $availableUnits
                priority = $priority
                exchangePlans = @($exchangePlans)
            }
        }
    }

    $selected = @($candidates | Sort-Object priority, skuPartNumber | Select-Object -First 1)

    if ($selected.Count -eq 0) {
        return $null
    }

    return $selected[0]
}

function New-ZTVPFreshUpn {
    param([string]$Prefix, [string]$Domain)

    $safePrefix = $Prefix.ToLower() -replace "[^a-z0-9._-]", "-"
    $safePrefix = $safePrefix -replace "-+", "-"

    if ([string]::IsNullOrWhiteSpace($safePrefix)) {
        $safePrefix = "ztvp-idc003-legacyauth"
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
        [string]$Password,
        [string]$UsageLocation
    )

    $mailNickname = $UserPrincipalName.Split("@")[0]
    $mailNickname = $mailNickname -replace "[^a-zA-Z0-9._-]", ""

    $body = @{
        accountEnabled = $true
        displayName = $DisplayName
        mailNickname = $mailNickname
        userPrincipalName = $UserPrincipalName
        usageLocation = $UsageLocation
        passwordProfile = @{
            forceChangePasswordNextSignIn = $false
            password = $Password
        }
    } | ConvertTo-Json -Depth 20

    return Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users" -Body $body -ContentType "application/json"
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes
$domain = Get-ZTVPDefaultDomain
$selectedSku = Get-ZTVPExchangeCapableSku

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-003"
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null

$resultPath = Join-Path $stateDir "decoy-prepare-result.json"

if ($null -eq $selectedSku) {
    $result = [PSCustomObject]@{
        ok = $false
        status = "NOT_APPLICABLE_NO_FREE_EXCHANGE_LICENSE"
        message = "No free Exchange-capable license seat was found. A fresh controlled legacy-auth decoy mailbox test cannot be prepared."
    }

    $result | ConvertTo-Json -Depth 20 | Set-Content -Path $resultPath -Encoding UTF8

    throw $result.message
}

$upn = New-ZTVPFreshUpn -Prefix $DecoyAliasPrefix -Domain $domain
$password = New-ZTVPStrongPassword

$user = New-ZTVPDecoyUser `
    -UserPrincipalName $upn `
    -DisplayName $DisplayName `
    -Password $password `
    -UsageLocation $UsageLocation

$userId = [string](Get-ZTVPValue -Object $user -Name "id")
$userUpn = [string](Get-ZTVPValue -Object $user -Name "userPrincipalName")

$licenseBody = @{
    addLicenses = @(
        @{
            skuId = $selectedSku.skuId
        }
    )
    removeLicenses = @()
} | ConvertTo-Json -Depth 20

Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/users/$userId/assignLicense" `
    -Body $licenseBody `
    -ContentType "application/json" | Out-Null

$runId = Get-Date -Format "yyyyMMdd-HHmmss"

$statePath = Join-Path $stateDir "decoy-state.json"
$secretOncePath = Join-Path $stateDir "decoy-secret-once.json"
$secretPrivatePath = Join-Path $stateDir "decoy-secret-private.json"

$state = [PSCustomObject]@{
    scenario_id = "ID-C-003"
    scenario_name = "Controlled Legacy Authentication Exposure Validation"
    run_id = $runId
    lifecycle = "FreshLicensedUserPerRun"
    prepared_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    connected_account = $ctx.Account
    decoy_user = [PSCustomObject]@{
        id = $userId
        user_principal_name = $userUpn
        display_name = $DisplayName
        usage_location = $UsageLocation
        created_by_ztvp = $true
        must_be_deleted_after_test = $true
    }
    license = [PSCustomObject]@{
        assigned = $true
        sku_id = $selectedSku.skuId
        sku_part_number = $selectedSku.skuPartNumber
        exchange_plans = @($selectedSku.exchangePlans)
    }
    cleanup = [PSCustomObject]@{
        status = "Pending"
        cleaned_at = $null
        action = $null
    }
}

$secretPublic = [PSCustomObject]@{
    user_principal_name = $userUpn
    temporary_password = $password
    warning = "This password is shown once. ZTVP also stores a private local copy only until cleanup so the protocol test can authenticate."
}

$secretPrivate = [PSCustomObject]@{
    user_principal_name = $userUpn
    temporary_password = $password
    purpose = "Private local protocol-test secret. Delete during cleanup. Do not commit."
}

$state | ConvertTo-Json -Depth 50 | Set-Content -Path $statePath -Encoding UTF8
$secretPublic | ConvertTo-Json -Depth 20 | Set-Content -Path $secretOncePath -Encoding UTF8
$secretPrivate | ConvertTo-Json -Depth 20 | Set-Content -Path $secretPrivatePath -Encoding UTF8

$result = [PSCustomObject]@{
    ok = $true
    status = "DECOY_CREATED_AND_LICENSED"
    run_id = $runId
    user_principal_name = $userUpn
    user_id = $userId
    assigned_sku_part_number = $selectedSku.skuPartNumber
    assigned_sku_id = $selectedSku.skuId
    state_path = $statePath
    secret_available_once = $true
}

$result | ConvertTo-Json -Depth 50 | Set-Content -Path $resultPath -Encoding UTF8

Write-Host ""
Write-Host "ID-C-003 licensed legacy-auth decoy created"
Write-Host "UPN: $userUpn"
Write-Host "Assigned license: $($selectedSku.skuPartNumber)"
Write-Host "Run ID: $runId"
Write-Host "State: $statePath"
Write-Host ""

