param(
    [string]$UserPrefix = "ztvp-appc002-forwarding",
    [string]$DisplayName = "ZTVP APP-C-002 Exchange Forwarding Decoy Mailbox",
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
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch {}

        Connect-MgGraph -Scopes $Scopes -ContextScope CurrentUser -NoWelcome | Out-Null
        $ctx = Get-MgContext
    }

    return $ctx
}

function Write-ZTVPJson {
    param(
        [string]$Path,
        [object]$Object
    )

    $Object |
        ConvertTo-Json -Depth 100 |
        Set-Content -Path $Path -Encoding UTF8
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

function New-ZTVPPassword {
    $bytes = New-Object byte[] 20
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)

    $raw = [Convert]::ToBase64String($bytes)
    $raw = $raw.Replace("=", "")
    $raw = $raw.Replace("/", "_")
    $raw = $raw.Replace("+", "!")

    return "ZTVP!" + $raw + "a1"
}

function Get-ZTVPTenantDomain {
    $uri = "https://graph.microsoft.com/v1.0/organization?`$select=verifiedDomains"
    $org = Invoke-MgGraphRequest -Method GET -Uri $uri
    $values = @(Get-ZTVPValue -Object $org -Name "value")

    foreach ($o in $values) {
        foreach ($d in @($o.verifiedDomains)) {
            if ($d.isInitial -eq $true) {
                return [string]$d.name
            }
        }
    }

    foreach ($o in $values) {
        foreach ($d in @($o.verifiedDomains)) {
            if ($d.isDefault -eq $true) {
                return [string]$d.name
            }
        }
    }

    throw "Could not determine tenant domain."
}




function Convert-ZTVPInt {
    param([object]$Value)

    if ($null -eq $Value) { return 0 }

    try { return [int]$Value }
    catch { return 0 }
}

function Test-ZTVPExcludedSkuForExchange {
    param([string]$SkuPartNumber)

    if ([string]::IsNullOrWhiteSpace($SkuPartNumber)) {
        return $true
    }

    $sku = $SkuPartNumber.ToUpperInvariant()

    # Exclude obvious non-mailbox products.
    # Important: DO NOT exclude every SKU containing TEAMS,
    # because Microsoft 365 E5 no Teams can contain TEAMS in the SKU name.
    if ($sku -match "POWER_BI|POWERBI|FABRIC|POWERAPPS|FLOW|VISIO|PROJECT|DYN365|CRM|VIVA|DEFENDER|VULNERABILITY") {
        return $true
    }

    # Exclude Teams-only products only when the SKU starts like a Teams SKU.
    if ($sku -match "^TEAMS|^MCOMEET|^MCOSTANDARD|^MCOEV") {
        return $true
    }

    return $false
}

function Get-ZTVPExchangeSkuScore {
    param(
        [string]$SkuPartNumber,
        [string[]]$PlanNames
    )

    $score = 0

    if ([string]::IsNullOrWhiteSpace($SkuPartNumber)) {
        return 0
    }

    $sku = $SkuPartNumber.ToUpperInvariant()

    if (Test-ZTVPExcludedSkuForExchange -SkuPartNumber $sku) {
        return -100
    }

    # Strong Exchange-capable suite names.
    # This intentionally accepts E5 no Teams.
    if ($sku -match "SPE_E5|ENTERPRISEPREMIUM|MICROSOFT_365_E5|M365_E5|OFFICE_365_E5|E5") {
        $score += 300
    }
    elseif ($sku -match "SPE_E3|ENTERPRISEPACK|MICROSOFT_365_E3|M365_E3|OFFICE_365_E3|E3") {
        $score += 260
    }
    elseif ($sku -match "STANDARDPACK|BUSINESS_PREMIUM|BUSINESS_STANDARD|O365_BUSINESS|M365_BUSINESS|SPB") {
        $score += 220
    }
    elseif ($sku -match "EXCHANGESTANDARD|EXCHANGEENTERPRISE|EXCHANGE") {
        $score += 220
    }

    $exchangePlans = @(
        $PlanNames |
        Where-Object {
            $_ -match "EXCHANGE" -and
            $_ -notmatch "FOUNDATION|ARCHIVE|HYGIENE|ANALYTICS|MIGRATION"
        }
    )

    if ($exchangePlans.Count -gt 0) {
        $score += 500
    }
    elseif (@($PlanNames | Where-Object { $_ -match "EXCHANGE" }).Count -gt 0) {
        $score += 150
    }

    return $score
}

function Get-ZTVPExchangeSku {
    $response = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/subscribedSkus"
    $skus = @(Get-ZTVPValue -Object $response -Name "value")

    $scanRows = @()
    $candidates = @()

    foreach ($sku in $skus) {
        $skuId = [string](Get-ZTVPValue -Object $sku -Name "skuId")
        $skuPartNumber = [string](Get-ZTVPValue -Object $sku -Name "skuPartNumber")
        $capabilityStatus = [string](Get-ZTVPValue -Object $sku -Name "capabilityStatus")

        $prepaid = Get-ZTVPValue -Object $sku -Name "prepaidUnits"
        $enabled = Convert-ZTVPInt (Get-ZTVPValue -Object $prepaid -Name "enabled")
        $consumed = Convert-ZTVPInt (Get-ZTVPValue -Object $sku -Name "consumedUnits")
        $available = $enabled - $consumed

        $plans = @(Get-ZTVPValue -Object $sku -Name "servicePlans")
        $planNames = @()

        foreach ($plan in $plans) {
            $planName = [string](Get-ZTVPValue -Object $plan -Name "servicePlanName")

            if (-not [string]::IsNullOrWhiteSpace($planName)) {
                $planNames += $planName.ToUpperInvariant()
            }
        }

        $excluded = Test-ZTVPExcludedSkuForExchange -SkuPartNumber $skuPartNumber
        $score = Get-ZTVPExchangeSkuScore -SkuPartNumber $skuPartNumber -PlanNames $planNames
        $exchangePlans = @($planNames | Where-Object { $_ -match "EXCHANGE" })

        $isCandidate = (
            $capabilityStatus -eq "Enabled" -and
            $available -gt 0 -and
            -not $excluded -and
            $score -gt 0
        )

        $scanRows += [PSCustomObject]@{
            skuId = $skuId
            skuPartNumber = $skuPartNumber
            capabilityStatus = $capabilityStatus
            enabled = $enabled
            consumed = $consumed
            available = $available
            excluded = $excluded
            score = $score
            exchangePlans = @($exchangePlans)
            selectedCandidate = $isCandidate
        }

        if ($isCandidate) {
            $candidates += [PSCustomObject]@{
                skuId = $skuId
                skuPartNumber = $skuPartNumber
                available = $available
                priority = $score
                exchangePlanNames = @($exchangePlans)
                allPlanNames = @($planNames)
            }
        }
    }

    $scanDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\APP-C-002"
    New-Item -ItemType Directory -Path $scanDir -Force | Out-Null

    $scanPath = Join-Path $scanDir "appc002-license-scan.json"
    $scanRows | ConvertTo-Json -Depth 100 | Set-Content -Path $scanPath -Encoding UTF8

    Write-Host ""
    Write-Host "APP-C-002 license scan:"
    Write-Host "Saved to: $scanPath"
    Write-Host ""

    foreach ($row in @($scanRows | Sort-Object -Property score -Descending)) {
        Write-Host ("SKU: {0} | Available: {1} | Score: {2} | Excluded: {3} | Candidate: {4}" -f $row.skuPartNumber, $row.available, $row.score, $row.excluded, $row.selectedCandidate)
    }

    if ($candidates.Count -eq 0) {
        return $null
    }

    $selected = @(
        $candidates |
        Sort-Object `
            -Property @{ Expression = "priority"; Descending = $true }, @{ Expression = "available"; Descending = $true }
    )[0]

    Write-Host ""
    Write-Host "Selected Exchange-capable SKU: $($selected.skuPartNumber)"
    Write-Host ""

    return $selected
}


$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "APP-C-002"
$historyDir = Join-Path $scenarioDir "history"

New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null
New-Item -ItemType Directory -Path $historyDir -Force | Out-Null

$statePath = Join-Path $scenarioDir "appc002-state.json"
$reportPath = Join-Path $reportRoot "APP-C-002-result.json"

if (Test-Path $statePath) {
    throw "An active APP-C-002 run already exists. Cleanup the active run first."
}

$sku = Get-ZTVPExchangeSku

if ($null -eq $sku) {
    $result = [PSCustomObject]@{
        scenario_id = "APP-C-002"
        display_id = "APP-DV-002"
        scenario_name = "Exchange External Mail Forwarding Exposure Validation"
        pillar = "Applications"
        scope = "Cloud"
        generated_at = (Get-Date).ToString("s")
        tenant_id = $ctx.TenantId
        connected_account = $ctx.Account
        status = "NOT_APPLICABLE_NO_EXCHANGE_LICENSE"
        risk = "INFO"
        executive_summary = "No available Exchange-capable license was found in this tenant."
        final_claim = "ZTVP could not create a controlled Exchange mailbox, so this validation is not applicable until an Exchange-capable license is available."
        evidence_quality = "Configuration prerequisite not met."
        warnings = @("No Exchange-capable license with available units was found.")
        metrics = [PSCustomObject]@{
            mailbox_ready = $false
            mailbox_forwarding_allowed = $false
            inbox_rule_allowed = $false
            forwarding_artifacts_cleanup_completed = $true
        }
    }

    Write-ZTVPJson -Path $reportPath -Object $result

    Write-Host "NOT APPLICABLE - No Exchange License"
    Write-Host "Report saved to: $reportPath"
    exit 0
}

$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$suffix = New-ZTVPRandomSuffix
$domain = Get-ZTVPTenantDomain

$upn = "$UserPrefix-$runId-$suffix@$domain"
$mailNickname = ("appc002" + $runId + $suffix).Replace("-", "")
$password = New-ZTVPPassword

$userBodyObject = @{
    accountEnabled = $true
    displayName = "$DisplayName $runId"
    mailNickname = $mailNickname
    userPrincipalName = $upn
    usageLocation = $UsageLocation
    passwordProfile = @{
        forceChangePasswordNextSignIn = $false
        password = $password
    }
}

$userBody = $userBodyObject | ConvertTo-Json -Depth 20

$user = Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/users" `
    -Body $userBody `
    -ContentType "application/json"

$userId = [string](Get-ZTVPValue -Object $user -Name "id")

$licenseBodyObject = @{
    addLicenses = @(
        @{
            skuId = $sku.skuId
        }
    )
    removeLicenses = @()
}

$licenseBody = $licenseBodyObject | ConvertTo-Json -Depth 20

Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/users/$userId/assignLicense" `
    -Body $licenseBody `
    -ContentType "application/json" | Out-Null

$state = [PSCustomObject]@{
    scenario_id = "APP-C-002"
    display_id = "APP-DV-002"
    scenario_name = "Exchange External Mail Forwarding Exposure Validation"
    run_id = $runId
    prepared_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    connected_account = $ctx.Account
    decoy_user = [PSCustomObject]@{
        id = $userId
        user_principal_name = $upn
        display_name = "$DisplayName $runId"
        usage_location = $UsageLocation
        created_by_ztvp = $true
        password_stored_in_report = $false
        must_be_deleted_after_test = $true
    }
    assigned_license = [PSCustomObject]@{
        sku_id = $sku.skuId
        sku_part_number = $sku.skuPartNumber
        exchange_plan_names = @($sku.exchangePlanNames)
        assigned_by_ztvp = $true
        must_be_removed_after_test = $true
    }
    forwarding_artifacts = [PSCustomObject]@{
        mailbox_forwarding_configured = $false
        inbox_rule_created = $false
        inbox_rule_name = $null
        external_target = $null
    }
    cleanup = [PSCustomObject]@{
        status = "Pending"
        action = "Cleanup removes forwarding artifacts, license assignment, decoy user, and local state."
    }
}

Write-ZTVPJson -Path $statePath -Object $state

Write-Host ""
Write-Host "APP-C-002 preparation completed."
Write-Host "Run ID: $runId"
Write-Host "Decoy mailbox user: $upn"
Write-Host "Assigned license: $($sku.skuPartNumber)"
Write-Host "State: $statePath"
Write-Host ""
