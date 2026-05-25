param(
    [int]$LookbackHours = 4,
    [int]$Top = 200,
    [int]$PollSeconds = 30,
    [string]$WindowStartUtc = "",
    [switch]$WaitUntilLogFound
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "AuditLog.Read.All",
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

function Invoke-ZTVPSafeGraphGet {
    param([string]$Uri)

    try {
        return Invoke-MgGraphRequest -Method GET -Uri $Uri
    }
    catch {
        return $null
    }
}

function Get-ZTVPDeviceValue {
    param([object]$Device, [string]$Name)

    if ($null -eq $Device) { return $null }
    $prop = $Device.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function Convert-ZTVPDateString {
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    try {
        return ([datetime]$Value).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    catch {
        return [string]$Value
    }
}

function Convert-ZTVPPolicy {
    param([object]$Policy)

    return [PSCustomObject]@{
        display_name = $Policy.displayName
        result = $Policy.result
        enforced_grant_controls = @($Policy.enforcedGrantControls)
        enforced_session_controls = @($Policy.enforcedSessionControls)
    }
}

function Test-ZTVPDeviceTrustPolicy {
    param([object]$Policy)

    $name = [string]$Policy.displayName
    $result = [string]$Policy.result
    $controls = @($Policy.enforcedGrantControls) -join " "

    if ($result -match "notApplied|reportOnlyNotApplied") {
        return $false
    }

    if ($name -match "DeviceCode|Device Code|LegacyAuth|Legacy Auth") {
        return $false
    }

    return (
        $name -match "compliant|compliance|hybrid|join|joined|managed|intune|unmanaged|device trust|device" -or
        $controls -match "RequireCompliantDevice|CompliantDevice|compliant|domainJoined|joined|managed|Hybrid"
    )
}

function Get-ZTVPSignInsForUser {
    param(
        [string]$UserPrincipalName,
        [int]$LookbackHours,
        [int]$Top
    )

    $startUtc = (Get-Date).ToUniversalTime().AddHours(-1 * $LookbackHours).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $safeUser = $UserPrincipalName.Replace("'", "''")

    $filter1 = [uri]::EscapeDataString("userPrincipalName eq '$safeUser' and createdDateTime ge $startUtc")
    $filter2 = [uri]::EscapeDataString("createdDateTime ge $startUtc")

    $queries = @(
        "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter1&`$top=$Top",
        "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$filter1&`$top=$Top",
        "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter2&`$top=$Top",
        "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$filter2&`$top=$Top"
    )

    $all = @()

    foreach ($uri in $queries) {
        $res = Invoke-ZTVPSafeGraphGet -Uri $uri

        if ($res -and $res.value) {
            foreach ($item in @($res.value)) {
                if ([string]$item.userPrincipalName -ieq $UserPrincipalName) {
                    $all += $item
                }
            }
        }
    }

    $unique = @{}
    $deduped = @()

    foreach ($item in $all) {
        $key = [string]$item.id

        if ([string]::IsNullOrWhiteSpace($key)) {
            $key = "$($item.createdDateTime)|$($item.userPrincipalName)|$($item.appDisplayName)|$($item.resourceDisplayName)|$($item.status.errorCode)"
        }

        if (-not $unique.ContainsKey($key)) {
            $unique[$key] = $true
            $deduped += $item
        }
    }

    return @($deduped | Sort-Object createdDateTime -Descending)
}

function Convert-ZTVPSignInSummary {
    param([object]$Item)

    $errorCode = $null
    $failureReason = $null
    $additionalDetails = $null

    if ($Item.status) {
        $errorCode = $Item.status.errorCode
        $failureReason = $Item.status.failureReason
        $additionalDetails = $Item.status.additionalDetails
    }

    $device = $Item.deviceDetail
    $policies = @()
    $blockingPolicies = @()
    $devicePolicies = @()
    $reportOnlyPolicies = @()
    $notAppliedPolicies = @()

    if ($Item.appliedConditionalAccessPolicies) {
        foreach ($p in @($Item.appliedConditionalAccessPolicies)) {
            $p2 = Convert-ZTVPPolicy -Policy $p
            $policies += $p2

            $r = [string]$p.result

            if ($r -match "failure") {
                $blockingPolicies += $p2
            }
            elseif ($r -match "reportOnly") {
                $reportOnlyPolicies += $p2
            }
            elseif ($r -match "notApplied") {
                $notAppliedPolicies += $p2
            }

            if (Test-ZTVPDeviceTrustPolicy -Policy $p) {
                $devicePolicies += $p2
            }
        }
    }

    $isSuccess = ([int]$errorCode -eq 0)
    $isKeepMeSignedIn = ([int]$errorCode -eq 50140 -or [string]$failureReason -match "Keep me signed in")

    return [PSCustomObject]@{
        id = $Item.id
        created_date_time = Convert-ZTVPDateString -Value $Item.createdDateTime
        user_principal_name = $Item.userPrincipalName
        app_display_name = $Item.appDisplayName
        resource_display_name = $Item.resourceDisplayName
        client_app_used = $Item.clientAppUsed
        ip_address = $Item.ipAddress
        sign_in_event_types = @($Item.signInEventTypes)

        status_error_code = $errorCode
        status_failure_reason = $failureReason
        status_additional_details = $additionalDetails
        conditional_access_status = $Item.conditionalAccessStatus

        is_success = $isSuccess
        is_failure = (-not $isSuccess)
        is_keep_me_signed_in_noise = $isKeepMeSignedIn
        ca_failed = ([string]$Item.conditionalAccessStatus -match "failure")

        device_detail = [PSCustomObject]@{
            device_id = Get-ZTVPDeviceValue -Device $device -Name "deviceId"
            display_name = Get-ZTVPDeviceValue -Device $device -Name "displayName"
            operating_system = Get-ZTVPDeviceValue -Device $device -Name "operatingSystem"
            browser = Get-ZTVPDeviceValue -Device $device -Name "browser"
            is_compliant = Get-ZTVPDeviceValue -Device $device -Name "isCompliant"
            is_managed = Get-ZTVPDeviceValue -Device $device -Name "isManaged"
            trust_type = Get-ZTVPDeviceValue -Device $device -Name "trustType"
        }

        applied_conditional_access_policies = @($policies)
        blocking_policies = @($blockingPolicies)
        device_trust_policies = @($devicePolicies)
        report_only_policies = @($reportOnlyPolicies)
        not_applied_policies = @($notAppliedPolicies)
    }
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "DEV-DV-001"
$statePath = Join-Path $scenarioDir "devdv001-state.json"
$reportPath = Join-Path $reportRoot "DEV-DV-001-result.json"

if (-not (Test-Path $statePath)) {
    throw "No DEV-DV-001 state file found. Prepare decoy first."
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json
$decoyUpn = [string]$state.decoy_user.user_principal_name

if ([string]::IsNullOrWhiteSpace($WindowStartUtc)) {
    throw "WindowStartUtc is required. Start a fresh validation window in Step 2 before analyzing."
}

try {
    $windowStartDateTime = ([datetime]$WindowStartUtc).ToUniversalTime()
}
catch {
    throw "Invalid WindowStartUtc value: $WindowStartUtc"
}

Write-Host "DEV-DV-001 fresh validation window: $WindowStartUtc"
Write-Host "Waiting until a new meaningful sign-in appears for: $decoyUpn"
Write-Host "Poll interval seconds: $PollSeconds"

$summaries = @()
$meaningfulEvents = @()
$pollCount = 0

do {
    $pollCount++

    $rawItems = Get-ZTVPSignInsForUser -UserPrincipalName $decoyUpn -LookbackHours $LookbackHours -Top $Top
    $summaries = @($rawItems | ForEach-Object { Convert-ZTVPSignInSummary -Item $_ })

    $summaries = @(
        $summaries | Where-Object {
            try {
                ([datetime]$_.created_date_time).ToUniversalTime() -ge $windowStartDateTime
            }
            catch {
                $false
            }
        }
    )

    $meaningfulEvents = @($summaries | Where-Object { $_.is_keep_me_signed_in_noise -ne $true })

    if ($meaningfulEvents.Count -gt 0) {
        break
    }

    Write-Host "Poll #$pollCount : no meaningful sign-in found yet after $WindowStartUtc. Waiting $PollSeconds seconds..."
    Start-Sleep -Seconds $PollSeconds
}
while ($WaitUntilLogFound)

if ($meaningfulEvents.Count -eq 0) {
    throw "No meaningful sign-in appeared yet after $WindowStartUtc. Rerun analysis or use WaitUntilLogFound."
}

$successEvents = @($meaningfulEvents | Where-Object { $_.is_success -eq $true })
$failedEvents = @($meaningfulEvents | Where-Object { $_.is_failure -eq $true })
$caFailureEvents = @($meaningfulEvents | Where-Object { $_.ca_failed -eq $true -or $_.blocking_policies.Count -gt 0 })
$deviceTrustFailureEvents = @($meaningfulEvents | Where-Object { $_.is_failure -eq $true -and $_.device_trust_policies.Count -gt 0 })

# Latest meaningful sign-in decides.
$chosen = $meaningfulEvents | Select-Object -First 1

$status = "PARTIAL_SIGNIN_FOUND_UNCLASSIFIED"
$risk = "MEDIUM"
$summary = "ZTVP found a new decoy sign-in, but could not classify the access decision."
$finalClaim = "Sign-in evidence exists, but the unmanaged-device result is unclear."
$evidenceQuality = "Partial - new sign-in found but no clear device-trust decision."

if ($chosen.is_success -eq $true) {
    $status = "FAIL_UNMANAGED_DEVICE_ACCESS_ALLOWED_POLICY_NOT_ENFORCED"
    $risk = "HIGH"
    $summary = "The latest meaningful decoy sign-in succeeded. The unmanaged-device access path was allowed."
    $finalClaim = "The decoy user reached Microsoft 365/cloud resources successfully. The expected unmanaged-device protection was not enforced for this latest access path."
    $evidenceQuality = "Strong - latest meaningful sign-in shows successful cloud access by the decoy user."
}
elseif ($chosen.device_trust_policies.Count -gt 0) {
    $status = "PASS_UNMANAGED_DEVICE_BLOCKED_BY_DEVICE_TRUST"
    $risk = "LOW"
    $summary = "The latest meaningful decoy sign-in was blocked by an enforced device-trust Conditional Access policy."
    $finalClaim = "Microsoft 365/cloud access from the unmanaged device context was blocked by device-trust enforcement."
    $evidenceQuality = "Strong - latest meaningful sign-in shows device-trust Conditional Access failure."
}
elseif ($chosen.blocking_policies.Count -gt 0 -or $chosen.ca_failed -eq $true) {
    $status = "PARTIAL_BLOCKED_BY_NON_DEVICE_OR_UNCLASSIFIED_POLICY"
    $risk = "MEDIUM"
    $summary = "The latest meaningful decoy sign-in was blocked by Conditional Access, but not by a clearly identified device-trust policy."
    $finalClaim = "The access attempt was blocked, but the blocker does not prove unmanaged-device enforcement."
    $evidenceQuality = "Partial - latest meaningful sign-in was blocked, but device-trust cause is unclear."
}

$blockingPolicyName = $null
$deviceTrustPolicyName = $null

if ($chosen.blocking_policies.Count -gt 0) {
    $blockingPolicyName = ($chosen.blocking_policies | Select-Object -First 1).display_name
}

if ($chosen.device_trust_policies.Count -gt 0) {
    $deviceTrustPolicyName = ($chosen.device_trust_policies | Select-Object -First 1).display_name
}

$signInEvidence = [PSCustomObject]@{
    analyzed_at = (Get-Date).ToString("s")
    validation_window_start_utc = $WindowStartUtc
    lookback_hours = $LookbackHours
    poll_seconds = $PollSeconds
    poll_count = $pollCount
    admin_account_used_for_log_query = $ctx.Account
    decoy_user = $decoyUpn

    sign_in_found = ($summaries.Count -gt 0)
    matching_sign_in_count = $summaries.Count
    meaningful_sign_in_count = $meaningfulEvents.Count
    successful_sign_in_count = $successEvents.Count
    failed_sign_in_count = $failedEvents.Count
    ca_failure_sign_in_count = $caFailureEvents.Count
    device_trust_failure_count = $deviceTrustFailureEvents.Count

    selected_decision_basis = "latest meaningful sign-in after validation window"
    selected_event = $chosen

    created_date_time = $chosen.created_date_time
    app_display_name = $chosen.app_display_name
    resource_display_name = $chosen.resource_display_name
    client_app_used = $chosen.client_app_used
    ip_address = $chosen.ip_address
    sign_in_event_types = @($chosen.sign_in_event_types)

    status_error_code = $chosen.status_error_code
    status_failure_reason = $chosen.status_failure_reason
    status_additional_details = $chosen.status_additional_details
    conditional_access_status = $chosen.conditional_access_status

    device_detail = $chosen.device_detail

    blocking_policy_name = $blockingPolicyName
    device_trust_policy_name = $deviceTrustPolicyName
    blocking_policies = @($chosen.blocking_policies)
    device_trust_policies = @($chosen.device_trust_policies)
    applied_conditional_access_policies = @($chosen.applied_conditional_access_policies)
    all_matching_sign_ins = @($meaningfulEvents)
}

$state.sign_in_log_evidence = $signInEvidence
Write-ZTVPJson -Path $statePath -Object $state

$result = [PSCustomObject]@{
    scenario_id = "DEV-DV-001"
    display_id = "DEV-DV-001"
    scenario_name = "Unmanaged Device Cloud Access Probe"
    pillar = "Devices"
    scope = "Cloud"
    mode = "Managed Decoy Unmanaged VM Browser Probe"
    generated_at = (Get-Date).ToString("s")

    tenant_id = $state.tenant_id
    admin_account = $state.admin_account
    decoy_user = [PSCustomObject]@{
        id = $state.decoy_user.id
        user_principal_name = $state.decoy_user.user_principal_name
        display_name = $state.decoy_user.display_name
        password_stored_in_report = $false
        created_by_ztvp = $true
    }

    target = $state.target
    unmanaged_probe = $state.unmanaged_probe

    status = $status
    risk = $risk
    executive_summary = $summary
    final_claim = $finalClaim
    evidence_quality = $evidenceQuality

    controlled_action = "Attempt Microsoft 365/cloud access from a clean unmanaged VM or InPrivate browser using a controlled decoy user, then wait for the new Entra sign-in log and classify the latest meaningful event."
    expected_result = "Unmanaged or non-compliant device access should be blocked or require a compliant/managed device."
    sign_in_log_evidence = $signInEvidence

    metrics = [PSCustomObject]@{
        decoy_user_created = $true
        validation_window_start_utc = $WindowStartUtc
        sign_in_log_found = $true
        matching_sign_in_count = $summaries.Count
        meaningful_sign_in_count = $meaningfulEvents.Count
        successful_sign_in_count = $successEvents.Count
        failed_sign_in_count = $failedEvents.Count
        ca_failure_sign_in_count = $caFailureEvents.Count
        device_trust_failure_count = $deviceTrustFailureEvents.Count
        conditional_access_status = $chosen.conditional_access_status
        device_is_compliant = $chosen.device_detail.is_compliant
        device_is_managed = $chosen.device_detail.is_managed
        device_id_present = (-not [string]::IsNullOrWhiteSpace([string]$chosen.device_detail.device_id))
        blocking_policy_found = ($null -ne $blockingPolicyName)
        blocking_policy_name = $blockingPolicyName
        device_trust_policy_found = ($null -ne $deviceTrustPolicyName)
        device_trust_policy_name = $deviceTrustPolicyName
    }

    recommendations = @(
        "If the result is FAIL, create or enable an enforced Conditional Access policy requiring compliant devices for Microsoft 365 access.",
        "If the result is PASS, keep the device-trust policy enabled and verify the decoy user is still in scope.",
        "Scope the device-trust policy to normal users or a pilot group containing the decoy user.",
        "Target Office 365 / Microsoft 365 cloud apps, or All cloud apps if this matches the organization policy.",
        "Use the grant control Require compliant device. Optionally combine it with Require MFA.",
        "Do not leave the device-trust policy only in report-only mode after validation.",
        "Review exclusions. Break-glass accounts should be excluded, but normal users and test decoys should not be excluded.",
        "Run cleanup to delete the DEV-DV-001 decoy user."
    )

    limitations = @(
        "This scenario waits until a new meaningful sign-in appears after the validation window start.",
        "Keep-me-signed-in interruptions are ignored as noise.",
        "The latest meaningful sign-in after the validation window decides PASS or FAIL.",
        "The decoy user is temporary and must be cleaned up."
    )
}

Write-ZTVPJson -Path $reportPath -Object $result

Write-Host ""
Write-Host "DEV-DV-001 analysis completed."
Write-Host "Status: $status"
Write-Host "Risk: $risk"
Write-Host "Validation window start: $WindowStartUtc"
Write-Host "Poll count: $pollCount"
Write-Host "Meaningful sign-ins: $($meaningfulEvents.Count)"
Write-Host "Selected event time: $($chosen.created_date_time)"
Write-Host "Selected app: $($chosen.app_display_name)"
Write-Host "Selected CA status: $($chosen.conditional_access_status)"
Write-Host "Device trust policy: $deviceTrustPolicyName"
Write-Host "Report: $reportPath"
Write-Host ""
