param(
    [int]$WaitMinutes = 15,
    [int]$PollSeconds = 60
)

$ErrorActionPreference = "Stop"

function Get-ZTVPValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    return $Object.$Name
}

function Test-ZTVPTextAny {
    param([string]$Text, [string[]]$Needles)
    $safeText = if ($null -eq $Text) { "" } else { $Text }
    $value = $safeText.ToLowerInvariant()
    foreach ($needle in $Needles) {
        if ($value.Contains($needle.ToLowerInvariant())) { return $true }
    }
    return $false
}

function ConvertTo-ZTVPJsonFile {
    param($Object, [string]$Path)
    $Object | ConvertTo-Json -Depth 80 | Set-Content -Path $Path -Encoding UTF8
}

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "APP-DV-004"
$statePath = Join-Path $scenarioDir "appdv004-state.json"
$reportPath = Join-Path $reportRoot "APP-DV-004-result.json"
New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null

if (-not (Test-Path $statePath)) {
    throw "APP-DV-004 state file not found. Start the validation window from the UI first."
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json
$runId = [string]$state.run_id
$testUser = [string]$state.test_user
$targetApp = [string]$state.target_app
$targetUrl = [string]$state.target_app_url
$expectedPolicy = [string]$state.expected_policy_name
$validationStartUtc = [string]$state.validation_start_utc

if ([string]::IsNullOrWhiteSpace($testUser)) { throw "Test user UPN is required." }
if ([string]::IsNullOrWhiteSpace($targetApp)) { throw "Target app is required." }
if ([string]::IsNullOrWhiteSpace($validationStartUtc)) { throw "Validation start UTC is missing." }

$requiredScopes = @("AuditLog.Read.All", "Policy.Read.All", "Directory.Read.All")
try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $ctx = Get-MgContext
    if (-not $ctx) {
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome | Out-Null
        $ctx = Get-MgContext
    }
}
catch {
    $report = [ordered]@{
        scenario_id = "APP-DV-004"
        display_id = "APP-DV-004"
        scenario_name = "Sensitive App Access From Unmanaged Device Probe"
        pillar = "Applications"
        scope = "Cloud"
        run_id = $runId
        tenant_id = $null
        test_user = $testUser
        target_app = $targetApp
        target_app_url = $targetUrl
        started_utc = $validationStartUtc
        completed_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        status = "ERROR_GRAPH_CONNECTION_FAILED"
        risk = "MEDIUM"
        final_claim = "Graph connection failed before sign-in evidence could be collected."
        error = $_.Exception.Message
        evidence = [ordered]@{ graph = [ordered]@{ connected = $false; error = $_.Exception.Message } }
        metrics = [ordered]@{ poll_attempts = 0; max_poll_attempts = 0; polling_stopped_early = $false }
        cleanup = [ordered]@{ cleanup_required = $false; cleanup_completed = $true }
        recommendations = @("Confirm Microsoft Graph PowerShell is installed.", "Grant AuditLog.Read.All and Policy.Read.All.", "Rerun APP-DV-004 after Graph access is available.")
    }
    ConvertTo-ZTVPJsonFile -Object $report -Path $reportPath
    exit 0
}

$maxAttempts = [Math]::Max(1, [Math]::Ceiling(($WaitMinutes * 60) / [Math]::Max(1, $PollSeconds)))
$matched = $null
$allCandidates = @()
$apiErrors = @()
$stoppedEarly = $false

$appNeedles = switch ($targetApp) {
    "SharePoint Online" { @("sharepoint", "office 365 sharepoint online") }
    "Office 365" { @("office 365", "microsoft 365", "sharepoint", "exchange", "office") }
    "Exchange Online" { @("exchange", "office 365 exchange online") }
    "Azure portal" { @("azure portal", "windows azure service management api", "microsoft azure management") }
    default { @($targetApp) }
}

for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    try {
        $filterUser = $testUser.Replace("'", "''")
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=50&`$filter=userPrincipalName eq '$filterUser' and createdDateTime ge $validationStartUtc&`$orderby=createdDateTime desc"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $rows = @($response.value)

        foreach ($row in $rows) {
            $appDisplayName = [string](Get-ZTVPValue $row "appDisplayName")
            $resourceDisplayName = [string](Get-ZTVPValue $row "resourceDisplayName")
            $combinedApp = "$appDisplayName $resourceDisplayName"
            if (-not (Test-ZTVPTextAny -Text $combinedApp -Needles $appNeedles)) { continue }

            $caStatus = [string](Get-ZTVPValue $row "conditionalAccessStatus")
            $statusObj = Get-ZTVPValue $row "status"
            $errorCode = [string](Get-ZTVPValue $statusObj "errorCode")
            $failureReason = [string](Get-ZTVPValue $statusObj "failureReason")
            $device = Get-ZTVPValue $row "deviceDetail"
            $isCompliant = Get-ZTVPValue $device "isCompliant"
            $isManaged = Get-ZTVPValue $device "isManaged"
            $trustType = [string](Get-ZTVPValue $device "trustType")
            $policies = @((Get-ZTVPValue $row "appliedConditionalAccessPolicies"))

            $blockedPolicy = $null
            $expectedPolicyMatched = $false
            foreach ($policy in $policies) {
                $policyName = [string](Get-ZTVPValue $policy "displayName")
                $policyResult = [string](Get-ZTVPValue $policy "result")
                if (-not [string]::IsNullOrWhiteSpace($expectedPolicy) -and $policyName -eq $expectedPolicy) {
                    $expectedPolicyMatched = $true
                }
                if (Test-ZTVPTextAny -Text $policyResult -Needles @("failure", "block", "failed")) {
                    if ($null -eq $blockedPolicy) { $blockedPolicy = $policy }
                }
            }

            $accessBlocked = (
                $caStatus -eq "failure" -or
                $errorCode -notin @("", "0") -or
                (Test-ZTVPTextAny -Text $failureReason -Needles @("conditional access", "device", "compliant", "grant controls", "access has been blocked"))
            )
            $accessSucceeded = ($errorCode -in @("", "0") -and $caStatus -in @("success", "notApplied", ""))
            $deviceUnmanaged = (
                $isCompliant -eq $false -or
                $isManaged -eq $false -or
                [string]::IsNullOrWhiteSpace($trustType) -or
                $trustType -eq "None"
            )
            $caEvidenceFound = ($policies.Count -gt 0 -and ($blockedPolicy -ne $null -or $caStatus -eq "failure" -or ($expectedPolicyMatched -and $accessBlocked)))

            $candidate = [ordered]@{
                id = [string](Get-ZTVPValue $row "id")
                createdDateTime = [string](Get-ZTVPValue $row "createdDateTime")
                userPrincipalName = [string](Get-ZTVPValue $row "userPrincipalName")
                appDisplayName = $appDisplayName
                resourceDisplayName = $resourceDisplayName
                conditionalAccessStatus = $caStatus
                errorCode = $errorCode
                failureReason = $failureReason
                access_blocked = [bool]$accessBlocked
                access_succeeded = [bool]$accessSucceeded
                ca_evidence_found = [bool]$caEvidenceFound
                expected_policy_matched = [bool]$expectedPolicyMatched
                blocked_policy_name = if ($blockedPolicy) { [string](Get-ZTVPValue $blockedPolicy "displayName") } else { "" }
                device_unmanaged_or_noncompliant = [bool]$deviceUnmanaged
                device_detail = $device
                applied_conditional_access_policies = $policies
                raw = $row
            }
            $allCandidates += $candidate

            if ($expectedPolicy -and $expectedPolicyMatched) {
                $matched = $candidate
                break
            }
            if (-not $matched -and $caEvidenceFound) {
                $matched = $candidate
            }
            elseif (-not $matched) {
                $matched = $candidate
            }
        }

        if ($matched -and (($matched.ca_evidence_found -and $matched.access_blocked) -or $matched.access_succeeded)) {
            $stoppedEarly = $true
            break
        }
    }
    catch {
        $apiErrors += $_.Exception.Message
        if ($_.Exception.Message -match "Authentication_RequestFromUnsupportedUserRole|Authorization_RequestDenied|Forbidden|Insufficient privileges|403") {
            break
        }
    }

    if ($attempt -lt $maxAttempts) {
        Start-Sleep -Seconds ([Math]::Max(1, $PollSeconds))
    }
}

$completedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$status = "PARTIAL_SIGNIN_EVIDENCE_NOT_FOUND"
$risk = "MEDIUM"
$finalClaim = "No matching sign-in attempt was found during the monitoring window."
$accessResult = "unknown"

if ($apiErrors.Count -gt 0 -and -not $matched) {
    $status = "UNSUPPORTED_SIGNIN_LOGS_NOT_ACCESSIBLE"
    $risk = "MEDIUM"
    $finalClaim = "ZTVP could not access Entra sign-in logs or Conditional Access evidence."
}
elseif ($matched) {
    if ($matched.access_blocked -and $matched.ca_evidence_found -and $matched.device_unmanaged_or_noncompliant) {
        $status = "PASS_CA_BLOCKED_UNMANAGED_DEVICE"
        $risk = "LOW"
        $accessResult = "blocked"
        $finalClaim = "Conditional Access blocked the selected sensitive app from the unmanaged or non-compliant device context."
    }
    elseif ($matched.access_succeeded) {
        $status = "FAIL_SENSITIVE_APP_ACCESS_SUCCEEDED"
        $risk = "HIGH"
        $accessResult = "success"
        $finalClaim = "The test user accessed the sensitive app successfully and no matching Conditional Access block was found."
    }
    else {
        $status = "PARTIAL_CA_OR_DEVICE_EVIDENCE_UNCLEAR"
        $risk = "MEDIUM"
        $accessResult = if ($matched.access_blocked) { "blocked" } elseif ($matched.access_succeeded) { "success" } else { "unknown" }
        $finalClaim = "A matching sign-in was found, but Conditional Access or device compliance evidence was incomplete or unclear."
    }
}

$report = [ordered]@{
    scenario_id = "APP-DV-004"
    display_id = "APP-DV-004"
    scenario_name = "Sensitive App Access From Unmanaged Device Probe"
    pillar = "Applications"
    scope = "Cloud"
    run_id = $runId
    tenant_id = $ctx.TenantId
    tenant = $ctx.TenantId
    test_user = $testUser
    target_app = $targetApp
    target_app_url = $targetUrl
    expected_policy_name = $expectedPolicy
    started_utc = $validationStartUtc
    completed_utc = $completedUtc
    status = $status
    risk = $risk
    final_claim = $finalClaim
    control_tested = "Conditional Access should block sensitive application access from unmanaged or non-compliant devices."
    test_method = "Operator manually attempted access from Windows Sandbox or another unmanaged/non-compliant endpoint, then ZTVP queried Entra sign-in logs."
    evidence = [ordered]@{
        source = "Microsoft Graph signIns / Entra sign-in logs"
        access_result = $accessResult
        matched_signin = $matched
        candidates = @($allCandidates)
        api_errors = @($apiErrors)
    }
    appdv004_evidence = [ordered]@{
        signin_found = ($null -ne $matched)
        access_result = $accessResult
        ca_evidence_found = if ($matched) { [bool]$matched.ca_evidence_found } else { $false }
        applied_policy_name = if ($matched) { [string]$matched.blocked_policy_name } else { "" }
        device_unmanaged_or_noncompliant = if ($matched) { [bool]$matched.device_unmanaged_or_noncompliant } else { $false }
        conditional_access_status = if ($matched) { [string]$matched.conditionalAccessStatus } else { "" }
        failure_reason = if ($matched) { [string]$matched.failureReason } else { "" }
        signin_timestamp = if ($matched) { [string]$matched.createdDateTime } else { "" }
    }
    metrics = [ordered]@{
        poll_attempts = [Math]::Min($attempt, $maxAttempts)
        max_poll_attempts = $maxAttempts
        polling_stopped_early = $stoppedEarly
        tenant_evidence_found = ($null -ne $matched)
        ca_evidence_found = if ($matched) { [bool]$matched.ca_evidence_found } else { $false }
    }
    cleanup = [ordered]@{
        cleanup_required = $false
        cleanup_completed = $true
    }
    recommendations = @(
        "Create or fix a Conditional Access policy for sensitive apps.",
        "Scope it first to a test group.",
        "Require device to be marked as compliant or block unmanaged devices.",
        "Exclude break-glass accounts.",
        "Use report-only mode before enforcing broadly.",
        "Verify Intune compliance integration.",
        "Rerun APP-DV-004 from Windows Sandbox."
    )
}

ConvertTo-ZTVPJsonFile -Object $report -Path $reportPath
Write-Host "APP-DV-004 report written: $reportPath"
Write-Host "APP-DV-004 status: $status"
