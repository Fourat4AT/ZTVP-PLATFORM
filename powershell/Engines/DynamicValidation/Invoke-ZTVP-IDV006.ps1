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

function ConvertTo-ZTVPJsonFile {
    param($Object, [string]$Path)
    $Object | ConvertTo-Json -Depth 80 | Set-Content -Path $Path -Encoding UTF8
}

function Test-ZTVPRisky {
    param([string]$DuringSignIn, [string]$Aggregated, [string]$RiskState)
    $riskyLevels = @("low", "medium", "high")
    $d = ("" + $DuringSignIn).ToLowerInvariant()
    $a = ("" + $Aggregated).ToLowerInvariant()
    $s = ("" + $RiskState).ToLowerInvariant()
    if ($riskyLevels -contains $d) { return $true }
    if ($riskyLevels -contains $a) { return $true }
    if ($s -in @("atrisk", "confirmedcompromised")) { return $true }
    return $false
}

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "ID-DV-006"
$statePath = Join-Path $scenarioDir "idv006-state.json"
$reportPath = Join-Path $reportRoot "ID-DV-006-result.json"
New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null

if (-not (Test-Path $statePath)) {
    throw "ID-DV-006 state file not found. Run Step 1 Prepare and Start evidence window first."
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json
$runId = [string]$state.run_id
$decoyUpn = [string]$state.decoy_user.user_principal_name
$evidenceStartUtc = [string]$state.evidence_start_utc

# Window start = EvidenceStartUtc minus 5 minutes (fallback to now - WaitMinutes - 5m).
try {
    if ([string]::IsNullOrWhiteSpace($evidenceStartUtc)) {
        $windowStartDt = (Get-Date).ToUniversalTime().AddMinutes(-1 * ($WaitMinutes + 5))
    }
    else {
        $windowStartDt = ([datetime]$evidenceStartUtc).ToUniversalTime().AddMinutes(-5)
    }
}
catch {
    $windowStartDt = (Get-Date).ToUniversalTime().AddMinutes(-1 * ($WaitMinutes + 5))
}
$windowStart = $windowStartDt.ToString("yyyy-MM-ddTHH:mm:ssZ")

$requiredScopes = @("AuditLog.Read.All", "Policy.Read.All", "Directory.Read.All")
try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $ctx = Get-MgContext
    $needScopes = $false
    if (-not $ctx) { $needScopes = $true }
    else {
        $current = @()
        if ($ctx.Scopes) { $current = @($ctx.Scopes | ForEach-Object { $_.ToLower() }) }
        foreach ($s in $requiredScopes) { if ($current -notcontains $s.ToLower()) { $needScopes = $true } }
    }
    if ($needScopes) {
        Connect-MgGraph -Scopes $requiredScopes -ContextScope CurrentUser -NoWelcome | Out-Null
        $ctx = Get-MgContext
    }
}
catch {
    $report = [ordered]@{
        scenario_id = "ID-DV-006"; display_id = "ID-DV-006"
        scenario_name = "Sign-in Risk Conditional Access Validation"
        pillar = "Identity"; scope = "Cloud"; run_id = $runId
        expected_decoy_user = $decoyUpn
        started_utc = $windowStart
        completed_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        status = "ERROR_GRAPH_CONNECTION_FAILED"; risk = "MEDIUM"
        final_claim = "Graph connection failed before evidence could be collected."
        error = $_.Exception.Message
        metrics = [ordered]@{ poll_attempts = 0; max_poll_attempts = 0; tenant_evidence_found = $false }
        recommendations = @("Grant AuditLog.Read.All and Policy.Read.All.", "Rerun ID-DV-006 after Graph access is available.")
    }
    ConvertTo-ZTVPJsonFile -Object $report -Path $reportPath
    exit 0
}

# ---- 1. Conditional Access policy existence check (no hard-coded names) ----
$policyEvidence = @()
$enabledRiskPolicies = @()
$policyApiError = $null
try {
    $resp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$top=200"
    foreach ($p in @($resp.value)) {
        $conditions = Get-ZTVPValue $p "conditions"
        $signInRisk = @(Get-ZTVPValue $conditions "signInRiskLevels")
        if ($signInRisk.Count -eq 0) { continue }
        $grant = Get-ZTVPValue $p "grantControls"
        $builtIn = @(Get-ZTVPValue $grant "builtInControls")
        $authStrength = Get-ZTVPValue $grant "authenticationStrength"
        $pState = [string](Get-ZTVPValue $p "state")
        $entry = [ordered]@{
            policy_name = [string](Get-ZTVPValue $p "displayName")
            state = $pState
            sign_in_risk_levels = $signInRisk
            grant_controls = $builtIn
            authentication_strength = if ($authStrength) { [string](Get-ZTVPValue $authStrength "displayName") } else { $null }
        }
        $policyEvidence += $entry
        if ($pState -eq "enabled") { $enabledRiskPolicies += $entry }
    }
}
catch {
    $policyApiError = $_.Exception.Message
}

$completedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# If no ENABLED sign-in-risk CA policy exists -> FAIL/HIGH, finish early.
if ($enabledRiskPolicies.Count -eq 0 -and -not $policyApiError) {
    $report = [ordered]@{
        scenario_id = "ID-DV-006"; display_id = "ID-DV-006"
        scenario_name = "Sign-in Risk Conditional Access Validation"
        pillar = "Identity"; scope = "Cloud"
        mode = "Active run - sign-in risk + Conditional Access evidence"
        run_id = $runId; tenant_id = $ctx.TenantId; tenant = $ctx.TenantId
        expected_decoy_user = $decoyUpn
        evidence_start_utc = $evidenceStartUtc; window_start_utc = $windowStart
        started_utc = $windowStart; completed_utc = $completedUtc
        status = "FAIL_NO_SIGNIN_RISK_POLICY"; risk = "HIGH"
        risk_detected = $false
        executive_summary = "No enabled Conditional Access policy targeting sign-in risk was found in the tenant."
        final_claim = "No enabled Conditional Access policy targeting sign-in risk was found. The tenant does not have a confirmed CA response for this risk scenario."
        control_tested = "An enabled Conditional Access policy should respond to risky sign-ins with Block or an MFA/strong-authentication challenge."
        test_method = "ZTVP queried Conditional Access policies for enabled policies targeting sign-in risk."
        ca_action = "None"
        policy_found = $false
        conditional_access_policy_evidence = @($policyEvidence)
        sign_in_risk_evidence = [ordered]@{ matching_sign_in_found = $false; risk_detected = $false; all_events = @() }
        metrics = [ordered]@{ poll_attempts = 0; max_poll_attempts = 0; polling_stopped_early = $true; tenant_evidence_found = $false; enabled_sign_in_risk_policy_found = $false }
        cleanup = [ordered]@{ cleanup_required = $true; cleanup_completed = $false }
        recommendations = @(
            "Create an enabled Conditional Access policy that targets sign-in risk (low/medium/high).",
            "Apply Block or require MFA / a strong authentication strength for risky sign-ins.",
            "Scope it to a test group first and use report-only before enforcing broadly.",
            "Re-run ID-DV-006 after the policy is enabled to validate enforcement."
        )
    }
    ConvertTo-ZTVPJsonFile -Object $report -Path $reportPath
    Write-Host "ID-DV-006 status: FAIL_NO_SIGNIN_RISK_POLICY (no enabled sign-in risk CA policy)"
    exit 0
}

# ---- 2. Poll Entra sign-in logs for the decoy's risky sign-in ----
$maxAttempts = [Math]::Max(1, [Math]::Ceiling(($WaitMinutes * 60) / [Math]::Max(1, $PollSeconds)))
$allEvents = @()
$matched = $null
$failedAttemptsFound = $false
$apiErrors = @()
$stoppedEarly = $false
$attempt = 0

for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    try {
        $filterUpn = $decoyUpn.Replace("'", "''")
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=100&`$filter=userPrincipalName eq '$filterUpn' and createdDateTime ge $windowStart&`$orderby=createdDateTime desc"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $rows = @($response.value)

        $allEvents = @()
        foreach ($row in $rows) {
            $statusObj = Get-ZTVPValue $row "status"
            $errorCode = [int]("0" + ([string](Get-ZTVPValue $statusObj "errorCode")))
            $caStatus = [string](Get-ZTVPValue $row "conditionalAccessStatus")
            $duringSignIn = [string](Get-ZTVPValue $row "riskLevelDuringSignIn")
            $aggregated = [string](Get-ZTVPValue $row "riskLevelAggregated")
            $riskState = [string](Get-ZTVPValue $row "riskState")
            $riskDetail = [string](Get-ZTVPValue $row "riskDetail")
            $policies = @(Get-ZTVPValue $row "appliedConditionalAccessPolicies")
            $loc = Get-ZTVPValue $row "location"
            $locText = if ($loc) { (("" + (Get-ZTVPValue $loc "city")) + " " + ("" + (Get-ZTVPValue $loc "countryOrRegion"))).Trim() } else { "" }

            $isRisky = Test-ZTVPRisky -DuringSignIn $duringSignIn -Aggregated $aggregated -RiskState $riskState

            # CA response classification
            $caBlock = $false; $caMfa = $false; $caStrong = $false
            foreach ($pol in $policies) {
                $polResult = ("" + (Get-ZTVPValue $pol "result")).ToLowerInvariant()
                $enforced = @(Get-ZTVPValue $pol "enforcedGrantControls")
                $enforcedText = (($enforced | ForEach-Object { "" + $_ }) -join ",").ToLowerInvariant()
                if ($polResult -in @("failure", "block", "blocked") -and $enforcedText -match "block") { $caBlock = $true }
                if ($polResult -in @("success", "notapplied") -or $polResult -eq "reportonlysuccess") {
                    if ($enforcedText -match "mfa|multifactor") { $caMfa = $true }
                    if ($enforcedText -match "strength|strongauth") { $caStrong = $true }
                }
            }
            if ($caStatus -eq "failure") { $caBlock = $true }
            if (@(50074, 50076, 50079, 53004) -contains $errorCode) { $caMfa = $true }
            if ($errorCode -eq 53003) { $caBlock = $true }

            $accessSucceeded = ($errorCode -eq 0 -and ($caStatus -in @("success", "notApplied", "")))
            if (@(50126, 50053, 50055) -contains $errorCode) { $failedAttemptsFound = $true }

            $caAction = if ($caBlock) { "Block" } elseif ($caStrong) { "Strong auth" } elseif ($caMfa) { "MFA" } else { "None" }

            $appliedPolicyName = ""
            foreach ($pol in $policies) {
                $r = ("" + (Get-ZTVPValue $pol "result")).ToLowerInvariant()
                if ($r -in @("failure", "success")) { $appliedPolicyName = [string](Get-ZTVPValue $pol "displayName"); break }
            }

            $event = [ordered]@{
                createdDateTime = [string](Get-ZTVPValue $row "createdDateTime")
                userPrincipalName = [string](Get-ZTVPValue $row "userPrincipalName")
                appDisplayName = [string](Get-ZTVPValue $row "appDisplayName")
                resourceDisplayName = [string](Get-ZTVPValue $row "resourceDisplayName")
                errorCode = $errorCode
                failureReason = [string](Get-ZTVPValue $statusObj "failureReason")
                conditionalAccessStatus = $caStatus
                riskLevelDuringSignIn = $duringSignIn
                riskLevelAggregated = $aggregated
                riskState = $riskState
                riskDetail = $riskDetail
                ipAddress = [string](Get-ZTVPValue $row "ipAddress")
                location = $locText
                requestId = [string](Get-ZTVPValue $row "id")
                is_risky = $isRisky
                access_succeeded = $accessSucceeded
                ca_action = $caAction
                ca_block = $caBlock
                ca_mfa = $caMfa
                ca_strong = $caStrong
                applied_policy_name = $appliedPolicyName
                applied_conditional_access_policies = $policies
            }
            $allEvents += $event

            # Prefer a risky event with a decisive CA outcome.
            if ($isRisky) {
                if ($caBlock -or $caMfa -or $caStrong -or $accessSucceeded) {
                    $matched = $event
                }
                elseif (-not $matched) {
                    $matched = $event
                }
            }
            elseif (-not $matched) {
                $matched = $event
            }
        }

        # Decisive early-exit: risky + clear CA outcome (block/mfa/strong/allowed).
        if ($matched -and $matched.is_risky -and ($matched.ca_block -or $matched.ca_mfa -or $matched.ca_strong -or $matched.access_succeeded)) {
            $stoppedEarly = $true
            break
        }
    }
    catch {
        $apiErrors += $_.Exception.Message
        if ($_.Exception.Message -match "Authorization_RequestDenied|Forbidden|Insufficient privileges|403") { break }
    }

    if ($attempt -lt $maxAttempts) {
        Start-Sleep -Seconds ([Math]::Max(1, $PollSeconds))
    }
}

$completedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# ---- 3. Verdict ----
$riskDetected = ($matched -ne $null -and $matched.is_risky)
$caAction = if ($matched) { [string]$matched.ca_action } else { "None" }

$status = "PARTIAL_NO_RISK_SIGNIN_EVIDENCE"
$risk = "MEDIUM"
$summary = "No matching decoy sign-in evidence was found before the selected timeout."
$finalClaim = "Risk trigger attempts or sign-in evidence were found, but Entra did not produce enough tenant evidence to prove enforcement."

if ($matched -and $matched.is_risky -and ($matched.ca_block)) {
    $status = "PASS_RISKY_SIGNIN_BLOCKED"; $risk = "LOW"
    $summary = "A risky sign-in was detected and Conditional Access blocked access."
    $finalClaim = "Tenant evidence shows the risky sign-in was blocked by Conditional Access."
}
elseif ($matched -and $matched.is_risky -and ($matched.ca_mfa -or $matched.ca_strong)) {
    $status = "PASS_RISKY_SIGNIN_CHALLENGED"; $risk = "LOW"
    $summary = "A risky sign-in was detected and Conditional Access required MFA or strong authentication."
    $finalClaim = "Tenant evidence shows the risky sign-in was challenged with MFA or strong authentication by Conditional Access."
}
elseif ($matched -and $matched.is_risky -and $matched.access_succeeded) {
    $status = "FAIL_RISKY_SIGNIN_ALLOWED"; $risk = "HIGH"
    $summary = "A risky sign-in was detected but access succeeded with no block or authentication challenge."
    $finalClaim = "Tenant evidence shows the risky sign-in succeeded without a block or authentication challenge."
}
elseif ($failedAttemptsFound -and -not $riskDetected) {
    $status = "PARTIAL_NOT_CLASSIFIED_RISKY"; $risk = "MEDIUM"
    $summary = "Failed sign-in attempts were found, but Entra did not classify the sign-in as risky."
    $finalClaim = "Risk trigger attempts or sign-in evidence were found, but Entra did not produce enough tenant evidence to prove enforcement."
}
elseif ($matched) {
    $status = "PARTIAL_CA_RESPONSE_UNCLEAR"; $risk = "MEDIUM"
    $summary = "A matching sign-in was found, but the Conditional Access response could not be clearly attributed."
    $finalClaim = "Risk trigger attempts or sign-in evidence were found, but Entra did not produce enough tenant evidence to prove enforcement."
}

$report = [ordered]@{
    scenario_id = "ID-DV-006"; display_id = "ID-DV-006"
    scenario_name = "Sign-in Risk Conditional Access Validation"
    pillar = "Identity"; scope = "Cloud"
    mode = "Active run - sign-in risk + Conditional Access evidence"
    run_id = $runId; tenant_id = $ctx.TenantId; tenant = $ctx.TenantId
    expected_decoy_user = $decoyUpn
    evidence_start_utc = $evidenceStartUtc; window_start_utc = $windowStart
    started_utc = $windowStart; completed_utc = $completedUtc
    status = $status; risk = $risk
    risk_detected = $riskDetected
    executive_summary = $summary
    final_claim = $finalClaim
    control_tested = "An enabled Conditional Access policy should respond to risky sign-ins with Block or an MFA/strong-authentication challenge."
    test_method = "The decoy signs in with risky behavior (TOR/VPN/unusual location and/or repeated wrong passwords); ZTVP polls Entra sign-in logs and Conditional Access policies for the enforcement result."
    ca_action = $caAction
    policy_found = ($enabledRiskPolicies.Count -gt 0)
    applied_policy_name = if ($matched) { [string]$matched.applied_policy_name } else { "" }
    conditional_access_policy_evidence = @($policyEvidence)
    sign_in_risk_evidence = [ordered]@{
        evidence_source = "Microsoft Entra sign-in logs (auditLogs/signIns)"
        matching_sign_in_found = ($matched -ne $null)
        risk_detected = $riskDetected
        selected_event = $matched
        all_events = @($allEvents)
        event_count = @($allEvents).Count
        failed_attempts_found = $failedAttemptsFound
        api_errors = @($apiErrors)
    }
    metrics = [ordered]@{
        poll_attempts = [Math]::Min($attempt, $maxAttempts)
        max_poll_attempts = $maxAttempts
        polling_stopped_early = $stoppedEarly
        tenant_evidence_found = ($matched -ne $null)
        enabled_sign_in_risk_policy_found = ($enabledRiskPolicies.Count -gt 0)
        risk_detected = $riskDetected
    }
    cleanup = [ordered]@{ cleanup_required = $true; cleanup_completed = $false }
    recommendations = @(
        "Ensure an enabled Conditional Access policy targets sign-in risk and enforces Block or MFA/strong authentication.",
        "Validate the policy is enforced (not report-only) for the targeted users.",
        "Generate a real risky sign-in (TOR/VPN/unusual location, repeated wrong passwords) to confirm enforcement.",
        "Review Identity Protection risk detections for the decoy user.",
        "Run cleanup to delete the ID-DV-006 decoy user."
    )
}

ConvertTo-ZTVPJsonFile -Object $report -Path $reportPath
Write-Host "ID-DV-006 report written: $reportPath"
Write-Host "ID-DV-006 status: $status (risk_detected=$riskDetected, ca_action=$caAction, polls $attempt/$maxAttempts)"
