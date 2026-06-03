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

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "APP-DV-001"
$statePath = Join-Path $scenarioDir "appdv001-state.json"
$reportPath = Join-Path $reportRoot "APP-DV-001-result.json"
New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null

if (-not (Test-Path $statePath)) {
    throw "APP-DV-001 state file not found. Run Step 1 Prepare first."
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json
$runId = [string]$state.run_id
$decoyUpn = [string]$state.decoy_user.user_principal_name
$decoyId = [string]$state.decoy_user.id
$tenantIdState = [string]$state.tenant_id
$targetAppId = [string]$state.target_app.app_id
$targetAppName = [string]$state.target_app.display_name

if ([string]::IsNullOrWhiteSpace($targetAppId)) { throw "Target app id missing from state." }

$requiredScopes = @("AuditLog.Read.All", "Directory.Read.All")
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
        scenario_id = "APP-DV-001"
        display_id = "APP-DV-001"
        scenario_name = "Enterprise App Assignment Enforcement Probe"
        pillar = "Applications"
        scope = "Cloud"
        run_id = $runId
        tenant_id = $tenantIdState
        expected_decoy_user = $decoyUpn
        target_app = $targetAppName
        started_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        completed_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        status = "ERROR_GRAPH_CONNECTION_FAILED"
        risk = "MEDIUM"
        final_claim = "Graph connection failed before sign-in evidence could be collected."
        error = $_.Exception.Message
        sign_in_log_evidence = [ordered]@{ evidence_source = "Entra sign-in logs"; signin_found = $false; connected = $false; error = $_.Exception.Message }
        metrics = [ordered]@{ poll_attempts = 0; max_poll_attempts = 0; polling_stopped_early = $false; tenant_evidence_found = $false }
        recommendations = @("Confirm Microsoft Graph PowerShell is installed.", "Grant AuditLog.Read.All and Directory.Read.All.", "Rerun APP-DV-001 after Graph access is available.")
    }
    ConvertTo-ZTVPJsonFile -Object $report -Path $reportPath
    exit 0
}

$maxAttempts = [Math]::Max(1, [Math]::Ceiling(($WaitMinutes * 60) / [Math]::Max(1, $PollSeconds)))
$apiErrors = @()
$allEvents = @()
$definitive = $null            # 50105 (blocked) or 0 (success) event
$latestEvent = $null           # latest event of any kind, for partial fallback
$stoppedEarly = $false
$attempt = 0

for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    try {
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=50&`$filter=appId eq '$targetAppId'&`$orderby=createdDateTime desc"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $rows = @($response.value)

        foreach ($row in $rows) {
            $upn = [string](Get-ZTVPValue $row "userPrincipalName")
            $uid = [string](Get-ZTVPValue $row "userId")
            # Only consider the decoy user (the controlled app is unique to this scenario,
            # but match defensively in case other identities touched it).
            if (-not [string]::IsNullOrWhiteSpace($decoyId) -and $uid -ne $decoyId -and $upn.ToLower() -ne $decoyUpn.ToLower()) {
                continue
            }

            $statusObj = Get-ZTVPValue $row "status"
            $errorCode = [int]("0" + ([string](Get-ZTVPValue $statusObj "errorCode")))
            $failureReason = [string](Get-ZTVPValue $statusObj "failureReason")

            $event = [ordered]@{
                id = [string](Get-ZTVPValue $row "id")
                createdDateTime = [string](Get-ZTVPValue $row "createdDateTime")
                userPrincipalName = $upn
                appDisplayName = [string](Get-ZTVPValue $row "appDisplayName")
                resourceDisplayName = [string](Get-ZTVPValue $row "resourceDisplayName")
                conditionalAccessStatus = [string](Get-ZTVPValue $row "conditionalAccessStatus")
                errorCode = $errorCode
                failureReason = $failureReason
                clientAppUsed = [string](Get-ZTVPValue $row "clientAppUsed")
                ipAddress = [string](Get-ZTVPValue $row "ipAddress")
            }
            $allEvents += $event

            if ($null -eq $latestEvent) { $latestEvent = $event }

            if ($errorCode -eq 50105 -or $errorCode -eq 0) {
                if ($null -eq $definitive) { $definitive = $event }
            }
        }

        if ($null -ne $definitive) {
            $stoppedEarly = $true
            break
        }
    }
    catch {
        $apiErrors += $_.Exception.Message
        if ($_.Exception.Message -match "Authorization_RequestDenied|Forbidden|Insufficient privileges|403") {
            break
        }
    }

    if ($attempt -lt $maxAttempts) {
        Start-Sleep -Seconds ([Math]::Max(1, $PollSeconds))
    }
}

$selected = if ($definitive) { $definitive } else { $latestEvent }
$errorCode = if ($selected) { [int]$selected.errorCode } else { $null }

$accessGranted = ($errorCode -eq 0)
$assignmentBlocked = ($errorCode -eq 50105)

$status = "PARTIAL_NO_SIGNIN"
$risk = "MEDIUM"
$summary = "No decoy sign-in to the controlled enterprise app was found in the Entra sign-in logs during the monitoring window."
$finalClaim = "Sign in once as the decoy user to the controlled app (Step 2a), then let the active run collect the sign-in evidence."
$evidenceQuality = "Inconclusive - no sign-in event recorded yet."

if ($apiErrors.Count -gt 0 -and -not $selected) {
    $status = "UNSUPPORTED_SIGNIN_LOGS_NOT_ACCESSIBLE"
    $risk = "MEDIUM"
    $summary = "ZTVP could not read Entra sign-in logs to collect assignment-enforcement evidence."
    $finalClaim = "Grant AuditLog.Read.All and rerun the active run."
    $evidenceQuality = "Inconclusive - sign-in logs not accessible."
}
elseif ($null -ne $errorCode) {
    if ($errorCode -eq 50105) {
        $status = "PASS_UNASSIGNED_USER_BLOCKED"
        $risk = "LOW"
        $summary = "The unassigned decoy user was blocked from the assignment-required enterprise app (AADSTS50105)."
        $finalClaim = "Enterprise app assignment enforcement works: an unassigned user is denied access to the controlled app."
        $evidenceQuality = "Strong - Entra sign-in log recorded an assignment-required block (error 50105)."
    }
    elseif ($errorCode -eq 0) {
        $status = "FAIL_UNASSIGNED_USER_GRANTED_ACCESS"
        $risk = "HIGH"
        $summary = "The unassigned decoy user successfully signed in to the assignment-required enterprise app."
        $finalClaim = "Enterprise app assignment enforcement is not effective: an unassigned user accessed the controlled app."
        $evidenceQuality = "Strong - Entra sign-in log recorded a successful sign-in (error 0) for the unassigned decoy."
    }
    elseif (@(50076, 50074, 50072, 50079, 500121) -contains $errorCode) {
        $status = "PARTIAL_MFA_BEFORE_ASSIGNMENT"
        $risk = "MEDIUM"
        $summary = "The decoy sign-in was interrupted by MFA (error $errorCode) before the assignment requirement could be evaluated."
        $finalClaim = "Complete the decoy MFA during the sign-in so Entra reaches the assignment decision, then the active run will capture a definitive PASS or FAIL."
        $evidenceQuality = "Partial - MFA gated the sign-in (error $errorCode) before assignment enforcement could be observed."
    }
    elseif (@(53003, 53000, 53001, 530031) -contains $errorCode) {
        $status = "PARTIAL_BLOCKED_BY_CONDITIONAL_ACCESS"
        $risk = "MEDIUM"
        $summary = "The decoy sign-in was blocked by Conditional Access (error $errorCode), not by the enterprise app assignment requirement."
        $finalClaim = "Conditional Access blocked the sign-in before the assignment check could be evaluated."
        $evidenceQuality = "Partial - Conditional Access blocked the sign-in (error $errorCode) before assignment enforcement could be observed."
    }
    else {
        $status = "PARTIAL_SIGN_IN_INCONCLUSIVE"
        $risk = "MEDIUM"
        $summary = "A decoy sign-in was found but returned an error code that does not map cleanly to assignment enforcement (error $errorCode)."
        $finalClaim = "Review the sign-in error and Conditional Access result to interpret this outcome."
        $evidenceQuality = "Partial - ambiguous sign-in error code $errorCode."
    }
}

# Persist the probe outcome back to scenario state.
if ($null -ne $errorCode) {
    $state.assignment_probe.attempted = $true
    $state.assignment_probe.access_granted = $accessGranted
    $state.assignment_probe.assignment_required_blocked = $assignmentBlocked
    $state.assignment_probe.connected_account = $decoyUpn
    $state.assignment_probe.error_message = if ($selected) { [string]$selected.failureReason } else { $null }
    ConvertTo-ZTVPJsonFile -Object $state -Path $statePath
}

$completedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$report = [ordered]@{
    scenario_id = "APP-DV-001"
    display_id = "APP-DV-001"
    scenario_name = "Enterprise App Assignment Enforcement Probe"
    pillar = "Applications"
    scope = "Cloud"
    mode = "Active run - Entra sign-in log evidence polling"
    run_id = $runId
    tenant_id = $ctx.TenantId
    tenant = $ctx.TenantId
    expected_decoy_user = $decoyUpn
    connected_probe_account = $decoyUpn
    target_app = $targetAppName
    started_utc = $completedUtc
    completed_utc = $completedUtc

    status = $status
    risk = $risk
    executive_summary = $summary
    final_claim = $finalClaim
    evidence_quality = $evidenceQuality
    control_tested = "An enterprise application that requires user assignment must deny access to users who are not assigned."
    test_method = "The decoy user signs in to the controlled assignment-required app; ZTVP polls Entra sign-in logs for the authorization result (error code 50105 vs success)."
    warnings = @($apiErrors)

    decoy_user = [ordered]@{
        id = $state.decoy_user.id
        user_principal_name = $state.decoy_user.user_principal_name
        display_name = $state.decoy_user.display_name
        assigned_to_app = $false
        password_stored_in_report = $false
        created_by_ztvp = $true
    }

    assignment_enforcement_evidence = [ordered]@{
        evidence_source = "Microsoft Entra sign-in logs (auditLogs/signIns)"
        actual_sign_in_attempt_performed = ($null -ne $selected)
        target_app_id = $targetAppId
        target_app_display_name = $targetAppName
        app_role_assignment_required = $true
        decoy_user_assigned = $false
        sign_in_time = if ($selected) { [string]$selected.createdDateTime } else { $null }
        sign_in_error_code = $errorCode
        sign_in_failure_reason = if ($selected) { [string]$selected.failureReason } else { $null }
        resource_signed_into = if ($selected) { [string]$selected.resourceDisplayName } else { $null }
        conditional_access_status = if ($selected) { [string]$selected.conditionalAccessStatus } else { $null }
        access_granted = $accessGranted
        assignment_required_blocked = $assignmentBlocked
    }

    sign_in_log_evidence = [ordered]@{
        evidence_source = "Microsoft Entra sign-in logs (auditLogs/signIns)"
        signin_found = ($null -ne $selected)
        selected_event = $selected
        sign_in_error_code = $errorCode
        all_events = @($allEvents)
        event_count = @($allEvents).Count
        api_errors = @($apiErrors)
    }

    cleanup = [ordered]@{
        app_cleanup_required = $true
        decoy_user_cleanup_required = $true
        state_file_active = $true
        cleanup_required = $true
        cleanup_completed = $false
    }

    metrics = [ordered]@{
        probe_used_decoy_user = ($null -ne $selected)
        actual_sign_in_attempt_performed = ($null -ne $selected)
        sign_in_error_code = $errorCode
        access_granted = $accessGranted
        assignment_required_blocked = $assignmentBlocked
        app_role_assignment_required = $true
        tenant_evidence_found = ($null -ne $selected)
        poll_attempts = [Math]::Min($attempt, $maxAttempts)
        max_poll_attempts = $maxAttempts
        polling_stopped_early = $stoppedEarly
    }

    recommendations = @(
        "Require user assignment on sensitive enterprise applications (appRoleAssignmentRequired).",
        "Grant access only through controlled groups or approved app role assignments.",
        "Review existing enterprise apps that do not require assignment.",
        "Monitor Entra sign-in logs for unassigned access attempts (error code 50105).",
        "Run cleanup to delete the APP-DV-001 decoy user and controlled app."
    )

    limitations = @(
        "This validation requires one controlled decoy sign-in to the controlled app.",
        "If MFA (Security Defaults / Conditional Access) is enforced, the decoy must complete MFA before Entra reaches the assignment decision.",
        "The controlled enterprise app and decoy user are temporary and must be cleaned up."
    )
}

ConvertTo-ZTVPJsonFile -Object $report -Path $reportPath
Write-Host "APP-DV-001 report written: $reportPath"
Write-Host "APP-DV-001 status: $status (error code: $errorCode, polls: $attempt/$maxAttempts)"
