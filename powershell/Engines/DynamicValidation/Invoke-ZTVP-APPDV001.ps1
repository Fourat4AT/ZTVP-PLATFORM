param(
    [int]$MaxPollSeconds = 150,
    [int]$PollIntervalSeconds = 10
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# Reading Entra sign-in logs is the authoritative, ambiguity-proof evidence for
# enterprise app assignment enforcement. AADSTS50105 (not assigned) is logged
# during authorization, before any MFA challenge, so it is captured cleanly even
# when the browser shows an interstitial error page that never redirects back.
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

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "APP-DV-001"
$statePath = Join-Path $scenarioDir "appdv001-state.json"
$reportPath = Join-Path $reportRoot "APP-DV-001-result.json"

if (-not (Test-Path $statePath)) {
    throw "No APP-DV-001 state file found. Run Step 1 Prepare Decoy first."
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json
$decoyUpn = [string]$state.decoy_user.user_principal_name
$decoyId = [string]$state.decoy_user.id
$runId = [string]$state.run_id
$tenantId = [string]$state.tenant_id
$targetAppId = [string]$state.target_app.app_id
$targetAppName = [string]$state.target_app.display_name

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

Write-Host ""
Write-Host "APP-DV-001 sign-in evidence collection"
Write-Host "Reading as: $($ctx.Account)"
Write-Host "Looking for decoy sign-ins to controlled app: $targetAppName ($targetAppId)"
Write-Host ""

# Poll the sign-in logs because ingestion can lag a few minutes.
$signInFilter = "appId eq '$targetAppId' and userId eq '$decoyId'"
$uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$signInFilter&`$top=25"

$events = @()
$elapsed = 0

while ($elapsed -le $MaxPollSeconds) {
    try {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
        $events = @($resp.value)
    }
    catch {
        Write-Host "Sign-in log query attempt failed: $($_.Exception.Message)"
        $events = @()
    }

    if ($events.Count -gt 0) {
        break
    }

    if ($elapsed -lt $MaxPollSeconds) {
        Write-Host "No sign-in evidence yet. Waiting $PollIntervalSeconds s (elapsed $elapsed s)..."
        Start-Sleep -Seconds $PollIntervalSeconds
    }
    $elapsed += $PollIntervalSeconds
}

$latest = $null
if ($events.Count -gt 0) {
    $latest = $events | Sort-Object createdDateTime -Descending | Select-Object -First 1
}

$errorCode = $null
$failureReason = $null
$resourceDisplayName = $null
$caStatus = $null
$signInTime = $null
$accessGranted = $false
$assignmentBlocked = $false
$warnings = @()

if ($latest) {
    $errorCode = [int]$latest.status.errorCode
    $failureReason = [string]$latest.status.failureReason
    $resourceDisplayName = [string]$latest.resourceDisplayName
    $caStatus = [string]$latest.conditionalAccessStatus
    $signInTime = [string]$latest.createdDateTime
    $accessGranted = ($errorCode -eq 0)
    $assignmentBlocked = ($errorCode -eq 50105)
}

# Classify from the authoritative sign-in log error code.
$status = "PARTIAL_NO_SIGNIN"
$risk = "MEDIUM"
$summary = "No decoy sign-in to the controlled enterprise app was found in the Entra sign-in logs yet."
$finalClaim = "Sign in once as the decoy user to the controlled app (Step 2 trigger), then rerun evidence collection."
$evidenceQuality = "Inconclusive - no sign-in event recorded."

if ($null -ne $errorCode) {
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
        # MFA was required and not completed. In tenants with Security Defaults or an
        # MFA Conditional Access policy, MFA is evaluated before the app assignment
        # check, so the assignment result (50105 vs success) cannot be observed until
        # the decoy completes MFA. This is inconclusive for assignment enforcement,
        # NOT a failure of it.
        $status = "PARTIAL_MFA_BEFORE_ASSIGNMENT"
        $risk = "MEDIUM"
        $summary = "The decoy sign-in was interrupted by MFA (error $errorCode) before the assignment requirement could be evaluated. MFA is enforced ahead of the assignment check in this tenant."
        $finalClaim = "Complete the decoy MFA during the sign-in so Entra reaches the assignment decision, then collect evidence again to get a definitive PASS or FAIL."
        $evidenceQuality = "Partial - MFA gated the sign-in (error $errorCode) before assignment enforcement could be observed."
        $warnings += "MFA (Security Defaults or Conditional Access) interrupted the sign-in before the assignment check. Complete MFA as the decoy to obtain a definitive assignment verdict."
    }
    elseif (@(53003, 53000, 53001, 530031) -contains $errorCode) {
        $status = "PARTIAL_BLOCKED_BY_CONDITIONAL_ACCESS"
        $risk = "MEDIUM"
        $summary = "The decoy sign-in was blocked by Conditional Access (error $errorCode), not by the enterprise app assignment requirement."
        $finalClaim = "Conditional Access blocked the sign-in before the assignment check. Adjust the test conditions to isolate assignment enforcement."
        $evidenceQuality = "Partial - Conditional Access blocked the sign-in (error $errorCode) before assignment enforcement could be observed."
        $warnings += "Conditional Access blocked the sign-in before the assignment check could be evaluated."
    }
    else {
        $status = "PARTIAL_SIGN_IN_INCONCLUSIVE"
        $risk = "MEDIUM"
        $summary = "A decoy sign-in was found but returned an error code that does not map cleanly to assignment enforcement (error $errorCode)."
        $finalClaim = "Review the sign-in error and Conditional Access result to interpret this outcome."
        $evidenceQuality = "Partial - ambiguous sign-in error code $errorCode."
        $warnings += "Unmapped sign-in error code $errorCode ($failureReason)."
    }
}

$usedDecoy = $false
if ($latest) {
    $usedDecoy = ([string]$latest.userPrincipalName).ToLower() -eq $decoyUpn.ToLower()
}

# Persist the probe outcome back to state.
$state.assignment_probe.attempted = $true
$state.assignment_probe.access_granted = $accessGranted
$state.assignment_probe.assignment_required_blocked = $assignmentBlocked
$state.assignment_probe.connected_account = $decoyUpn
$state.assignment_probe.error_message = $failureReason
Write-ZTVPJson -Path $statePath -Object $state

$result = [PSCustomObject]@{
    scenario_id = "APP-DV-001"
    display_id = "APP-DV-001"
    scenario_name = "Enterprise App Assignment Enforcement Probe"
    pillar = "Applications"
    scope = "Cloud"
    mode = "Three-Step Managed Decoy Enterprise App Sign-in"
    run_id = $runId
    generated_at = (Get-Date).ToString("s")

    tenant_id = $tenantId
    expected_decoy_user = $decoyUpn
    connected_probe_account = $decoyUpn
    target_app = $targetAppName

    status = $status
    risk = $risk
    executive_summary = $summary
    final_claim = $finalClaim
    evidence_quality = $evidenceQuality
    warnings = @($warnings)

    decoy_user = [PSCustomObject]@{
        id = $state.decoy_user.id
        user_principal_name = $state.decoy_user.user_principal_name
        display_name = $state.decoy_user.display_name
        assigned_to_app = $false
        password_stored_in_report = $false
        created_by_ztvp = $true
    }

    assignment_enforcement_evidence = [PSCustomObject]@{
        evidence_source = "Microsoft Entra sign-in logs (auditLogs/signIns)"
        actual_sign_in_attempt_performed = [bool]$latest
        target_app_id = $targetAppId
        target_app_display_name = $targetAppName
        app_role_assignment_required = $true
        decoy_user_assigned = $false
        sign_in_time = $signInTime
        sign_in_error_code = $errorCode
        sign_in_failure_reason = $failureReason
        resource_signed_into = $resourceDisplayName
        conditional_access_status = $caStatus
        access_granted = $accessGranted
        assignment_required_blocked = $assignmentBlocked
    }

    cleanup = [PSCustomObject]@{
        app_cleanup_required = $true
        decoy_user_cleanup_required = $true
        state_file_active = $true
        actions = @()
        errors = @()
    }

    metrics = [PSCustomObject]@{
        probe_used_decoy_user = $usedDecoy
        actual_sign_in_attempt_performed = [bool]$latest
        sign_in_error_code = $errorCode
        access_granted = $accessGranted
        assignment_required_blocked = $assignmentBlocked
        app_role_assignment_required = $true
    }

    recommendations = @(
        "Require user assignment on sensitive enterprise applications (appRoleAssignmentRequired).",
        "Grant access only through controlled groups or approved app role assignments.",
        "Review existing enterprise apps that do not require assignment.",
        "Monitor Entra sign-in logs for unassigned access attempts (error code 50105).",
        "Run cleanup to delete the APP-DV-001 decoy user and controlled app."
    )

    limitations = @(
        "This validation requires the operator to perform one controlled decoy sign-in to the controlled app during Step 2.",
        "The controlled enterprise app and decoy user are temporary and must be cleaned up.",
        "Assignment enforcement is validated against a ZTVP-controlled app, not a production app."
    )
}

Write-ZTVPJson -Path $reportPath -Object $result

Write-Host ""
Write-Host "APP-DV-001 evidence collection completed."
Write-Host "Status: $status"
Write-Host "Risk: $risk"
Write-Host "Sign-in error code: $errorCode"
Write-Host "Access granted: $accessGranted"
Write-Host "Assignment blocked: $assignmentBlocked"
Write-Host "Report: $reportPath"
Write-Host ""
