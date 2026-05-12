param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath
)

function H {
    param($Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Value.ToString())
}

function YN {
    param($Value)
    if ($Value -eq $true) { return "Yes" }
    return "No"
}

function Join-Values {
    param($Values)

    $items = @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if ($items.Count -eq 0) {
        return "None"
    }

    return (($items | ForEach-Object { H $_ }) -join "<br>")
}

function Metric {
    param(
        [string]$Label,
        $Value,
        [string]$Class = ""
    )

@"
<div class="metric $Class">
    <div class="metric-value">$(H $Value)</div>
    <div class="metric-label">$(H $Label)</div>
</div>
"@
}

function ActionCard {
    param(
        [string]$Title,
        [string]$Text,
        [string]$Class = ""
    )

@"
<div class="action $Class">
    <div class="action-title">$(H $Title)</div>
    <div class="action-text">$(H $Text)</div>
</div>
"@
}

function PolicyTable {
    param(
        [string]$Title,
        $Policies,
        [string]$Empty
    )

    $rows = ""

    foreach ($p in @($Policies | Where-Object { $null -ne $_ })) {
        $rows += @"
<tr>
    <td class="policy">$(H $p.name)</td>
    <td>$(H $p.state_label)</td>
    <td>$(H $p.risk_type)</td>
    <td>$(H $p.control_summary)</td>
    <td>$(Join-Values $p.user_risk_levels)</td>
    <td>$(Join-Values $p.sign_in_risk_levels)</td>
    <td>$(H (YN $p.has_exclusions))</td>
    <td>$(H $p.exclude_users_count)</td>
    <td>$(H $p.exclude_groups_count)</td>
    <td>$(H $p.exclude_roles_count)</td>
</tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='10' class='empty'>$(H $Empty)</td></tr>"
    }

@"
<section class="section">
    <h2>$Title</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Policy</th>
                    <th>State</th>
                    <th>Risk Type</th>
                    <th>Control</th>
                    <th>User Risk Levels</th>
                    <th>Sign-in Risk Levels</th>
                    <th>Has Exclusions</th>
                    <th>Excluded Users</th>
                    <th>Excluded Groups</th>
                    <th>Excluded Roles</th>
                </tr>
            </thead>
            <tbody>$rows</tbody>
        </table>
    </div>
</section>
"@
}

if (-not (Test-Path $JsonPath)) {
    throw "JSON report not found: $JsonPath"
}

$result = Get-Content $JsonPath -Raw | ConvertFrom-Json

if ($result.scenario_id -ne "ID1") {
    throw "This report converter is only for ID1. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$statusClass = "pass"
$decisionClass = "pass"
$decisionTitle = "Risk-based Conditional Access looks controlled."
$decisionText = "User risk and sign-in risk protections are enabled and enforcing."

if ($result.status -eq "PARTIAL") {
    $statusClass = "partial"
    $decisionClass = "partial"
    $decisionTitle = "Risk-based Conditional Access needs review."
    $decisionText = "Risk protection is enabled, but exclusions or report-only policies reduce confidence."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "fail"
    $decisionClass = "fail"
    $decisionTitle = "Risk-based Conditional Access enforcement gap detected."
    $decisionText = "User risk or sign-in risk protection is missing, report-only, or not enforcing the required controls."
}

$plainSummary = "This tenant has $($e.enabled_user_risk_policy_count) enabled user risk policy and $($e.enabled_sign_in_risk_policy_count) enabled sign-in risk policy. ID1 found $($e.risk_policy_count) risk-based Conditional Access policies, $($e.enabled_risk_policy_count) enabled risk policies, $($e.report_only_risk_policy_count) report-only risk policies, and $($e.enabled_risk_policy_with_exclusion_count) enabled risk policies with exclusions."

$targetState = "Target state: user risk should require secure password change or block access, sign-in risk should require MFA/authentication strength or block access, and exclusions should be minimal, documented, justified, approved, and monitored."

$metrics = ""
$metrics += Metric "Conditional Access Policies" $e.conditional_access_policy_count
$metrics += Metric "Risk-Based Policies" $e.risk_policy_count
$metrics += Metric "Enabled Risk Policies" $e.enabled_risk_policy_count
$metrics += Metric "Report-Only Risk Policies" $e.report_only_risk_policy_count "warn"
$metrics += Metric "Enabled User Risk Policies" $e.enabled_user_risk_policy_count
$metrics += Metric "Enabled Sign-in Risk Policies" $e.enabled_sign_in_risk_policy_count
$metrics += Metric "Risk Policies With Exclusions" $e.enabled_risk_policy_with_exclusion_count "warn"

$actions = ""

if ($e.enabled_user_risk_policy_count -eq 0) {
    $actions += ActionCard "1. Enable user risk protection" "Create or enable a user risk policy. High user risk should require secure password change or block access." "critical"
}
else {
    $actions += ActionCard "1. User risk protection is enabled" "Keep the user risk policy enforced and confirm its exclusions are justified." "info"
}

if ($e.enabled_sign_in_risk_policy_count -eq 0) {
    $actions += ActionCard "2. Enable sign-in risk protection" "Create or enable a sign-in risk policy. Risky sign-ins should require MFA/authentication strength or be blocked." "critical"
}
else {
    $actions += ActionCard "2. Sign-in risk protection is enabled" "Keep the sign-in risk policy enforced and confirm it targets the expected users and applications." "info"
}

if ($e.enabled_risk_policy_with_exclusion_count -gt 0) {
    $actions += ActionCard "3. Review risk policy exclusions" "Enabled risk policies contain exclusions. Confirm each excluded group, user, or role is required, documented, approved, and monitored." "warning"
}
else {
    $actions += ActionCard "3. Maintain minimal exclusions" "No enabled risk policy exclusions were detected. Keep exceptions tightly controlled." "info"
}

if ($e.report_only_risk_policy_count -gt 0) {
    $actions += ActionCard "4. Move report-only risk policies to enabled" "Report-only risk policies do not enforce protection. Review impact and move validated policies to enabled." "warning"
}
else {
    $actions += ActionCard "4. No report-only risk dependency" "No report-only risk policy dependency was detected." "info"
}

$actions += ActionCard "5. Continue with ID2 and ID3" "ID1 confirms policy enforcement. ID2 and ID3 should review risky users and risk detections." "info"

$findingsHtml = ""

foreach ($f in @($result.findings)) {
    $findingsHtml += @"
<div class="finding">
    <div class="finding-title">$(H $f.title)</div>
    <div class="finding-detail">$(H $f.detail)</div>
</div>
"@
}

if ([string]::IsNullOrWhiteSpace($findingsHtml)) {
    $findingsHtml = "<div class='good'>No findings detected.</div>"
}

$recommendationsHtml = ""

foreach ($r in @($result.recommendations)) {
    $recommendationsHtml += @"
<div class="recommendation">
    <div class="finding-title">$(H $r.title)</div>
    <div class="finding-detail">$(H $r.detail)</div>
</div>
"@
}

if ([string]::IsNullOrWhiteSpace($recommendationsHtml)) {
    $recommendationsHtml = "<div class='good'>No recommendations required.</div>"
}

$enabledUserRiskTable = PolicyTable `
    -Title "Enabled User Risk Protection Policies" `
    -Policies $e.enabled_user_risk_policies `
    -Empty "No enabled user risk protection policies detected."

$enabledSignInRiskTable = PolicyTable `
    -Title "Enabled Sign-in Risk Protection Policies" `
    -Policies $e.enabled_sign_in_risk_policies `
    -Empty "No enabled sign-in risk protection policies detected."

$exclusionTable = PolicyTable `
    -Title "Review Queue — Enabled Risk Policies With Exclusions" `
    -Policies $e.risk_policies_with_exclusions `
    -Empty "No enabled risk policies with exclusions detected."

$reportOnlyUserRiskTable = PolicyTable `
    -Title "Report-Only User Risk Policies" `
    -Policies $e.report_only_user_risk_policies `
    -Empty "No report-only user risk policies detected."

$reportOnlySignInRiskTable = PolicyTable `
    -Title "Report-Only Sign-in Risk Policies" `
    -Policies $e.report_only_sign_in_risk_policies `
    -Empty "No report-only sign-in risk policies detected."

$allRiskPoliciesTable = PolicyTable `
    -Title "Full Risk-Based Conditional Access Evidence" `
    -Policies $e.risk_policies `
    -Empty "No risk-based Conditional Access policies detected."

$title = H $result.scenario_name
$category = H $result.category
$status = H $result.status
$risk = H $result.risk
$timestamp = H $result.timestamp
$currentState = H $result.current_state
$target = H $result.zero_trust_target
$gap = H $result.gap_summary
$jsonSource = H (Resolve-Path $JsonPath)

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ZTVP - ID1 Risk-Based Conditional Access</title>
<style>
body { margin:0; font-family:"Segoe UI",Arial,sans-serif; background:#f4f7fb; color:#122033; }
.container { max-width:1280px; margin:32px auto; padding:0 24px; }
.header { background:linear-gradient(135deg,#0f172a,#14532d); color:white; border-radius:20px; padding:30px 34px; box-shadow:0 14px 34px rgba(15,23,42,.22); }
.header h1 { margin:0; font-size:31px; }
.header p { margin:8px 0 0 0; opacity:.85; }
.badge-row { margin-top:20px; display:flex; gap:12px; flex-wrap:wrap; }
.badge { padding:8px 14px; border-radius:999px; font-weight:800; font-size:13px; }
.pass { background:#dcfce7; color:#166534; }
.partial { background:#fef3c7; color:#92400e; }
.fail { background:#fee2e2; color:#991b1b; }
.section { background:white; border-radius:18px; padding:24px; margin-top:22px; box-shadow:0 7px 22px rgba(15,23,42,.08); }
.section h2 { margin:0 0 16px 0; font-size:22px; }
.decision { border-radius:16px; padding:20px; line-height:1.55; }
.decision.pass { border-left:7px solid #22c55e; background:#f0fdf4; color:#122033; }
.decision.partial { border-left:7px solid #f59e0b; background:#fffbeb; color:#122033; }
.decision.fail { border-left:7px solid #ef4444; background:#fff1f2; color:#122033; }
.decision strong { display:block; font-size:18px; margin-bottom:8px; }
.metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:14px; }
.metric { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:18px; }
.metric.warn { background:#fffbeb; border-color:#fde68a; }
.metric.negative { background:#fff1f2; border-color:#fecdd3; }
.metric-value { font-size:24px; font-weight:900; color:#0f172a; }
.metric-label { margin-top:6px; color:#64748b; font-size:14px; }
.action-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:14px; }
.action { border-radius:14px; padding:18px; border:1px solid #e2e8f0; background:#f8fafc; line-height:1.55; }
.action.critical { background:#fff1f2; border-color:#fecdd3; }
.action.warning { background:#fffbeb; border-color:#fde68a; }
.action.info { background:#eff6ff; border-color:#bfdbfe; }
.action-title { font-weight:900; margin-bottom:8px; color:#0f172a; }
.action-text { color:#334155; }
.finding { border-left:6px solid #ef4444; background:#fff1f2; border-radius:14px; padding:18px 20px; margin-top:14px; }
.recommendation { border-left:6px solid #2563eb; background:#eff6ff; border-radius:14px; padding:18px 20px; margin-top:14px; }
.good { border-left:6px solid #22c55e; background:#f0fdf4; border-radius:14px; padding:18px 20px; margin-top:14px; }
.finding-title { font-weight:900; font-size:17px; margin-bottom:8px; }
.finding-detail { line-height:1.55; color:#334155; }
.zt-block { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:16px; margin-top:12px; line-height:1.55; }
.table-wrap { overflow-x:auto; border:1px solid #e2e8f0; border-radius:14px; }
table { width:100%; border-collapse:collapse; min-width:1200px; }
th { background:#0f172a; color:white; text-align:left; padding:12px 14px; font-size:13px; white-space:nowrap; }
td { border-top:1px solid #e2e8f0; padding:12px 14px; vertical-align:top; font-size:14px; line-height:1.45; }
tr:nth-child(even) td { background:#f8fafc; }
.policy { font-weight:700; color:#0f172a; min-width:280px; }
.empty { color:#64748b; font-style:italic; }
.footer { color:#64748b; font-size:13px; margin:24px 0; text-align:center; }
</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>$title</h1>
    <p>$category</p>
    <div class="badge-row">
        <span class="badge $statusClass">Status: $status</span>
        <span class="badge $statusClass">Risk: $risk</span>
        <span class="badge partial">$timestamp</span>
    </div>
</div>

<section class="section">
    <h2>Plain-English Summary</h2>
    <div class="zt-block">$plainSummary</div>
    <div class="zt-block">$targetState</div>
</section>

<section class="section">
    <h2>Identity Protection Decision</h2>
    <div class="decision $decisionClass">
        <strong>$decisionTitle</strong>
        $decisionText
    </div>
</section>

<section class="section">
    <h2>Key Numbers</h2>
    <div class="metrics">$metrics</div>
</section>

<section class="section">
    <h2>What To Fix First</h2>
    <div class="action-grid">$actions</div>
</section>

<section class="section">
    <h2>Zero Trust Comparison</h2>
    <div class="zt-block"><strong>Current State:</strong><br>$currentState</div>
    <div class="zt-block"><strong>Zero Trust Target:</strong><br>$target</div>
    <div class="zt-block"><strong>Gap Summary:</strong><br>$gap</div>
</section>

<section class="section"><h2>Findings</h2>$findingsHtml</section>
<section class="section"><h2>Recommendations</h2>$recommendationsHtml</section>

$enabledUserRiskTable
$enabledSignInRiskTable
$exclusionTable
$reportOnlyUserRiskTable
$reportOnlySignInRiskTable
$allRiskPoliciesTable

<div class="footer">
Generated by Zero Trust Validation Platform (ZTVP). Source JSON: $jsonSource
</div>

</div>
</body>
</html>
"@

$outFolder = ".\powershell\Reports\Html"
New-Item -ItemType Directory -Path $outFolder -Force | Out-Null

$out = Join-Path $outFolder "ID1-result.html"

Set-Content -Path $out -Value $html -Encoding UTF8

Write-Host "Detailed ID1 HTML report generated:" -ForegroundColor Green
Write-Host $out -ForegroundColor Cyan

Start-Process $out
