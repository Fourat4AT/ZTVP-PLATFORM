param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath
)

function ConvertTo-B1HtmlSafe {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode($Value.ToString())
}

function New-B1Metric {
    param(
        [string]$Label,
        $Value
    )

    return @"
<div class="metric">
    <div class="metric-value">$(ConvertTo-B1HtmlSafe $Value)</div>
    <div class="metric-label">$(ConvertTo-B1HtmlSafe $Label)</div>
</div>
"@
}

function New-B1Card {
    param(
        [string]$Title,
        [string]$Text,
        [string]$Class
    )

    return @"
<div class="card $Class">
    <strong>$(ConvertTo-B1HtmlSafe $Title)</strong>
    <p>$(ConvertTo-B1HtmlSafe $Text)</p>
</div>
"@
}

function ConvertTo-B1YesNo {
    param($Value)

    if ($Value -eq $true) {
        return "Yes"
    }

    return "No"
}

function New-B1PolicyRows {
    param($Items)

    $rows = ""

    foreach ($p in @($Items | Where-Object { $null -ne $_ })) {
        $rows += @"
<tr>
    <td class="policy">$(ConvertTo-B1HtmlSafe $p.policy_name)</td>
    <td>$(ConvertTo-B1HtmlSafe $p.state_label)</td>
    <td>$(ConvertTo-B1HtmlSafe $p.control_summary)</td>
    <td>$(ConvertTo-B1HtmlSafe (ConvertTo-B1YesNo $p.targets_all_users))</td>
    <td>$(ConvertTo-B1HtmlSafe (ConvertTo-B1YesNo $p.targets_all_apps))</td>
    <td>$(ConvertTo-B1HtmlSafe (ConvertTo-B1YesNo $p.targets_roles))</td>
    <td>$(ConvertTo-B1HtmlSafe (ConvertTo-B1YesNo $p.legacy_or_basic_hint))</td>
    <td>$(ConvertTo-B1HtmlSafe $p.exclude_users_count)</td>
    <td>$(ConvertTo-B1HtmlSafe $p.exclude_groups_count)</td>
    <td>$(ConvertTo-B1HtmlSafe $p.exclude_roles_count)</td>
</tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='10' class='empty'>No policies in this section.</td></tr>"
    }

    return $rows
}

if (-not (Test-Path $JsonPath)) {
    throw "JSON report not found: $JsonPath"
}

$result = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json

if ($result.scenario_id -ne "B1") {
    throw "This converter is only for B1 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$statusClass = "pass"
$decisionTitle = "Baseline protection model is present."
$decisionText = "The tenant has a baseline model through Security Defaults or custom Conditional Access."

if ($result.status -eq "PARTIAL") {
    $statusClass = "partial"
    $decisionTitle = "Custom baseline exists, but validation is still required."
    $decisionText = "B1 found baseline Conditional Access controls, but some controls are report-only or Security Defaults evidence is unknown."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "fail"
    $decisionTitle = "Baseline protection model gap detected."
    $decisionText = "Security Defaults or an adequate enabled Conditional Access baseline was not confirmed."
}

$reviewText = "Use B1 as the baseline overview. Validate enforcement through A1/A2/A6, E1/E2/E3/E5, ID1/ID4, and later Devices/Intune scenarios."

if ($e.report_only_baseline_policy_count -gt 0) {
    $reviewText = "Custom Conditional Access baseline exists, but several baseline controls are report-only. Test impact, confirm exclusions, then move approved controls to enabled state. Validate details through A1/A2/A6, E1/E2/E3/E5, ID1/ID4, and later Devices/Intune scenarios."
}

if ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $reviewText = "Enable Security Defaults for a simple tenant, or implement an enabled Conditional Access baseline. Then validate coverage through the dedicated scenarios."
}

$metrics = ""
$metrics += New-B1Metric "Security Defaults State" $e.security_defaults_state
$metrics += New-B1Metric "CA Policies" $e.conditional_access_policy_count
$metrics += New-B1Metric "Enabled CA Policies" $e.enabled_conditional_access_policy_count
$metrics += New-B1Metric "Enabled Baseline Policies" $e.enabled_baseline_policy_count
$metrics += New-B1Metric "All-User Baseline Policies" $e.enabled_all_user_baseline_policy_count
$metrics += New-B1Metric "MFA/Auth Policies" $e.enabled_mfa_policy_count
$metrics += New-B1Metric "Block Policies" $e.enabled_block_policy_count
$metrics += New-B1Metric "Risk Policies" $e.enabled_risk_policy_count
$metrics += New-B1Metric "Report-Only Baseline" $e.report_only_baseline_policy_count

$findingsHtml = ""

foreach ($finding in @($result.findings)) {
    $findingsHtml += New-B1Card -Title $finding.title -Text $finding.detail -Class "finding"
}

if ([string]::IsNullOrWhiteSpace($findingsHtml)) {
    $findingsHtml = New-B1Card -Title "No major baseline protection gap detected" -Text "B1 did not detect a missing baseline protection model." -Class "good"
}

$recommendationsHtml = ""

foreach ($rec in @($result.recommendations)) {
    $recommendationsHtml += New-B1Card -Title $rec.title -Text $rec.detail -Class "recommendation"
}

if ([string]::IsNullOrWhiteSpace($recommendationsHtml)) {
    $recommendationsHtml = New-B1Card -Title "No immediate recommendation" -Text "No immediate action is required for this scenario." -Class "good"
}

$enabledRows = New-B1PolicyRows -Items $e.enabled_baseline_policies
$allUserRows = New-B1PolicyRows -Items $e.enabled_all_user_baseline_policies
$reportOnlyRows = New-B1PolicyRows -Items $e.report_only_baseline_policies

$title = ConvertTo-B1HtmlSafe $result.scenario_name
$category = ConvertTo-B1HtmlSafe $result.category
$status = ConvertTo-B1HtmlSafe $result.status
$risk = ConvertTo-B1HtmlSafe $result.risk
$timestamp = ConvertTo-B1HtmlSafe $result.timestamp
$currentState = ConvertTo-B1HtmlSafe $result.current_state
$target = ConvertTo-B1HtmlSafe $result.zero_trust_target
$gap = ConvertTo-B1HtmlSafe $result.gap_summary
$jsonSource = ConvertTo-B1HtmlSafe (Resolve-Path $JsonPath)

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ZTVP - B1 Baseline Security Review</title>
<style>
body { margin:0; font-family:"Segoe UI",Arial,sans-serif; background:#f4f7fb; color:#122033; }
.container { max-width:1280px; margin:32px auto; padding:0 24px; }
.header { background:linear-gradient(135deg,#0f172a,#334155); color:white; border-radius:18px; padding:28px 32px; box-shadow:0 12px 30px rgba(15,23,42,.18); }
.header h1 { margin:0; font-size:30px; }
.header p { margin:8px 0 0 0; opacity:.85; }
.badges { display:flex; gap:10px; flex-wrap:wrap; margin-top:18px; }
.badge { padding:8px 13px; border-radius:999px; font-weight:800; font-size:13px; }
.pass { background:#dcfce7; color:#166534; }
.partial { background:#fef3c7; color:#92400e; }
.fail { background:#fee2e2; color:#991b1b; }
.section { background:white; border-radius:16px; padding:22px; margin-top:20px; box-shadow:0 6px 18px rgba(15,23,42,.07); }
.section h2 { margin:0 0 14px 0; font-size:21px; }
.decision { border-radius:16px; padding:20px; line-height:1.55; color:#122033; }
.decision.pass { border-left:7px solid #22c55e; background:#f0fdf4; }
.decision.partial { border-left:7px solid #f59e0b; background:#fffbeb; }
.decision.fail { border-left:7px solid #ef4444; background:#fff1f2; }
.decision strong { display:block; font-size:19px; margin-bottom:8px; }
.metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; }
.metric { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:16px; }
.metric-value { font-size:25px; font-weight:900; color:#0f172a; }
.metric-label { margin-top:6px; color:#64748b; font-size:14px; }
.review-box { background:#eff6ff; border:1px solid #bfdbfe; border-left:7px solid #2563eb; border-radius:14px; padding:18px; line-height:1.55; }
.card { border-radius:14px; padding:16px 18px; margin-top:12px; line-height:1.5; }
.card p { margin:8px 0 0 0; color:#334155; }
.finding { background:#fff7ed; border-left:6px solid #f97316; }
.recommendation { background:#eff6ff; border-left:6px solid #2563eb; }
.good { background:#f0fdf4; border-left:6px solid #22c55e; }
.zt-block { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:16px; margin-top:12px; line-height:1.55; }
.table-wrap { overflow-x:auto; border:1px solid #e2e8f0; border-radius:14px; }
table { width:100%; border-collapse:collapse; min-width:1100px; }
th { background:#0f172a; color:white; text-align:left; padding:12px 14px; font-size:13px; white-space:nowrap; }
td { border-top:1px solid #e2e8f0; padding:12px 14px; vertical-align:top; font-size:14px; line-height:1.45; }
tr:nth-child(even) td { background:#f8fafc; }
.policy { font-weight:700; color:#0f172a; min-width:260px; }
.empty { color:#64748b; font-style:italic; }
.footer { color:#64748b; font-size:13px; margin:22px 0; text-align:center; }
</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>$title</h1>
    <p>$category</p>
    <div class="badges">
        <span class="badge $statusClass">Status: $status</span>
        <span class="badge $statusClass">Risk: $risk</span>
        <span class="badge pass">$timestamp</span>
    </div>
</div>

<section class="section">
    <h2>Executive Decision</h2>
    <div class="decision $statusClass">
        <strong>$decisionTitle</strong>
        $decisionText
    </div>
</section>

<section class="section">
    <h2>Key Numbers</h2>
    <div class="metrics">$metrics</div>
</section>

<section class="section">
    <h2>What To Do Next</h2>
    <div class="review-box">$reviewText</div>
</section>

<section class="section">
    <h2>Findings</h2>
    $findingsHtml
</section>

<section class="section">
    <h2>Recommendations</h2>
    $recommendationsHtml
</section>

<section class="section">
    <h2>Zero Trust Comparison</h2>
    <div class="zt-block"><strong>Current State:</strong><br>$currentState</div>
    <div class="zt-block"><strong>Target:</strong><br>$target</div>
    <div class="zt-block"><strong>Gap:</strong><br>$gap</div>
</section>

<section class="section">
    <h2>Enabled Baseline Conditional Access Policies</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Policy</th>
                    <th>State</th>
                    <th>Control</th>
                    <th>All Users</th>
                    <th>All Apps</th>
                    <th>Roles</th>
                    <th>Legacy Hint</th>
                    <th>Excluded Users</th>
                    <th>Excluded Groups</th>
                    <th>Excluded Roles</th>
                </tr>
            </thead>
            <tbody>$enabledRows</tbody>
        </table>
    </div>
</section>

<section class="section">
    <h2>All-User Baseline Policies</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Policy</th>
                    <th>State</th>
                    <th>Control</th>
                    <th>All Users</th>
                    <th>All Apps</th>
                    <th>Roles</th>
                    <th>Legacy Hint</th>
                    <th>Excluded Users</th>
                    <th>Excluded Groups</th>
                    <th>Excluded Roles</th>
                </tr>
            </thead>
            <tbody>$allUserRows</tbody>
        </table>
    </div>
</section>

<section class="section">
    <h2>Report-Only Baseline Policies</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Policy</th>
                    <th>State</th>
                    <th>Control</th>
                    <th>All Users</th>
                    <th>All Apps</th>
                    <th>Roles</th>
                    <th>Legacy Hint</th>
                    <th>Excluded Users</th>
                    <th>Excluded Groups</th>
                    <th>Excluded Roles</th>
                </tr>
            </thead>
            <tbody>$reportOnlyRows</tbody>
        </table>
    </div>
</section>

<div class="footer">
Generated by Zero Trust Validation Platform (ZTVP). Source JSON: $jsonSource
</div>

</div>
</body>
</html>
"@

$outFolder = ".\powershell\Reports\Html"
New-Item -ItemType Directory -Path $outFolder -Force | Out-Null

$out = Join-Path $outFolder "B1-result.html"
Set-Content -Path $out -Value $html -Encoding UTF8

Write-Host "Clean B1 HTML report generated:" -ForegroundColor Green
Write-Host $out -ForegroundColor Cyan
Start-Process $out
