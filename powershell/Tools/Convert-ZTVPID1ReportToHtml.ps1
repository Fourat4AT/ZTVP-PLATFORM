param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath
)

function ConvertTo-ID1HtmlSafe {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode($Value.ToString())
}

function ConvertTo-ID1YesNo {
    param($Value)

    if ($Value -eq $true) {
        return "Yes"
    }

    return "No"
}

function Join-ID1Values {
    param($Values)

    $items = @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if ($items.Count -eq 0) {
        return "None"
    }

    return (($items | ForEach-Object { ConvertTo-ID1HtmlSafe $_ }) -join "<br>")
}

function New-ID1Metric {
    param(
        [string]$Label,
        $Value,
        [string]$Class = ""
    )

    return @"
<div class="metric $Class">
    <div class="metric-value">$(ConvertTo-ID1HtmlSafe $Value)</div>
    <div class="metric-label">$(ConvertTo-ID1HtmlSafe $Label)</div>
</div>
"@
}

function New-ID1PolicyRows {
    param($Policies)

    $rows = ""

    foreach ($p in @($Policies | Where-Object { $null -ne $_ })) {
        $exclusionSummary = "No"

        if ($p.has_exclusions -eq $true) {
            $exclusionSummary = "Yes — Users: $($p.exclude_users_count), Groups: $($p.exclude_groups_count), Roles: $($p.exclude_roles_count)"
        }

        $rows += @"
<tr>
    <td class="policy">$(ConvertTo-ID1HtmlSafe $p.name)</td>
    <td>$(ConvertTo-ID1HtmlSafe $p.state_label)</td>
    <td>$(ConvertTo-ID1HtmlSafe $p.risk_type)</td>
    <td>$(ConvertTo-ID1HtmlSafe $p.control_summary)</td>
    <td>$(Join-ID1Values $p.user_risk_levels)</td>
    <td>$(Join-ID1Values $p.sign_in_risk_levels)</td>
    <td>$(ConvertTo-ID1HtmlSafe $exclusionSummary)</td>
</tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='7' class='empty'>No risk-based Conditional Access policies detected.</td></tr>"
    }

    return $rows
}

if (-not (Test-Path $JsonPath)) {
    throw "JSON report not found: $JsonPath"
}

$result = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json

if ($result.scenario_id -ne "ID1") {
    throw "This converter is only for ID1 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$statusClass = "pass"
$decisionTitle = "Risk-based Conditional Access is aligned."
$decisionText = "User risk and sign-in risk protections are enabled and enforcing."

if ($result.status -eq "PARTIAL") {
    $statusClass = "partial"
    $decisionTitle = "Risk-based Conditional Access is mostly in place, but needs review."
    $decisionText = "User risk and sign-in risk policies are enabled. The remaining concern is that enabled risk policies contain exclusions."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "fail"
    $decisionTitle = "Risk-based Conditional Access is not fully enforced."
    $decisionText = "User risk or sign-in risk protection is missing, report-only, or not enforcing the expected control."
}

$reviewText = "No immediate cleanup item was detected."

if ($e.enabled_risk_policy_with_exclusion_count -gt 0) {
    $reviewText = "Review the excluded users, groups, or roles in enabled risk policies. Keep only approved exceptions and document why they exist."
}
elseif ($e.report_only_risk_policy_count -gt 0) {
    $reviewText = "Review report-only risk policies and move validated policies to enabled enforcement."
}
elseif ($result.status -eq "FAIL") {
    $reviewText = "Create or enable user risk and sign-in risk Conditional Access policies."
}

$metrics = ""
$metrics += New-ID1Metric "Risk-based policies" $e.risk_policy_count
$metrics += New-ID1Metric "Enabled risk policies" $e.enabled_risk_policy_count
$metrics += New-ID1Metric "User risk policies" $e.enabled_user_risk_policy_count
$metrics += New-ID1Metric "Sign-in risk policies" $e.enabled_sign_in_risk_policy_count
$metrics += New-ID1Metric "Report-only risk policies" $e.report_only_risk_policy_count
$metrics += New-ID1Metric "Enabled policies with exclusions" $e.enabled_risk_policy_with_exclusion_count "warn"

$findingsHtml = ""

foreach ($finding in @($result.findings)) {
    $findingsHtml += @"
<div class="compact-card finding">
    <strong>$(ConvertTo-ID1HtmlSafe $finding.title)</strong>
    <p>$(ConvertTo-ID1HtmlSafe $finding.detail)</p>
</div>
"@
}

if ([string]::IsNullOrWhiteSpace($findingsHtml)) {
    $findingsHtml = "<div class='compact-card good'><strong>No findings detected.</strong><p>No risk-based Conditional Access issue was detected by ID1.</p></div>"
}

$recommendationsHtml = ""

foreach ($rec in @($result.recommendations)) {
    $recommendationsHtml += @"
<div class="compact-card recommendation">
    <strong>$(ConvertTo-ID1HtmlSafe $rec.title)</strong>
    <p>$(ConvertTo-ID1HtmlSafe $rec.detail)</p>
</div>
"@
}

if ([string]::IsNullOrWhiteSpace($recommendationsHtml)) {
    $recommendationsHtml = "<div class='compact-card good'><strong>No recommendations required.</strong><p>No immediate action is required for this scenario.</p></div>"
}

$policyRows = New-ID1PolicyRows -Policies $e.risk_policies

$title = ConvertTo-ID1HtmlSafe $result.scenario_name
$category = ConvertTo-ID1HtmlSafe $result.category
$status = ConvertTo-ID1HtmlSafe $result.status
$risk = ConvertTo-ID1HtmlSafe $result.risk
$timestamp = ConvertTo-ID1HtmlSafe $result.timestamp
$jsonSource = ConvertTo-ID1HtmlSafe (Resolve-Path $JsonPath)

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ZTVP - ID1 Risk-Based Conditional Access</title>
<style>
body {
    margin: 0;
    font-family: "Segoe UI", Arial, sans-serif;
    background: #f4f7fb;
    color: #122033;
}
.container {
    max-width: 1180px;
    margin: 32px auto;
    padding: 0 24px;
}
.header {
    background: linear-gradient(135deg,#0f172a,#14532d);
    color: white;
    border-radius: 18px;
    padding: 28px 32px;
    box-shadow: 0 12px 30px rgba(15,23,42,.18);
}
.header h1 {
    margin: 0;
    font-size: 30px;
}
.header p {
    margin: 8px 0 0 0;
    opacity: .85;
}
.badges {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 18px;
}
.badge {
    padding: 8px 13px;
    border-radius: 999px;
    font-weight: 800;
    font-size: 13px;
}
.pass { background: #dcfce7; color: #166534; }
.partial { background: #fef3c7; color: #92400e; }
.fail { background: #fee2e2; color: #991b1b; }

.section {
    background: white;
    border-radius: 16px;
    padding: 22px;
    margin-top: 20px;
    box-shadow: 0 6px 18px rgba(15,23,42,.07);
}
.section h2 {
    margin: 0 0 14px 0;
    font-size: 21px;
}
.decision {
    border-radius: 16px;
    padding: 20px;
    line-height: 1.55;
}
.decision.pass { border-left: 7px solid #22c55e; background: #f0fdf4; color: #122033; }
.decision.partial { border-left: 7px solid #f59e0b; background: #fffbeb; color: #122033; }
.decision.fail { border-left: 7px solid #ef4444; background: #fff1f2; color: #122033; }
.decision strong {
    display: block;
    font-size: 19px;
    margin-bottom: 8px;
}
.metrics {
    display: grid;
    grid-template-columns: repeat(auto-fit,minmax(180px,1fr));
    gap: 12px;
}
.metric {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 14px;
    padding: 16px;
}
.metric.warn {
    background: #fffbeb;
    border-color: #fde68a;
}
.metric-value {
    font-size: 25px;
    font-weight: 900;
    color: #0f172a;
}
.metric-label {
    margin-top: 6px;
    color: #64748b;
    font-size: 14px;
}
.review-box {
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    border-left: 7px solid #2563eb;
    border-radius: 14px;
    padding: 18px;
    line-height: 1.55;
}
.compact-card {
    border-radius: 14px;
    padding: 16px 18px;
    margin-top: 12px;
    line-height: 1.5;
}
.compact-card p {
    margin: 8px 0 0 0;
    color: #334155;
}
.finding {
    background: #fff1f2;
    border-left: 6px solid #ef4444;
}
.recommendation {
    background: #eff6ff;
    border-left: 6px solid #2563eb;
}
.good {
    background: #f0fdf4;
    border-left: 6px solid #22c55e;
}
.table-wrap {
    overflow-x: auto;
    border: 1px solid #e2e8f0;
    border-radius: 14px;
}
table {
    width: 100%;
    border-collapse: collapse;
    min-width: 980px;
}
th {
    background: #0f172a;
    color: white;
    text-align: left;
    padding: 12px 14px;
    font-size: 13px;
    white-space: nowrap;
}
td {
    border-top: 1px solid #e2e8f0;
    padding: 12px 14px;
    vertical-align: top;
    font-size: 14px;
    line-height: 1.45;
}
tr:nth-child(even) td {
    background: #f8fafc;
}
.policy {
    font-weight: 700;
    color: #0f172a;
    min-width: 280px;
}
.empty {
    color: #64748b;
    font-style: italic;
}
.footer {
    color: #64748b;
    font-size: 13px;
    margin: 22px 0;
    text-align: center;
}
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
        <span class="badge partial">$timestamp</span>
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
    <h2>Review Required</h2>
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
    <h2>Risk-Based Conditional Access Evidence</h2>
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
                    <th>Exclusions</th>
                </tr>
            </thead>
            <tbody>$policyRows</tbody>
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

$out = Join-Path $outFolder "ID1-result.html"
Set-Content -Path $out -Value $html -Encoding UTF8

Write-Host "Clean ID1 HTML report generated:" -ForegroundColor Green
Write-Host $out -ForegroundColor Cyan

Start-Process $out
