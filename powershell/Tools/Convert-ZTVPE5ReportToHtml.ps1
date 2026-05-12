param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath
)

function ConvertTo-HtmlSafe {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode($Value.ToString())
}

function Get-YesNo {
    param($Value)

    if ($Value -eq $true) {
        return "Yes"
    }

    return "No"
}

function New-MetricCard {
    param(
        [string]$Label,
        [string]$Value,
        [string]$Class = ""
    )

    return @"
<div class="metric-card $Class">
    <div class="metric-value">$(ConvertTo-HtmlSafe $Value)</div>
    <div class="metric-label">$(ConvertTo-HtmlSafe $Label)</div>
</div>
"@
}

function New-PolicyTable {
    param(
        [string]$Title,
        $Policies,
        [string]$EmptyMessage
    )

    $rows = ""

    foreach ($p in @($Policies)) {
        $rows += @"
<tr>
    <td class="policy-name">$(ConvertTo-HtmlSafe $p.name)</td>
    <td>$(ConvertTo-HtmlSafe $p.state_label)</td>
    <td>$(ConvertTo-HtmlSafe $p.admin_scope_category)</td>
    <td>$(ConvertTo-HtmlSafe $p.admin_scope_reason)</td>
    <td>$(ConvertTo-HtmlSafe $p.control_summary)</td>
    <td>$(ConvertTo-HtmlSafe (Get-YesNo $p.has_mfa))</td>
    <td>$(ConvertTo-HtmlSafe (Get-YesNo $p.has_phishing_resistant))</td>
    <td>$(ConvertTo-HtmlSafe (Get-YesNo $p.has_device_trust))</td>
    <td>$(ConvertTo-HtmlSafe (Get-YesNo $p.has_block))</td>
    <td>$(ConvertTo-HtmlSafe (Get-YesNo $p.has_session_control))</td>
</tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='10' class='empty'>$(ConvertTo-HtmlSafe $EmptyMessage)</td></tr>"
    }

    return @"
<section class="section">
    <h2>$Title</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Policy Name</th>
                    <th>State</th>
                    <th>Scope Category</th>
                    <th>Scope Reason</th>
                    <th>Controls</th>
                    <th>MFA</th>
                    <th>Phish-Resistant</th>
                    <th>Device Trust</th>
                    <th>Block</th>
                    <th>Session</th>
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

$result = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json

if ($result.scenario_id -ne "E5") {
    throw "This converter is only for E5 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$statusClass = "status-pass"
$decisionClass = "decision-pass"
$decisionTitle = "Admin access policy posture appears controlled."
$decisionText = "Enabled confirmed admin authentication protection was detected."

if ($result.status -eq "PARTIAL") {
    $statusClass = "status-partial"
    $decisionClass = "decision-partial"
    $decisionTitle = "Admin access policy posture requires review."
    $decisionText = "Some protection exists, but confirmed dedicated admin enforcement, phishing-resistant authentication, device trust, or report-only dependencies require review."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "status-fail"
    $decisionClass = "decision-fail"
    $decisionTitle = "Critical admin access policy gap detected."
    $decisionText = "Enabled confirmed dedicated admin MFA or authentication-strength protection was not found."
}

$metrics = ""
$metrics += New-MetricCard "CA Policies Assessed" $e.conditional_access_policy_count
$metrics += New-MetricCard "Admin-Relevant Policies" $e.admin_relevant_policy_count
$metrics += New-MetricCard "Confirmed Admin-Scoped Policies" $e.confirmed_admin_policy_count
$metrics += New-MetricCard "Admin-Name-Only Policies" $e.admin_name_only_policy_count "warning"
$metrics += New-MetricCard "Enabled Confirmed Admin Auth" $e.enabled_confirmed_admin_auth_policy_count
$metrics += New-MetricCard "Report-only Confirmed Admin Auth" $e.report_only_confirmed_admin_auth_policy_count "warning"
$metrics += New-MetricCard "Report-only Admin-Name Auth" $e.report_only_admin_name_only_auth_policy_count "warning"
$metrics += New-MetricCard "Enabled Confirmed Phish-Resistant" $e.enabled_confirmed_admin_phish_policy_count
$metrics += New-MetricCard "Report-only Admin Phish Candidates" ($e.report_only_confirmed_admin_phish_policy_count + $e.report_only_admin_name_only_phish_policy_count) "warning"
$metrics += New-MetricCard "Enabled Confirmed Device Trust" $e.enabled_confirmed_admin_device_policy_count
$metrics += New-MetricCard "Report-only Device Trust Candidates" ($e.report_only_confirmed_admin_device_policy_count + $e.report_only_admin_name_only_device_policy_count) "warning"
$metrics += New-MetricCard "Enabled Broad Workforce MFA" $e.enabled_broad_workforce_auth_policy_count

$findingsHtml = ""
foreach ($finding in @($result.findings)) {
    $findingsHtml += @"
<div class="finding-card">
    <div class="finding-title">$(ConvertTo-HtmlSafe $finding.title)</div>
    <div class="finding-detail">$(ConvertTo-HtmlSafe $finding.detail)</div>
</div>
"@
}

if ([string]::IsNullOrWhiteSpace($findingsHtml)) {
    $findingsHtml = '<div class="good-card">No findings detected.</div>'
}

$recommendationsHtml = ""
foreach ($rec in @($result.recommendations)) {
    $recommendationsHtml += @"
<div class="recommendation-card">
    <div class="finding-title">$(ConvertTo-HtmlSafe $rec.title)</div>
    <div class="finding-detail">$(ConvertTo-HtmlSafe $rec.detail)</div>
</div>
"@
}

if ([string]::IsNullOrWhiteSpace($recommendationsHtml)) {
    $recommendationsHtml = '<div class="good-card">No recommendations required.</div>'
}

$confirmedAdminTable = New-PolicyTable `
    -Title "Confirmed Admin-Scoped Policy Inventory" `
    -Policies $e.confirmed_admin_policies `
    -EmptyMessage "No confirmed admin-scoped policies detected."

$nameOnlyTable = New-PolicyTable `
    -Title "Admin-Named Policies Requiring Scope Verification" `
    -Policies $e.admin_name_only_policies `
    -EmptyMessage "No admin-name-only policies detected."

$enabledConfirmedAuthTable = New-PolicyTable `
    -Title "Validated Control — Enabled Confirmed Admin Authentication Policies" `
    -Policies $e.enabled_confirmed_admin_auth_policies `
    -EmptyMessage "No enabled confirmed admin authentication policies detected."

$reportOnlyAuthTable = New-PolicyTable `
    -Title "Review Queue — Report-Only Admin Authentication Candidates" `
    -Policies (@($e.report_only_confirmed_admin_auth_policies) + @($e.report_only_admin_name_only_auth_policies)) `
    -EmptyMessage "No report-only admin authentication candidates detected."

$phishTable = New-PolicyTable `
    -Title "Review Queue — Admin Phishing-Resistant / Authentication Strength Candidates" `
    -Policies (@($e.enabled_confirmed_admin_phish_policies) + @($e.report_only_confirmed_admin_phish_policies) + @($e.enabled_admin_name_only_phish_policies) + @($e.report_only_admin_name_only_phish_policies)) `
    -EmptyMessage "No admin phishing-resistant/authentication-strength candidates detected."

$deviceTable = New-PolicyTable `
    -Title "Review Queue — Admin Device Trust Candidates" `
    -Policies (@($e.enabled_confirmed_admin_device_policies) + @($e.report_only_confirmed_admin_device_policies) + @($e.enabled_admin_name_only_device_policies) + @($e.report_only_admin_name_only_device_policies)) `
    -EmptyMessage "No admin device trust candidates detected."

$broadTable = New-PolicyTable `
    -Title "Context — Broad Workforce MFA Policies" `
    -Policies (@($e.enabled_broad_workforce_auth_policies) + @($e.report_only_broad_workforce_auth_policies)) `
    -EmptyMessage "No broad workforce MFA policies detected."

$title = ConvertTo-HtmlSafe $result.scenario_name
$category = ConvertTo-HtmlSafe $result.category
$status = ConvertTo-HtmlSafe $result.status
$risk = ConvertTo-HtmlSafe $result.risk
$timestamp = ConvertTo-HtmlSafe $result.timestamp
$summary = ConvertTo-HtmlSafe $e.executive_summary
$currentState = ConvertTo-HtmlSafe $result.current_state
$target = ConvertTo-HtmlSafe $result.zero_trust_target
$gap = ConvertTo-HtmlSafe $result.gap_summary
$jsonSource = ConvertTo-HtmlSafe (Resolve-Path $JsonPath)

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ZTVP - E5 Admin Access Policy Presence Review</title>
<style>
body { margin:0; font-family:"Segoe UI",Arial,sans-serif; background:#f4f7fb; color:#122033; }
.container { max-width:1280px; margin:32px auto; padding:0 24px; }
.header { background:linear-gradient(135deg,#0f172a,#1e3a8a); color:white; border-radius:20px; padding:30px 34px; box-shadow:0 14px 34px rgba(15,23,42,.22); }
.header h1 { margin:0; font-size:31px; }
.header p { margin:8px 0 0 0; opacity:.85; }
.badge-row { margin-top:20px; display:flex; gap:12px; flex-wrap:wrap; }
.badge { padding:8px 14px; border-radius:999px; font-weight:800; font-size:13px; }
.status-pass { background:#dcfce7; color:#166534; }
.status-partial { background:#fef3c7; color:#92400e; }
.status-fail { background:#fee2e2; color:#991b1b; }
.section { background:white; border-radius:18px; padding:24px; margin-top:22px; box-shadow:0 7px 22px rgba(15,23,42,.08); }
.section h2 { margin:0 0 16px 0; font-size:22px; }
.decision { border-radius:16px; padding:20px; line-height:1.55; }
.decision-pass { border-left:7px solid #22c55e; background:#f0fdf4; }
.decision-partial { border-left:7px solid #f59e0b; background:#fffbeb; }
.decision-fail { border-left:7px solid #ef4444; background:#fff1f2; }
.decision strong { display:block; font-size:18px; margin-bottom:8px; }
.metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:14px; }
.metric-card { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:18px; }
.metric-card.warning { background:#fffbeb; border-color:#fde68a; }
.metric-value { font-size:24px; font-weight:900; color:#0f172a; }
.metric-label { margin-top:6px; color:#64748b; font-size:14px; }
.finding-card { border-left:6px solid #ef4444; background:#fff1f2; border-radius:14px; padding:18px 20px; margin-top:14px; }
.recommendation-card { border-left:6px solid #2563eb; background:#eff6ff; border-radius:14px; padding:18px 20px; margin-top:14px; }
.good-card { border-left:6px solid #22c55e; background:#f0fdf4; border-radius:14px; padding:18px 20px; margin-top:14px; }
.finding-title { font-weight:900; font-size:17px; margin-bottom:8px; }
.finding-detail { line-height:1.55; color:#334155; }
.zt-block { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:16px; margin-top:12px; line-height:1.55; }
.table-wrap { overflow-x:auto; border:1px solid #e2e8f0; border-radius:14px; }
table { width:100%; border-collapse:collapse; min-width:1180px; }
th { background:#0f172a; color:white; text-align:left; padding:12px 14px; font-size:13px; white-space:nowrap; }
td { border-top:1px solid #e2e8f0; padding:12px 14px; vertical-align:top; font-size:14px; line-height:1.45; }
tr:nth-child(even) td { background:#f8fafc; }
.policy-name { font-weight:700; color:#0f172a; min-width:300px; }
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
        <span class="badge status-partial">$timestamp</span>
    </div>
</div>

<section class="section">
    <h2>Executive Summary</h2>
    <div class="zt-block">$summary</div>
</section>

<section class="section">
    <h2>Admin Access Protection Decision</h2>
    <div class="decision $decisionClass">
        <strong>$decisionTitle</strong>
        $decisionText
    </div>
</section>

<section class="section">
    <h2>Key Metrics</h2>
    <div class="metrics">$metrics</div>
</section>

<section class="section">
    <h2>Zero Trust Comparison</h2>
    <div class="zt-block"><strong>Current State:</strong><br>$currentState</div>
    <div class="zt-block"><strong>Zero Trust Target:</strong><br>$target</div>
    <div class="zt-block"><strong>Gap Summary:</strong><br>$gap</div>
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
    <h2>Admin Access Policy Evidence</h2>
    <div class="zt-block">
        E5 separates confirmed admin-scoped policies from policies that only appear admin-related by name.
        Confirmed admin scope means the policy targets admin roles or Microsoft Admin Portals. Admin-name-only policies should be reviewed before being treated as valid admin protection.
    </div>
</section>

$enabledConfirmedAuthTable
$confirmedAdminTable
$nameOnlyTable
$reportOnlyAuthTable
$phishTable
$deviceTable
$broadTable

<div class="footer">
Generated by Zero Trust Validation Platform (ZTVP). Source JSON: $jsonSource
</div>

</div>
</body>
</html>
"@

$htmlFolder = ".\powershell\Reports\Html"
New-Item -ItemType Directory -Path $htmlFolder -Force | Out-Null

$outputPath = Join-Path $htmlFolder "E5-result.html"

Set-Content -Path $outputPath -Value $html -Encoding UTF8

Write-Host "Detailed E5 HTML report generated:" -ForegroundColor Green
Write-Host $outputPath -ForegroundColor Cyan

Start-Process $outputPath
