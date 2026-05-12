param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath
)

function ConvertTo-ZTVPHtmlSafe {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode($Value.ToString())
}

function ConvertTo-ZTVPYesNo {
    param($Value)

    if ($Value -eq $true) {
        return "Yes"
    }

    return "No"
}

function New-ZTVPMetricCard {
    param(
        [string]$Label,
        $Value,
        [string]$Class = ""
    )

    return @"
<div class="metric-card $Class">
    <div class="metric-value">$(ConvertTo-ZTVPHtmlSafe $Value)</div>
    <div class="metric-label">$(ConvertTo-ZTVPHtmlSafe $Label)</div>
</div>
"@
}

function New-ZTVPActionCard {
    param(
        [string]$Title,
        [string]$Text,
        [string]$Class = ""
    )

    return @"
<div class="action-card $Class">
    <div class="action-title">$(ConvertTo-ZTVPHtmlSafe $Title)</div>
    <div class="action-text">$(ConvertTo-ZTVPHtmlSafe $Text)</div>
</div>
"@
}

function New-ZTVPGATable {
    param(
        [string]$Title,
        $Items,
        [string]$EmptyMessage
    )

    $rows = ""

    foreach ($a in @($Items)) {
        $rows += @"
<tr>
    <td class="name">$(ConvertTo-ZTVPHtmlSafe $a.principalLabel)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $a.principalType)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe (ConvertTo-ZTVPYesNo $a.accountEnabled))</td>
    <td>$(ConvertTo-ZTVPHtmlSafe (ConvertTo-ZTVPYesNo $a.emergency))</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $a.assignmentModel)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $a.endDateTime)</td>
</tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='6' class='empty'>$(ConvertTo-ZTVPHtmlSafe $EmptyMessage)</td></tr>"
    }

    return @"
<section class="section">
    <h2>$Title</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Principal</th>
                    <th>Type</th>
                    <th>Enabled</th>
                    <th>Emergency</th>
                    <th>Access Model</th>
                    <th>End Date</th>
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

if ($result.scenario_id -ne "P2") {
    throw "This converter is only for P2 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$statusClass = "status-pass"
$decisionClass = "decision-pass"
$decisionTitle = "Global Administrator posture looks controlled."
$decisionText = "Global Administrator membership is limited and aligned with least privilege."

if ($result.status -eq "PARTIAL") {
    $statusClass = "status-partial"
    $decisionClass = "decision-partial"
    $decisionTitle = "Global Administrator posture needs review."
    $decisionText = "Global Administrator count, break-glass coverage, or PIM/JIT alignment needs improvement."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "status-fail"
    $decisionClass = "decision-fail"
    $decisionTitle = "Too much Global Administrator exposure."
    $decisionText = "Reduce Global Administrators, remove or justify service principals, and move normal admins to PIM eligible/time-bound access."
}

$plainSummary = "This tenant has $($e.active_global_admin_count) active Global Administrators, including $($e.normal_user_global_admin_count) normal user accounts, $($e.emergency_global_admin_count) emergency accounts, and $($e.non_user_global_admin_count) service principals or non-user objects. $($e.permanent_normal_user_global_admin_count) normal users have permanent Global Administrator. The main goal is to reduce standing Global Administrator access."

$targetState = "Target state: keep only a small approved Global Administrator set, keep break-glass accounts controlled, move normal admins to PIM eligible/time-bound access, and remove Global Administrator from service principals unless strongly justified."

$metrics = ""
$metrics += New-ZTVPMetricCard "Active Global Administrators" $e.active_global_admin_count "negative"
$metrics += New-ZTVPMetricCard "Normal User Global Admins" $e.normal_user_global_admin_count "negative"
$metrics += New-ZTVPMetricCard "Emergency Global Admins" $e.emergency_global_admin_count "warning"
$metrics += New-ZTVPMetricCard "Service Principal / Non-User GAs" $e.non_user_global_admin_count "negative"
$metrics += New-ZTVPMetricCard "Permanent Normal User GAs" $e.permanent_normal_user_global_admin_count "negative"
$metrics += New-ZTVPMetricCard "PIM Eligible Global Admins" $e.eligible_global_admin_count
$metrics += New-ZTVPMetricCard "Active Without PIM Eligibility" $e.active_without_eligibility_count "warning"
$metrics += New-ZTVPMetricCard "JIT / PIM Model" $e.jit_model

$actions = ""
$actions += New-ZTVPActionCard "1. Reduce Global Administrators" "Keep only a small number of approved Global Administrators. Remove unnecessary Global Administrator assignments." "critical"
$actions += New-ZTVPActionCard "2. Move normal admins to PIM" "Normal admin users should become PIM eligible and activate Global Administrator only when needed." "critical"
$actions += New-ZTVPActionCard "3. Remove Global Admin from apps" "Service principals should not have Global Administrator unless there is a documented and monitored business requirement." "critical"
$actions += New-ZTVPActionCard "4. Keep break-glass controlled" "Emergency Global Administrators should be cloud-only, monitored, tested in A4, and not used for daily administration." "warning"
$actions += New-ZTVPActionCard "5. Delegate narrower roles" "Use roles like Conditional Access Administrator, Security Administrator, Exchange Administrator, or User Administrator instead of Global Administrator." "info"

$findingsHtml = ""

foreach ($finding in @($result.findings)) {
    $findingsHtml += @"
<div class="finding-card">
    <div class="finding-title">$(ConvertTo-ZTVPHtmlSafe $finding.title)</div>
    <div class="finding-detail">$(ConvertTo-ZTVPHtmlSafe $finding.detail)</div>
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
    <div class="finding-title">$(ConvertTo-ZTVPHtmlSafe $rec.title)</div>
    <div class="finding-detail">$(ConvertTo-ZTVPHtmlSafe $rec.detail)</div>
</div>
"@
}

if ([string]::IsNullOrWhiteSpace($recommendationsHtml)) {
    $recommendationsHtml = '<div class="good-card">No recommendations required.</div>'
}

$activeTable = New-ZTVPGATable `
    -Title "All Active Global Administrators" `
    -Items $e.active_global_admins `
    -EmptyMessage "No active Global Administrators detected."

$normalTable = New-ZTVPGATable `
    -Title "Action Queue — Normal Users With Global Administrator" `
    -Items $e.normal_user_global_admins `
    -EmptyMessage "No normal user Global Administrators detected."

$nonUserTable = New-ZTVPGATable `
    -Title "Action Queue — Service Principals / Non-User Global Administrators" `
    -Items $e.non_user_global_admins `
    -EmptyMessage "No service principals or non-user objects with Global Administrator detected."

$emergencyTable = New-ZTVPGATable `
    -Title "Review Queue — Break-Glass Global Administrators" `
    -Items $e.emergency_global_admins `
    -EmptyMessage "No break-glass Global Administrators detected."

$eligibleTable = New-ZTVPGATable `
    -Title "PIM Eligible Global Administrator Assignments" `
    -Items $e.eligible_global_admins `
    -EmptyMessage "No PIM eligible Global Administrator assignments detected."

$title = ConvertTo-ZTVPHtmlSafe $result.scenario_name
$category = ConvertTo-ZTVPHtmlSafe $result.category
$status = ConvertTo-ZTVPHtmlSafe $result.status
$risk = ConvertTo-ZTVPHtmlSafe $result.risk
$timestamp = ConvertTo-ZTVPHtmlSafe $result.timestamp
$currentState = ConvertTo-ZTVPHtmlSafe $result.current_state
$target = ConvertTo-ZTVPHtmlSafe $result.zero_trust_target
$gap = ConvertTo-ZTVPHtmlSafe $result.gap_summary
$jsonSource = ConvertTo-ZTVPHtmlSafe (Resolve-Path $JsonPath)

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ZTVP - P2 Global Administrator Count and Hygiene Review</title>
<style>
body { margin:0; font-family:"Segoe UI",Arial,sans-serif; background:#f4f7fb; color:#122033; }
.container { max-width:1280px; margin:32px auto; padding:0 24px; }
.header { background:linear-gradient(135deg,#0f172a,#7f1d1d); color:white; border-radius:20px; padding:30px 34px; box-shadow:0 14px 34px rgba(15,23,42,.22); }
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
.metric-card.negative { background:#fff1f2; border-color:#fecdd3; }
.metric-value { font-size:24px; font-weight:900; color:#0f172a; }
.metric-label { margin-top:6px; color:#64748b; font-size:14px; }
.action-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:14px; }
.action-card { border-radius:14px; padding:18px; border:1px solid #e2e8f0; background:#f8fafc; line-height:1.55; }
.action-card.critical { background:#fff1f2; border-color:#fecdd3; }
.action-card.warning { background:#fffbeb; border-color:#fde68a; }
.action-card.info { background:#eff6ff; border-color:#bfdbfe; }
.action-title { font-weight:900; margin-bottom:8px; color:#0f172a; }
.action-text { color:#334155; }
.finding-card { border-left:6px solid #ef4444; background:#fff1f2; border-radius:14px; padding:18px 20px; margin-top:14px; }
.recommendation-card { border-left:6px solid #2563eb; background:#eff6ff; border-radius:14px; padding:18px 20px; margin-top:14px; }
.good-card { border-left:6px solid #22c55e; background:#f0fdf4; border-radius:14px; padding:18px 20px; margin-top:14px; }
.finding-title { font-weight:900; font-size:17px; margin-bottom:8px; }
.finding-detail { line-height:1.55; color:#334155; }
.zt-block { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:16px; margin-top:12px; line-height:1.55; }
.table-wrap { overflow-x:auto; border:1px solid #e2e8f0; border-radius:14px; }
table { width:100%; border-collapse:collapse; min-width:950px; }
th { background:#0f172a; color:white; text-align:left; padding:12px 14px; font-size:13px; white-space:nowrap; }
td { border-top:1px solid #e2e8f0; padding:12px 14px; vertical-align:top; font-size:14px; line-height:1.45; }
tr:nth-child(even) td { background:#f8fafc; }
.name { font-weight:700; color:#0f172a; min-width:280px; }
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
    <h2>Plain-English Summary</h2>
    <div class="zt-block">$plainSummary</div>
    <div class="zt-block">$targetState</div>
</section>

<section class="section">
    <h2>Global Administrator Decision</h2>
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

<section class="section">
    <h2>Findings</h2>
    $findingsHtml
</section>

<section class="section">
    <h2>Recommendations</h2>
    $recommendationsHtml
</section>

$activeTable
$normalTable
$nonUserTable
$emergencyTable
$eligibleTable

<div class="footer">
Generated by Zero Trust Validation Platform (ZTVP). Source JSON: $jsonSource
</div>

</div>
</body>
</html>
"@

$htmlFolder = ".\powershell\Reports\Html"
New-Item -ItemType Directory -Path $htmlFolder -Force | Out-Null

$outputPath = Join-Path $htmlFolder "P2-result.html"

Set-Content -Path $outputPath -Value $html -Encoding UTF8

Write-Host "Clear P2 HTML report generated:" -ForegroundColor Green
Write-Host $outputPath -ForegroundColor Cyan

Start-Process $outputPath
