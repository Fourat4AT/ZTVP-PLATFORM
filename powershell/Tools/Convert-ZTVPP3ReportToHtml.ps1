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

function Join-ZTVPHtmlValues {
    param($Values)

    $items = @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if ($items.Count -eq 0) {
        return "None"
    }

    return (($items | ForEach-Object { ConvertTo-ZTVPHtmlSafe $_ }) -join "<br>")
}

function New-ZTVPMetricCard {
    param([string]$Label, $Value, [string]$Class = "")

    return @"
<div class="metric-card $Class">
    <div class="metric-value">$(ConvertTo-ZTVPHtmlSafe $Value)</div>
    <div class="metric-label">$(ConvertTo-ZTVPHtmlSafe $Label)</div>
</div>
"@
}

function New-ZTVPActionCard {
    param([string]$Title, [string]$Text, [string]$Class = "")

    return @"
<div class="action-card $Class">
    <div class="action-title">$(ConvertTo-ZTVPHtmlSafe $Title)</div>
    <div class="action-text">$(ConvertTo-ZTVPHtmlSafe $Text)</div>
</div>
"@
}

function New-ZTVPAssignmentTable {
    param([string]$Title, $Items, [string]$EmptyMessage)

    $rows = ""

    foreach ($a in @($Items | Where-Object { $null -ne $_ })) {
        $rows += @"
<tr>
    <td class="name">$(ConvertTo-ZTVPHtmlSafe $a.principalLabel)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $a.principalType)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $a.roleName)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $a.impact)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe (ConvertTo-ZTVPYesNo $a.accountEnabled))</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $a.ownerCount)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $a.assignmentModel)</td>
</tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='7' class='empty'>$(ConvertTo-ZTVPHtmlSafe $EmptyMessage)</td></tr>"
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
                    <th>Role</th>
                    <th>Impact</th>
                    <th>Enabled</th>
                    <th>Owner Count</th>
                    <th>Access Model</th>
                </tr>
            </thead>
            <tbody>$rows</tbody>
        </table>
    </div>
</section>
"@
}

function New-ZTVPPrincipalTable {
    param([string]$Title, $Items, [string]$EmptyMessage)

    $rows = ""

    foreach ($p in @($Items | Where-Object { $null -ne $_ })) {
        $rows += @"
<tr>
    <td class="name">$(ConvertTo-ZTVPHtmlSafe $p.principalLabel)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $p.principalType)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe (ConvertTo-ZTVPYesNo $p.accountEnabled))</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $p.ownerCount)</td>
    <td>$(Join-ZTVPHtmlValues $p.roles)</td>
    <td>$(Join-ZTVPHtmlValues $p.ownerLabels)</td>
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
                    <th>Owner Count</th>
                    <th>Roles</th>
                    <th>Owners</th>
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

if ($result.scenario_id -ne "P3") {
    throw "This converter is only for P3 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$statusClass = "status-pass"
$decisionClass = "decision-pass"
$decisionTitle = "Non-human privileged access looks controlled."
$decisionText = "No risky service principal, app, group, or non-user privileged role exposure was detected."

if ($result.status -eq "PARTIAL") {
    $statusClass = "status-partial"
    $decisionClass = "decision-partial"
    $decisionTitle = "Non-human privileged access needs review."
    $decisionText = "Some service principals, apps, groups, or non-user identities hold privileged roles that need ownership or least-privilege review."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "status-fail"
    $decisionClass = "decision-fail"
    $decisionTitle = "Critical non-human privileged access detected."
    $decisionText = "Service principals or non-user identities have powerful roles such as Global Administrator or permanent critical privileged access."
}

$plainSummary = "This tenant has $($e.non_human_privileged_assignment_count) non-human privileged role assignments, including $($e.service_principal_privileged_assignment_count) service principal assignments, $($e.group_privileged_assignment_count) group assignments, and $($e.non_human_global_admin_count) non-human Global Administrator assignments. The main goal is to remove, reduce, or formally justify privileged roles assigned to apps, service principals, groups, or other non-human identities."

$targetState = "Target state: service principals and apps should not have broad privileged directory roles unless strictly required. Every privileged app should have owners, documented purpose, credential hygiene, monitoring, and least-privilege permissions."

$metrics = ""
$metrics += New-ZTVPMetricCard "Non-Human Privileged Assignments" $e.non_human_privileged_assignment_count "warning"
$metrics += New-ZTVPMetricCard "Service Principal Assignments" $e.service_principal_privileged_assignment_count "warning"
$metrics += New-ZTVPMetricCard "Group Privileged Assignments" $e.group_privileged_assignment_count "warning"
$metrics += New-ZTVPMetricCard "Non-Human Global Admins" $e.non_human_global_admin_count "negative"
$metrics += New-ZTVPMetricCard "Critical Non-Human Assignments" $e.non_human_critical_assignment_count "negative"
$metrics += New-ZTVPMetricCard "High-Impact Non-Human Assignments" $e.non_human_high_impact_assignment_count "warning"
$metrics += New-ZTVPMetricCard "Permanent Non-Human Assignments" $e.permanent_non_human_assignment_count "warning"
$metrics += New-ZTVPMetricCard "No-Owner Service Principals" $e.service_principal_no_owner_count "warning"

$actions = ""
$actions += New-ZTVPActionCard "1. Remove Global Admin from apps" "Service principals and non-user objects should not have Global Administrator unless there is a documented, monitored, and unavoidable reason." "critical"
$actions += New-ZTVPActionCard "2. Reduce app privileges" "Replace broad directory roles with narrower application permissions, workload permissions, or managed identity permissions." "critical"
$actions += New-ZTVPActionCard "3. Assign accountable owners" "Every privileged service principal should have clear owners and a documented business purpose." "warning"
$actions += New-ZTVPActionCard "4. Review credentials and monitoring" "Privileged app credentials and certificates should be monitored, rotated, and protected." "warning"
$actions += New-ZTVPActionCard "5. Review privileged groups" "Groups with privileged roles need controlled membership, owners, and access reviews." "warning"

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

$allNonHumanTable = New-ZTVPAssignmentTable `
    -Title "All Non-Human Privileged Assignments" `
    -Items $e.non_human_privileged_assignments `
    -EmptyMessage "No non-human privileged assignments detected."

$globalAdminTable = New-ZTVPAssignmentTable `
    -Title "Action Queue — Non-Human Global Administrators" `
    -Items $e.non_human_global_admins `
    -EmptyMessage "No non-human Global Administrator assignments detected."

$criticalTable = New-ZTVPAssignmentTable `
    -Title "Action Queue — Critical Non-Human Assignments" `
    -Items $e.non_human_critical_assignments `
    -EmptyMessage "No critical non-human assignments detected."

$servicePrincipalTable = New-ZTVPAssignmentTable `
    -Title "Service Principal Privileged Assignments" `
    -Items $e.service_principal_privileged_assignments `
    -EmptyMessage "No service principal privileged assignments detected."

$groupTable = New-ZTVPAssignmentTable `
    -Title "Group Privileged Assignments" `
    -Items $e.group_privileged_assignments `
    -EmptyMessage "No group privileged assignments detected."

$noOwnerTable = New-ZTVPAssignmentTable `
    -Title "Review Queue — Privileged Service Principals With No Owners" `
    -Items $e.service_principals_with_no_owners `
    -EmptyMessage "No privileged service principals with zero owners detected."

$principalSummaryTable = New-ZTVPPrincipalTable `
    -Title "Non-Human Privileged Principal Summary" `
    -Items $e.non_human_by_principal `
    -EmptyMessage "No non-human privileged principals detected."

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
<title>ZTVP - P3 Privileged Service Principal Role Review</title>
<style>
body { margin:0; font-family:"Segoe UI",Arial,sans-serif; background:#f4f7fb; color:#122033; }
.container { max-width:1280px; margin:32px auto; padding:0 24px; }
.header { background:linear-gradient(135deg,#0f172a,#7c2d12); color:white; border-radius:20px; padding:30px 34px; box-shadow:0 14px 34px rgba(15,23,42,.22); }
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
.action-title { font-weight:900; margin-bottom:8px; color:#0f172a; }
.action-text { color:#334155; }
.finding-card { border-left:6px solid #ef4444; background:#fff1f2; border-radius:14px; padding:18px 20px; margin-top:14px; }
.recommendation-card { border-left:6px solid #2563eb; background:#eff6ff; border-radius:14px; padding:18px 20px; margin-top:14px; }
.good-card { border-left:6px solid #22c55e; background:#f0fdf4; border-radius:14px; padding:18px 20px; margin-top:14px; }
.finding-title { font-weight:900; font-size:17px; margin-bottom:8px; }
.finding-detail { line-height:1.55; color:#334155; }
.zt-block { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:16px; margin-top:12px; line-height:1.55; }
.table-wrap { overflow-x:auto; border:1px solid #e2e8f0; border-radius:14px; }
table { width:100%; border-collapse:collapse; min-width:1000px; }
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
    <h2>Non-Human Privileged Access Decision</h2>
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

$globalAdminTable
$criticalTable
$servicePrincipalTable
$groupTable
$noOwnerTable
$principalSummaryTable
$allNonHumanTable

<div class="footer">
Generated by Zero Trust Validation Platform (ZTVP). Source JSON: $jsonSource
</div>

</div>
</body>
</html>
"@

$htmlFolder = ".\powershell\Reports\Html"
New-Item -ItemType Directory -Path $htmlFolder -Force | Out-Null

$outputPath = Join-Path $htmlFolder "P3-result.html"

Set-Content -Path $outputPath -Value $html -Encoding UTF8

Write-Host "Clear P3 HTML report generated:" -ForegroundColor Green
Write-Host $outputPath -ForegroundColor Cyan

Start-Process $outputPath
