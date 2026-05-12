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

function Join-ZTVPHtmlValues {
    param($Values)

    $items = @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if ($items.Count -eq 0) {
        return "None"
    }

    return (($items | ForEach-Object { ConvertTo-ZTVPHtmlSafe $_ }) -join "<br>")
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

function New-ZTVPAssignmentTable {
    param(
        [string]$Title,
        $Assignments,
        [string]$EmptyMessage
    )

    $rows = ""

    foreach ($a in @($Assignments)) {
        $rows += @"
<tr>
    <td class="name">$(ConvertTo-ZTVPHtmlSafe $a.roleName)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $a.impact)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $a.principalLabel)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $a.principalType)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe (ConvertTo-ZTVPYesNo $a.emergency))</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $a.assignmentModel)</td>
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
                    <th>Role</th>
                    <th>Impact</th>
                    <th>Principal</th>
                    <th>Type</th>
                    <th>Emergency</th>
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
    param(
        [string]$Title,
        $Principals,
        [string]$EmptyMessage
    )

    $rows = ""

    foreach ($p in @($Principals)) {
        $rows += @"
<tr>
    <td class="name">$(ConvertTo-ZTVPHtmlSafe $p.principalLabel)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $p.principalType)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe (ConvertTo-ZTVPYesNo $p.emergency))</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $p.roleCount)</td>
    <td>$(Join-ZTVPHtmlValues $p.roles)</td>
    <td>$(Join-ZTVPHtmlValues $p.eligibleRoles)</td>
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
                    <th>Emergency</th>
                    <th>Role Count</th>
                    <th>Active Roles</th>
                    <th>Eligible Roles</th>
                </tr>
            </thead>
            <tbody>$rows</tbody>
        </table>
    </div>
</section>
"@
}

function New-ZTVPRoleTable {
    param(
        [string]$Title,
        $Roles,
        [string]$EmptyMessage
    )

    $rows = ""

    foreach ($r in @($Roles)) {
        $rows += @"
<tr>
    <td class="name">$(ConvertTo-ZTVPHtmlSafe $r.roleName)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $r.impact)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $r.activeCount)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $r.permanentActiveCount)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $r.timeBoundActiveCount)</td>
    <td>$(ConvertTo-ZTVPHtmlSafe $r.eligibleCount)</td>
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
                    <th>Role</th>
                    <th>Impact</th>
                    <th>Active</th>
                    <th>Permanent Active</th>
                    <th>Time-Bound Active</th>
                    <th>PIM Eligible</th>
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

if ($result.scenario_id -ne "P1") {
    throw "This converter is only for P1 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$statusClass = "status-pass"
$decisionClass = "decision-pass"
$decisionTitle = "Privileged access looks controlled."
$decisionText = "Privileged access is limited and aligned with least privilege and PIM/JIT."

if ($result.status -eq "PARTIAL") {
    $statusClass = "status-partial"
    $decisionClass = "decision-partial"
    $decisionTitle = "Privileged access needs cleanup."
    $decisionText = "Some privileged access is permanent or not fully aligned with PIM/JIT."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "status-fail"
    $decisionClass = "decision-fail"
    $decisionTitle = "Too much permanent privileged access."
    $decisionText = "There are too many permanent Global Administrators or critical roles. Normal admins should move to PIM eligible/time-bound access."
}

$plainSummary = "This tenant has $($e.global_admin_count) Global Administrators, $($e.permanent_critical_assignment_count) permanent critical role assignments, and $($e.active_without_eligibility_count) active privileged assignments without matching PIM eligibility. The main issue is standing privileged access: powerful roles are active all the time instead of being activated only when needed."

$targetState = "Target state: keep only a small number of approved Global Administrators, keep emergency accounts controlled, move normal admins to PIM eligible/time-bound access, and replace Global Administrator with narrower roles whenever possible."

$metrics = ""
$metrics += New-ZTVPMetricCard "Global Administrators" $e.global_admin_count "negative"
$metrics += New-ZTVPMetricCard "Permanent Critical Roles" $e.permanent_critical_assignment_count "negative"
$metrics += New-ZTVPMetricCard "Active Without PIM Eligibility" $e.active_without_eligibility_count "warning"
$metrics += New-ZTVPMetricCard "PIM Eligible Assignments" $e.eligible_privileged_assignment_count
$metrics += New-ZTVPMetricCard "Emergency Admin Accounts" $e.emergency_privileged_principal_count "warning"
$metrics += New-ZTVPMetricCard "Privileged Service Principals" $e.non_user_privileged_principal_count "warning"
$metrics += New-ZTVPMetricCard "JIT / PIM Model" $e.jit_model
$metrics += New-ZTVPMetricCard "Total Active Privileged Assignments" $e.active_privileged_assignment_count "warning"

$actions = ""
$actions += New-ZTVPActionCard "1. Reduce Global Administrators" "Keep only a small number of approved Global Administrators. Delegate narrower roles for daily work." "critical"
$actions += New-ZTVPActionCard "2. Move normal admins to PIM eligible access" "Normal administrators should be eligible and activate roles only when needed, with time limits and approval where appropriate." "critical"
$actions += New-ZTVPActionCard "3. Keep break-glass accounts controlled" "Emergency accounts may keep Global Administrator, but they must be cloud-only, monitored, tested, and not used for daily administration." "warning"
$actions += New-ZTVPActionCard "4. Review privileged service principals" "Confirm why each service principal has a privileged role. Remove or reduce the role if it is not strictly required." "warning"
$actions += New-ZTVPActionCard "5. Apply least privilege" "Use Conditional Access Administrator, Security Administrator, Exchange Administrator, User Administrator, or other narrower roles instead of Global Administrator." "info"

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

$roleTable = New-ZTVPRoleTable `
    -Title "Role Summary — Where the Risk Is" `
    -Roles $e.role_evidence `
    -EmptyMessage "No privileged role evidence detected."

$globalAdminTable = New-ZTVPPrincipalTable `
    -Title "Who Has Global Administrator" `
    -Principals $e.global_admins `
    -EmptyMessage "No Global Administrators detected."

$permanentCriticalTable = New-ZTVPAssignmentTable `
    -Title "Action Queue — Permanent Critical Roles to Convert to PIM" `
    -Assignments $e.permanent_critical_assignments `
    -EmptyMessage "No permanent critical active assignments detected."

$nonUserTable = New-ZTVPPrincipalTable `
    -Title "Action Queue — Privileged Service Principals / Apps" `
    -Principals $e.non_user_privileged_principals `
    -EmptyMessage "No privileged service principals detected."

$emergencyTable = New-ZTVPPrincipalTable `
    -Title "Review Queue — Break-Glass Accounts" `
    -Principals $e.emergency_privileged_principals `
    -EmptyMessage "No emergency privileged accounts detected."

$eligibleTable = New-ZTVPAssignmentTable `
    -Title "Current PIM / Eligible Assignments" `
    -Assignments $e.eligible_assignments `
    -EmptyMessage "No eligible privileged assignments detected."

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
<title>ZTVP - P1 Privileged Role Assignment and JIT Review</title>
<style>
body { margin:0; font-family:"Segoe UI",Arial,sans-serif; background:#f4f7fb; color:#122033; }
.container { max-width:1280px; margin:32px auto; padding:0 24px; }
.header { background:linear-gradient(135deg,#0f172a,#581c87); color:white; border-radius:20px; padding:30px 34px; box-shadow:0 14px 34px rgba(15,23,42,.22); }
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
.name { font-weight:700; color:#0f172a; min-width:260px; }
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
    <h2>Privileged Access Decision</h2>
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

$roleTable
$globalAdminTable
$permanentCriticalTable
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

$outputPath = Join-Path $htmlFolder "P1-result.html"

Set-Content -Path $outputPath -Value $html -Encoding UTF8

Write-Host "Clear P1 HTML report generated:" -ForegroundColor Green
Write-Host $outputPath -ForegroundColor Cyan

Start-Process $outputPath
