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

function Join-Values {
    param($Values)

    $items = @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if ($items.Count -eq 0) {
        return "None"
    }

    return ($items -join "<br>")
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

function New-RiskyPolicyTable {
    param(
        [string]$Title,
        $Policies,
        [string]$EmptyMessage
    )

    $rows = ""

    foreach ($p in @($Policies)) {
        $name = ConvertTo-HtmlSafe $p.name
        $state = ConvertTo-HtmlSafe $p.state_label

        $users = Join-Values $p.excluded_admin_users
        $roles = Join-Values $p.excluded_admin_roles
        $groups = Join-Values $p.excluded_admin_groups

        $members = @()

        foreach ($m in @($p.excluded_group_admin_members)) {
            $group = $m.groupName
            $admin = $m.admin
            $roleText = ""

            if ($m.roles) {
                $roleText = " [" + (@($m.roles) -join ", ") + "]"
            }

            $members += "$(ConvertTo-HtmlSafe $group) → $(ConvertTo-HtmlSafe $admin)$(ConvertTo-HtmlSafe $roleText)"
        }

        $memberText = "None"
        if ($members.Count -gt 0) {
            $memberText = ($members -join "<br>")
        }

        $rows += @"
<tr>
    <td class="policy-name">$name</td>
    <td>$state</td>
    <td>$users</td>
    <td>$roles</td>
    <td>$groups</td>
    <td>$memberText</td>
</tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='6' class='empty'>$(ConvertTo-HtmlSafe $EmptyMessage)</td></tr>"
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
                    <th>Excluded Privileged Users</th>
                    <th>Excluded Privileged Roles</th>
                    <th>Excluded Groups Containing Admins</th>
                    <th>Admin Members Found Inside Excluded Groups</th>
                </tr>
            </thead>
            <tbody>
                $rows
            </tbody>
        </table>
    </div>
</section>
"@
}

if (-not (Test-Path $JsonPath)) {
    throw "JSON report not found: $JsonPath"
}

$result = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json

if ($result.scenario_id -ne "E2") {
    throw "This converter is only for E2 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$risky = @($e.risky_policy_details)
$enabledRisky = @($risky | Where-Object { $_.enabled -eq $true })
$reportOnlyRisky = @($risky | Where-Object { $_.report_only -eq $true })
$disabledRisky = @($risky | Where-Object { $_.disabled -eq $true })

$statusClass = "status-pass"
$decisionClass = "decision-pass"
$decisionTitle = "Privileged Conditional Access exclusions appear controlled."
$decisionText = "No privileged users, privileged roles, or admin-containing groups were detected as excluded from Conditional Access enforcement."

if ($result.status -eq "PARTIAL") {
    $statusClass = "status-partial"
    $decisionClass = "decision-partial"
    $decisionTitle = "Privileged exclusion posture requires review."
    $decisionText = "Privileged exclusions were found in report-only/disabled policies or some group evidence could not be resolved."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "status-fail"
    $decisionClass = "decision-fail"
    $decisionTitle = "Critical privileged access bypass risk detected."
    $decisionText = "One or more enabled Conditional Access policies exclude privileged users, privileged roles, or groups containing privileged users."
}

$metrics = ""
$metrics += New-MetricCard "CA Policies Assessed" $e.conditional_access_policy_count
$metrics += New-MetricCard "Policies With Exclusions" $e.policy_with_exclusion_count "warning"
$metrics += New-MetricCard "Privileged Users Assessed" $e.privileged_user_count
$metrics += New-MetricCard "Privileged Exclusion Policies" $e.privileged_exclusion_policy_count "warning"
$metrics += New-MetricCard "Enabled Privileged Exclusion Policies" $e.enabled_privileged_exclusion_policy_count "negative"
$metrics += New-MetricCard "Report-only Privileged Exclusion Policies" $e.report_only_privileged_exclusion_policy_count "warning"
$metrics += New-MetricCard "Direct Admin User Exclusions" $e.direct_privileged_user_exclusion_count "negative"
$metrics += New-MetricCard "Admin Role Exclusions" $e.privileged_role_exclusion_count "negative"
$metrics += New-MetricCard "Admin Group Exclusions" $e.admin_group_exclusion_count "negative"
$metrics += New-MetricCard "Unresolved Excluded Groups" $e.unresolved_excluded_group_count "warning"

$findingsHtml = ""
foreach ($finding in @($result.findings)) {
    $findingsHtml += @"
<div class="finding-card">
    <div class="finding-title">$(ConvertTo-HtmlSafe $finding.title)</div>
    <div class="finding-detail">$(ConvertTo-HtmlSafe $finding.detail)</div>
</div>
"@
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

$enabledTable = New-RiskyPolicyTable `
    -Title "Action Queue — Enabled Policies Excluding Privileged Access" `
    -Policies $enabledRisky `
    -EmptyMessage "No enabled policies excluding privileged access detected."

$reportOnlyTable = New-RiskyPolicyTable `
    -Title "Review Queue — Report-Only Policies With Privileged Exclusions" `
    -Policies $reportOnlyRisky `
    -EmptyMessage "No report-only policies with privileged exclusions detected."

$disabledTable = New-RiskyPolicyTable `
    -Title "Cleanup Queue — Disabled Policies With Privileged Exclusions" `
    -Policies $disabledRisky `
    -EmptyMessage "No disabled policies with privileged exclusions detected."

$unresolvedRows = ""

foreach ($g in @($e.unresolved_excluded_groups)) {
    $unresolvedRows += @"
<tr>
    <td>$(ConvertTo-HtmlSafe $g.policyName)</td>
    <td>$(ConvertTo-HtmlSafe $g.groupId)</td>
    <td>$(ConvertTo-HtmlSafe $g.error)</td>
</tr>
"@
}

if ([string]::IsNullOrWhiteSpace($unresolvedRows)) {
    $unresolvedRows = "<tr><td colspan='3' class='empty'>No unresolved excluded groups detected.</td></tr>"
}

$unresolvedTable = @"
<section class="section">
    <h2>Unresolved Excluded Groups</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Policy Name</th>
                    <th>Group ID</th>
                    <th>Error</th>
                </tr>
            </thead>
            <tbody>
                $unresolvedRows
            </tbody>
        </table>
    </div>
</section>
"@

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
<title>ZTVP - E2 Admin Conditional Access Exclusion Review</title>
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
.metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(185px,1fr)); gap:14px; }
.metric-card { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:18px; }
.metric-card.warning { background:#fffbeb; border-color:#fde68a; }
.metric-card.negative { background:#fff1f2; border-color:#fecdd3; }
.metric-value { font-size:28px; font-weight:900; color:#0f172a; }
.metric-label { margin-top:6px; color:#64748b; font-size:14px; }
.finding-card { border-left:6px solid #ef4444; background:#fff1f2; border-radius:14px; padding:18px 20px; margin-top:14px; }
.recommendation-card { border-left:6px solid #2563eb; background:#eff6ff; border-radius:14px; padding:18px 20px; margin-top:14px; }
.finding-title { font-weight:900; font-size:17px; margin-bottom:8px; }
.finding-detail { line-height:1.55; color:#334155; }
.zt-block { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:16px; margin-top:12px; line-height:1.55; }
.table-wrap { overflow-x:auto; border:1px solid #e2e8f0; border-radius:14px; }
table { width:100%; border-collapse:collapse; min-width:1050px; }
th { background:#0f172a; color:white; text-align:left; padding:12px 14px; font-size:13px; white-space:nowrap; }
td { border-top:1px solid #e2e8f0; padding:12px 14px; vertical-align:top; font-size:14px; line-height:1.45; }
tr:nth-child(even) td { background:#f8fafc; }
.policy-name { font-weight:700; color:#0f172a; min-width:280px; }
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
    <h2>Privileged Exclusion Decision</h2>
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
    <h2>Privileged Exclusion Evidence</h2>
    <div class="zt-block">
        These tables show exactly which Conditional Access policies exclude privileged users, privileged roles, or groups containing privileged users.
        Use this section to re-check and justify every exclusion.
    </div>
</section>

$enabledTable
$reportOnlyTable
$disabledTable
$unresolvedTable

<div class="footer">
Generated by Zero Trust Validation Platform (ZTVP). Source JSON: $jsonSource
</div>

</div>
</body>
</html>
"@

$htmlFolder = ".\powershell\Reports\Html"
New-Item -ItemType Directory -Path $htmlFolder -Force | Out-Null

$outputPath = Join-Path $htmlFolder "E2-result.html"

Set-Content -Path $outputPath -Value $html -Encoding UTF8

Write-Host "Detailed E2 HTML report generated:" -ForegroundColor Green
Write-Host $outputPath -ForegroundColor Cyan

Start-Process $outputPath
