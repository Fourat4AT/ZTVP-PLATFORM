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

function Get-DisplayState {
    param($State)

    switch ($State) {
        "enabled" { return "Enabled" }
        "enabledForReportingButNotEnforced" { return "Report-only" }
        "disabled" { return "Disabled" }
        default { return $State }
    }
}

function Get-YesNo {
    param($Value)

    if ($Value -eq $true) {
        return "Yes"
    }

    return "No"
}

function Join-Values {
    param($Values)

    $items = @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if ($items.Count -eq 0) {
        return "None"
    }

    return (($items | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join "<br>")
}

function Get-CleanFindingDetail {
    param([string]$Detail)

    if ([string]::IsNullOrWhiteSpace($Detail)) {
        return ""
    }

    $clean = $Detail

    $patterns = @(
        "Policies:",
        "Sample:",
        "Affected policies:"
    )

    foreach ($pattern in $patterns) {
        $idx = $clean.IndexOf($pattern, [System.StringComparison]::OrdinalIgnoreCase)

        if ($idx -ge 0) {
            $clean = $clean.Substring(0, $idx).Trim()
            $clean = $clean.TrimEnd(".", " ")
            $clean = $clean + ". See the Policy Evidence tables for the full list."
            break
        }
    }

    return $clean
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

function New-E3PolicyTable {
    param(
        [string]$Title,
        $Policies,
        [string]$EmptyMessage,
        [bool]$ShowAlternative = $false
    )

    $rows = ""

    foreach ($p in @($Policies)) {
        $name = ConvertTo-HtmlSafe $p.name
        $state = ConvertTo-HtmlSafe (Get-DisplayState $p.state)
        $purpose = ConvertTo-HtmlSafe $p.purpose
        $severity = ConvertTo-HtmlSafe $p.severity

        $allUsers = ConvertTo-HtmlSafe (Get-YesNo $p.includes_all_users)
        $allApps = ConvertTo-HtmlSafe (Get-YesNo $p.includes_all_apps)
        $adminScope = ConvertTo-HtmlSafe (Get-YesNo $p.is_admin_scope)
        $riskBased = ConvertTo-HtmlSafe (Get-YesNo $p.is_risk_based)

        $alternative = "No"
        if ($p.enabled_alternative_exists -eq $true) {
            $alternative = "Yes"
        }

        $alternativeNames = Join-Values $p.enabled_alternative_policy_names

        if ($ShowAlternative -eq $true) {
            $rows += @"
<tr>
    <td class="policy-name">$name</td>
    <td><span class="pill state-report">$state</span></td>
    <td>$purpose</td>
    <td><span class="severity">$severity</span></td>
    <td>$allUsers</td>
    <td>$allApps</td>
    <td>$adminScope</td>
    <td>$riskBased</td>
    <td>$alternative</td>
    <td>$alternativeNames</td>
</tr>
"@
        }
        else {
            $rows += @"
<tr>
    <td class="policy-name">$name</td>
    <td><span class="pill state-report">$state</span></td>
    <td>$purpose</td>
    <td><span class="severity">$severity</span></td>
    <td>$allUsers</td>
    <td>$allApps</td>
    <td>$adminScope</td>
    <td>$riskBased</td>
</tr>
"@
        }
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        if ($ShowAlternative -eq $true) {
            $rows = "<tr><td colspan='10' class='empty'>$(ConvertTo-HtmlSafe $EmptyMessage)</td></tr>"
        }
        else {
            $rows = "<tr><td colspan='8' class='empty'>$(ConvertTo-HtmlSafe $EmptyMessage)</td></tr>"
        }
    }

    if ($ShowAlternative -eq $true) {
        return @"
<section class="section">
    <h2>$Title</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Policy Name</th>
                    <th>State</th>
                    <th>Security Purpose</th>
                    <th>Severity</th>
                    <th>All Users</th>
                    <th>All Apps</th>
                    <th>Admin Scope</th>
                    <th>Risk Based</th>
                    <th>Enabled Alternative</th>
                    <th>Enabled Alternative Policy</th>
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

    return @"
<section class="section">
    <h2>$Title</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Policy Name</th>
                    <th>State</th>
                    <th>Security Purpose</th>
                    <th>Severity</th>
                    <th>All Users</th>
                    <th>All Apps</th>
                    <th>Admin Scope</th>
                    <th>Risk Based</th>
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

if ($result.scenario_id -ne "E3") {
    throw "This converter is only for E3 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$details = @($e.report_only_important_policy_details)

$criticalWithoutEnabled = @(
    $details | Where-Object {
        $_.severity -eq "CRITICAL" -and $_.enabled_alternative_exists -ne $true
    }
)

$highWithoutEnabled = @(
    $details | Where-Object {
        $_.severity -eq "HIGH" -and $_.enabled_alternative_exists -ne $true
    }
)

$mediumWithoutEnabled = @(
    $details | Where-Object {
        $_.severity -eq "MEDIUM" -and $_.enabled_alternative_exists -ne $true
    }
)

$withAlternatives = @(
    $details | Where-Object {
        $_.enabled_alternative_exists -eq $true
    }
)

$allImportantReportOnly = @($details | Sort-Object severity, purpose, name)

$statusClass = "status-pass"
$decisionClass = "decision-pass"
$decisionTitle = "Report-only dependency posture appears controlled."
$decisionText = "No important Conditional Access protection was found to depend only on report-only mode."

if ($result.status -eq "PARTIAL") {
    $statusClass = "status-partial"
    $decisionClass = "decision-partial"
    $decisionTitle = "Report-only dependency posture requires review."
    $decisionText = "Some important Conditional Access protections remain in report-only mode or appear to be testing variants."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "status-fail"
    $decisionClass = "decision-fail"
    $decisionTitle = "Critical report-only dependency detected."
    $decisionText = "One or more critical Conditional Access protections exist only in report-only mode and are not enforcing protection."
}

$metrics = ""
$metrics += New-MetricCard "CA Policies Assessed" $e.conditional_access_policy_count
$metrics += New-MetricCard "Report-only Policies" $e.report_only_policy_count "warning"
$metrics += New-MetricCard "Important Report-only Policies" $e.important_report_only_policy_count "warning"
$metrics += New-MetricCard "Critical Report-only Policies" $e.critical_report_only_policy_count "negative"
$metrics += New-MetricCard "High Report-only Policies" $e.high_report_only_policy_count "warning"
$metrics += New-MetricCard "Medium Report-only Policies" $e.medium_report_only_policy_count
$metrics += New-MetricCard "Critical Without Enabled Equivalent" $e.critical_dependency_without_enabled_count "negative"
$metrics += New-MetricCard "High Without Enabled Equivalent" $e.high_dependency_without_enabled_count "warning"
$metrics += New-MetricCard "With Enabled Alternative" $e.report_only_with_enabled_alternative_count

$purposeRows = ""

foreach ($p in @($e.purpose_summary)) {
    $purposeRows += @"
<tr>
    <td>$(ConvertTo-HtmlSafe $p.purpose)</td>
    <td>$(ConvertTo-HtmlSafe $p.count)</td>
</tr>
"@
}

if ([string]::IsNullOrWhiteSpace($purposeRows)) {
    $purposeRows = "<tr><td colspan='2' class='empty'>No report-only policy purposes detected.</td></tr>"
}

$purposeTable = @"
<section class="section">
    <h2>Report-Only Purpose Summary</h2>
    <div class="table-wrap small-table">
        <table>
            <thead>
                <tr>
                    <th>Security Purpose</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
                $purposeRows
            </tbody>
        </table>
    </div>
</section>
"@

$findingsHtml = ""
foreach ($finding in @($result.findings)) {
    $findingsHtml += @"
<div class="finding-card">
    <div class="finding-title">$(ConvertTo-HtmlSafe $finding.title)</div>
    <div class="finding-detail">$(ConvertTo-HtmlSafe (Get-CleanFindingDetail $finding.detail))</div>
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

$criticalTable = New-E3PolicyTable `
    -Title "Action Queue — Critical Report-Only Dependencies Without Enabled Equivalent" `
    -Policies $criticalWithoutEnabled `
    -EmptyMessage "No critical report-only dependency without enabled equivalent detected."

$highTable = New-E3PolicyTable `
    -Title "Action Queue — High-Value Report-Only Dependencies Without Enabled Equivalent" `
    -Policies $highWithoutEnabled `
    -EmptyMessage "No high-value report-only dependency without enabled equivalent detected."

$mediumTable = New-E3PolicyTable `
    -Title "Review Queue — Medium Report-Only Dependencies Without Enabled Equivalent" `
    -Policies $mediumWithoutEnabled `
    -EmptyMessage "No medium report-only dependency without enabled equivalent detected."

$alternativeTable = New-E3PolicyTable `
    -Title "Review Queue — Report-Only Policies With Enabled Alternatives" `
    -Policies $withAlternatives `
    -EmptyMessage "No report-only policies with enabled alternatives detected." `
    -ShowAlternative $true

$fullTable = New-E3PolicyTable `
    -Title "Full Important Report-Only Policy Inventory" `
    -Policies $allImportantReportOnly `
    -EmptyMessage "No important report-only policies detected." `
    -ShowAlternative $true

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
<title>ZTVP - E3 Report-Only Policy Dependency Review</title>
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
.metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:14px; }
.metric-card { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:18px; }
.metric-card.warning { background:#fffbeb; border-color:#fde68a; }
.metric-card.negative { background:#fff1f2; border-color:#fecdd3; }
.metric-value { font-size:28px; font-weight:900; color:#0f172a; }
.metric-label { margin-top:6px; color:#64748b; font-size:14px; }
.finding-card { border-left:6px solid #ef4444; background:#fff1f2; border-radius:14px; padding:18px 20px; margin-top:14px; }
.recommendation-card { border-left:6px solid #2563eb; background:#eff6ff; border-radius:14px; padding:18px 20px; margin-top:14px; }
.good-card { border-left:6px solid #22c55e; background:#f0fdf4; border-radius:14px; padding:18px 20px; margin-top:14px; }
.finding-title { font-weight:900; font-size:17px; margin-bottom:8px; }
.finding-detail { line-height:1.55; color:#334155; }
.zt-block { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:16px; margin-top:12px; line-height:1.55; }
.table-wrap { overflow-x:auto; border:1px solid #e2e8f0; border-radius:14px; }
table { width:100%; border-collapse:collapse; min-width:1050px; }
.small-table table { min-width:500px; }
th { background:#0f172a; color:white; text-align:left; padding:12px 14px; font-size:13px; white-space:nowrap; }
td { border-top:1px solid #e2e8f0; padding:12px 14px; vertical-align:top; font-size:14px; line-height:1.45; }
tr:nth-child(even) td { background:#f8fafc; }
.policy-name { font-weight:700; color:#0f172a; min-width:280px; }
.pill { display:inline-block; border-radius:999px; padding:5px 10px; font-weight:800; font-size:12px; white-space:nowrap; }
.state-report { background:#fef3c7; color:#92400e; }
.severity { font-weight:900; }
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
    <h2>Report-Only Dependency Decision</h2>
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
    <h2>Policy Evidence</h2>
    <div class="zt-block">
        These tables show which important Conditional Access controls are still report-only, whether an enabled alternative exists, and which protections should be prioritized for enforcement.
    </div>
</section>

$purposeTable
$criticalTable
$highTable
$mediumTable
$alternativeTable
$fullTable

<div class="footer">
Generated by Zero Trust Validation Platform (ZTVP). Source JSON: $jsonSource
</div>

</div>
</body>
</html>
"@

$htmlFolder = ".\powershell\Reports\Html"
New-Item -ItemType Directory -Path $htmlFolder -Force | Out-Null

$outputPath = Join-Path $htmlFolder "E3-result.html"

Set-Content -Path $outputPath -Value $html -Encoding UTF8

Write-Host "Detailed E3 HTML report generated:" -ForegroundColor Green
Write-Host $outputPath -ForegroundColor Cyan

Start-Process $outputPath
