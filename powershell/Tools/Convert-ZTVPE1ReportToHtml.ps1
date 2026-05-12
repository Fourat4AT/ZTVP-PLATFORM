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

function Get-CleanFindingDetail {
    param([string]$Detail)

    if ([string]::IsNullOrWhiteSpace($Detail)) {
        return ""
    }

    $clean = $Detail

    $patterns = @(
        "Affected policies:",
        "Policies:",
        "Affected users:",
        "Affected accounts:",
        "Affected members:"
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

    $safeLabel = ConvertTo-HtmlSafe $Label
    $safeValue = ConvertTo-HtmlSafe $Value

    return @"
<div class="metric-card $Class">
    <div class="metric-value">$safeValue</div>
    <div class="metric-label">$safeLabel</div>
</div>
"@
}

function New-PolicyTable {
    param(
        [string]$Title,
        $Policies,
        [string]$EmptyMessage,
        [bool]$FullInventory = $false
    )

    $rows = ""

    foreach ($p in @($Policies)) {
        $name = ConvertTo-HtmlSafe $p.name
        $state = ConvertTo-HtmlSafe (Get-DisplayState $p.state)
        $grant = ConvertTo-HtmlSafe $p.grant_type
        $allUsers = ConvertTo-HtmlSafe (Get-YesNo $p.includes_all_users)
        $allApps = ConvertTo-HtmlSafe (Get-YesNo $p.includes_all_apps)

        $includeScope = ConvertTo-HtmlSafe ("Users: {0}, Groups: {1}, Roles: {2}" -f `
            $p.include_users_count, `
            $p.include_groups_count, `
            $p.include_roles_count)

        $exclusions = ConvertTo-HtmlSafe ("Users: {0}, Groups: {1}, Roles: {2}" -f `
            $p.excluded_users_count, `
            $p.excluded_groups_count, `
            $p.excluded_roles_count)

        $stateClass = "state-neutral"
        if ($p.enabled -eq $true) {
            $stateClass = "state-enabled"
        }
        elseif ($p.report_only -eq $true) {
            $stateClass = "state-report"
        }
        elseif ($p.disabled -eq $true) {
            $stateClass = "state-disabled"
        }

        $rows += @"
<tr>
    <td class="policy-name">$name</td>
    <td><span class="pill $stateClass">$state</span></td>
    <td>$grant</td>
    <td>$allUsers</td>
    <td>$allApps</td>
    <td>$includeScope</td>
    <td>$exclusions</td>
</tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $safeEmpty = ConvertTo-HtmlSafe $EmptyMessage

        $rows = @"
<tr>
    <td colspan="7" class="empty">$safeEmpty</td>
</tr>
"@
    }

    $note = ""
    if ($FullInventory -eq $true) {
        $note = '<p class="muted">This is the full Conditional Access policy inventory collected by E1 for validation.</p>'
    }

    return @"
<section class="section">
    <h2>$Title</h2>
    $note
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Policy Name</th>
                    <th>State</th>
                    <th>Grant / Control Type</th>
                    <th>All Users</th>
                    <th>All Apps</th>
                    <th>Included Scope</th>
                    <th>Exclusions</th>
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

if ($result.scenario_id -ne "E1") {
    throw "This converter is only for E1 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence
$policies = @($e.assessed_policies)

$reportOnlyPolicies = @($policies | Where-Object { $_.report_only -eq $true })
$disabledPolicies = @($policies | Where-Object { $_.disabled -eq $true })
$enabledExclusionPolicies = @($policies | Where-Object { $_.enabled -eq $true -and $_.has_exclusions -eq $true })
$enabledPolicies = @($policies | Where-Object { $_.enabled -eq $true })
$allPolicies = @($policies | Sort-Object state, name)

$statusClass = "status-pass"
$decisionClass = "decision-pass"
$decisionTitle = "Conditional Access governance appears controlled."
$decisionText = "Enabled policies are present and no major policy-state governance issue was detected."

if ($result.status -eq "PARTIAL") {
    $statusClass = "status-partial"
    $decisionClass = "decision-partial"
    $decisionTitle = "Conditional Access governance is partially controlled."
    $decisionText = "Enabled policies exist, but report-only policies or exclusions reduce enforcement confidence."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "status-fail"
    $decisionClass = "decision-fail"
    $decisionTitle = "Conditional Access governance requires urgent remediation."
    $decisionText = "The platform could not confirm effective Conditional Access enforcement."
}

$metrics = ""
$metrics += New-MetricCard "Total CA Policies" $e.conditional_access_policy_count
$metrics += New-MetricCard "Enabled Policies" "$($e.enabled_policy_count) ($($e.enabled_policy_percent)%)" "positive"
$metrics += New-MetricCard "Report-only Policies" "$($e.report_only_policy_count) ($($e.report_only_policy_percent)%)" "warning"
$metrics += New-MetricCard "Disabled Policies" "$($e.disabled_policy_count) ($($e.disabled_policy_percent)%)" "negative"
$metrics += New-MetricCard "Policies With Exclusions" $e.policy_with_exclusion_count "warning"
$metrics += New-MetricCard "Enabled With Exclusions" $e.enabled_policy_with_exclusion_count "warning"

$findingsHtml = ""
foreach ($finding in @($result.findings)) {
    $title = ConvertTo-HtmlSafe $finding.title
    $detail = ConvertTo-HtmlSafe (Get-CleanFindingDetail $finding.detail)

    $findingsHtml += @"
<div class="finding-card">
    <div class="finding-title">$title</div>
    <div class="finding-detail">$detail</div>
</div>
"@
}

if ([string]::IsNullOrWhiteSpace($findingsHtml)) {
    $findingsHtml = '<div class="good-card">No findings detected.</div>'
}

$recommendationsHtml = ""
foreach ($rec in @($result.recommendations)) {
    $title = ConvertTo-HtmlSafe $rec.title
    $detail = ConvertTo-HtmlSafe $rec.detail

    $recommendationsHtml += @"
<div class="recommendation-card">
    <div class="finding-title">$title</div>
    <div class="finding-detail">$detail</div>
</div>
"@
}

if ([string]::IsNullOrWhiteSpace($recommendationsHtml)) {
    $recommendationsHtml = '<div class="good-card">No recommendations required.</div>'
}

$reportOnlyTable = New-PolicyTable `
    -Title "Action Queue — Report-Only Policies" `
    -Policies $reportOnlyPolicies `
    -EmptyMessage "No report-only Conditional Access policies detected."

$disabledTable = New-PolicyTable `
    -Title "Action Queue — Disabled Policies" `
    -Policies $disabledPolicies `
    -EmptyMessage "No disabled Conditional Access policies detected."

$exclusionTable = New-PolicyTable `
    -Title "Action Queue — Enabled Policies With Exclusions" `
    -Policies $enabledExclusionPolicies `
    -EmptyMessage "No enabled Conditional Access policies with exclusions detected."

$enabledTable = New-PolicyTable `
    -Title "Reference — Enabled Policy Inventory" `
    -Policies $enabledPolicies `
    -EmptyMessage "No enabled Conditional Access policies detected."

$fullInventoryTable = New-PolicyTable `
    -Title "Full Conditional Access Policy Inventory" `
    -Policies $allPolicies `
    -EmptyMessage "No Conditional Access policies detected." `
    -FullInventory $true

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
<title>ZTVP - E1 Conditional Access Policy State Review</title>
<style>
    body {
        margin: 0;
        padding: 0;
        font-family: "Segoe UI", Arial, sans-serif;
        background: #f4f7fb;
        color: #122033;
    }

    .container {
        max-width: 1280px;
        margin: 32px auto;
        padding: 0 24px;
    }

    .header {
        background: linear-gradient(135deg, #0f172a, #1e3a8a);
        color: white;
        border-radius: 20px;
        padding: 30px 34px;
        box-shadow: 0 14px 34px rgba(15, 23, 42, 0.22);
    }

    .header h1 {
        margin: 0;
        font-size: 31px;
        letter-spacing: -0.3px;
    }

    .header p {
        margin: 8px 0 0 0;
        opacity: 0.85;
    }

    .badge-row {
        margin-top: 20px;
        display: flex;
        gap: 12px;
        flex-wrap: wrap;
    }

    .badge {
        padding: 8px 14px;
        border-radius: 999px;
        font-weight: 800;
        font-size: 13px;
    }

    .status-pass { background: #dcfce7; color: #166534; }
    .status-partial { background: #fef3c7; color: #92400e; }
    .status-fail { background: #fee2e2; color: #991b1b; }

    .section {
        background: white;
        border-radius: 18px;
        padding: 24px;
        margin-top: 22px;
        box-shadow: 0 7px 22px rgba(15, 23, 42, 0.08);
    }

    .section h2 {
        margin: 0 0 16px 0;
        font-size: 22px;
    }

    .decision {
        border-radius: 16px;
        padding: 20px;
        line-height: 1.55;
    }

    .decision-pass { border-left: 7px solid #22c55e; background: #f0fdf4; }
    .decision-partial { border-left: 7px solid #f59e0b; background: #fffbeb; }
    .decision-fail { border-left: 7px solid #ef4444; background: #fff1f2; }

    .decision strong {
        display: block;
        font-size: 18px;
        margin-bottom: 8px;
    }

    .metrics {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(185px, 1fr));
        gap: 14px;
    }

    .metric-card {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 14px;
        padding: 18px;
    }

    .metric-card.warning { background: #fffbeb; border-color: #fde68a; }
    .metric-card.positive { background: #f0fdf4; border-color: #bbf7d0; }
    .metric-card.negative { background: #fff1f2; border-color: #fecdd3; }

    .metric-value {
        font-size: 28px;
        font-weight: 900;
        color: #0f172a;
    }

    .metric-label {
        margin-top: 6px;
        color: #64748b;
        font-size: 14px;
    }

    .finding-card {
        border-left: 6px solid #ef4444;
        background: #fff1f2;
        border-radius: 14px;
        padding: 18px 20px;
        margin-top: 14px;
    }

    .recommendation-card {
        border-left: 6px solid #2563eb;
        background: #eff6ff;
        border-radius: 14px;
        padding: 18px 20px;
        margin-top: 14px;
    }

    .good-card {
        border-left: 6px solid #22c55e;
        background: #f0fdf4;
        border-radius: 14px;
        padding: 18px 20px;
        margin-top: 14px;
    }

    .finding-title {
        font-weight: 900;
        font-size: 17px;
        margin-bottom: 8px;
    }

    .finding-detail {
        line-height: 1.55;
        color: #334155;
    }

    .zt-block {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 14px;
        padding: 16px;
        margin-top: 12px;
        line-height: 1.55;
    }

    .muted {
        color: #64748b;
        margin-top: -4px;
    }

    .table-wrap {
        overflow-x: auto;
        border: 1px solid #e2e8f0;
        border-radius: 14px;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        min-width: 1050px;
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

    .policy-name {
        font-weight: 700;
        color: #0f172a;
        min-width: 280px;
    }

    .pill {
        display: inline-block;
        border-radius: 999px;
        padding: 5px 10px;
        font-weight: 800;
        font-size: 12px;
        white-space: nowrap;
    }

    .state-enabled { background: #dcfce7; color: #166534; }
    .state-report { background: #fef3c7; color: #92400e; }
    .state-disabled { background: #fee2e2; color: #991b1b; }
    .state-neutral { background: #e2e8f0; color: #334155; }

    .empty {
        color: #64748b;
        font-style: italic;
    }

    .footer {
        color: #64748b;
        font-size: 13px;
        margin: 24px 0;
        text-align: center;
    }
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
        <h2>Governance Decision</h2>
        <div class="decision $decisionClass">
            <strong>$decisionTitle</strong>
            $decisionText
        </div>
    </section>

    <section class="section">
        <h2>Key Metrics</h2>
        <div class="metrics">
            $metrics
        </div>
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
            The tables below preserve the full Conditional Access evidence. 
            Action queues show the policies requiring review, while the full inventory keeps all collected policies visible for audit and validation.
        </div>
    </section>

    $reportOnlyTable
    $disabledTable
    $exclusionTable
    $enabledTable
    $fullInventoryTable

    <div class="footer">
        Generated by Zero Trust Validation Platform (ZTVP). Source JSON: $jsonSource
    </div>

</div>
</body>
</html>
"@

$htmlFolder = ".\powershell\Reports\Html"

if (-not (Test-Path $htmlFolder)) {
    New-Item -ItemType Directory -Path $htmlFolder -Force | Out-Null
}

$outputPath = Join-Path $htmlFolder "E1-result.html"

Set-Content -Path $outputPath -Value $html -Encoding UTF8

Write-Host "Detailed professional E1 HTML report generated:" -ForegroundColor Green
Write-Host $outputPath -ForegroundColor Cyan

Start-Process $outputPath
