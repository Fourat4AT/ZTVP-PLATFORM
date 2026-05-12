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

    return (($items | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join "<br>")
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

function New-LocationTable {
    param(
        [string]$Title,
        $Locations,
        [string]$EmptyMessage
    )

    $rows = ""

    foreach ($l in @($Locations)) {
        $rows += @"
<tr>
    <td class="policy-name">$(ConvertTo-HtmlSafe $l.name)</td>
    <td>$(ConvertTo-HtmlSafe $l.type)</td>
    <td>$(ConvertTo-HtmlSafe (Get-YesNo $l.trusted))</td>
    <td>$(ConvertTo-HtmlSafe $l.ip_risk)</td>
    <td>$(Join-Values $l.ip_ranges)</td>
    <td>$(Join-Values $l.countries)</td>
    <td>$(ConvertTo-HtmlSafe (Get-YesNo $l.include_unknown_countries))</td>
</tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='8' class='empty'>$(ConvertTo-HtmlSafe $EmptyMessage)</td></tr>"
    }

    return @"
<section class="section">
    <h2>$Title</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Trusted</th>
                    <th>IP Risk</th>
                    <th>IP Ranges</th>
                    <th>Countries</th>
                    <th>Includes Unknown</th>
                </tr>
            </thead>
            <tbody>$rows</tbody>
        </table>
    </div>
</section>
"@
}

function New-PolicyUsageTable {
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
    <td>$(ConvertTo-HtmlSafe (Get-YesNo $p.is_block_policy))</td>
    <td>$(Join-Values $p.include_location_names)</td>
    <td>$(Join-Values $p.exclude_location_names)</td>
    <td>$(Join-Values $p.excluded_country_locations)</td>
    <td>$(ConvertTo-HtmlSafe (Get-YesNo $p.references_all_trusted_but_none_exist))</td>
    <td>$(ConvertTo-HtmlSafe (Get-YesNo $p.references_all_trusted_but_only_empty_exist))</td>
</tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='8' class='empty'>$(ConvertTo-HtmlSafe $EmptyMessage)</td></tr>"
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
                    <th>Block Policy</th>
                    <th>Included Locations</th>
                    <th>Excluded Locations</th>
                    <th>Allowed Country/Location</th>
                    <th>References All Trusted But None Exist</th>
                    <th>References All Trusted But Only Empty Trusted IPs</th>
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

if ($result.scenario_id -ne "E4") {
    throw "This converter is only for E4 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$statusClass = "status-pass"
$decisionClass = "decision-pass"
$decisionTitle = "Named location posture appears controlled."
$decisionText = "The tenant location strategy appears intentional and no major named-location issue was detected."

if ($result.status -eq "PARTIAL") {
    $statusClass = "status-partial"
    $decisionClass = "decision-partial"
    $decisionTitle = "Named location posture requires review."
    $decisionText = "Country-based controls may exist, but named-location cleanup, trusted-location references, or IP strategy should be reviewed."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "status-fail"
    $decisionClass = "decision-fail"
    $decisionTitle = "Critical trusted network risk detected."
    $decisionText = "One or more trusted named locations contain extremely broad IP ranges or create major access bypass risk."
}

$metrics = ""
$metrics += New-MetricCard "Named Locations" $e.named_location_count
$metrics += New-MetricCard "Country Strategy" $e.country_strategy
$metrics += New-MetricCard "IP Strategy" $e.ip_strategy
$metrics += New-MetricCard "Trusted Locations" $e.trusted_location_count
$metrics += New-MetricCard "Populated Trusted Locations" $e.trusted_non_empty_location_count
$metrics += New-MetricCard "Empty Trusted IP Locations" $e.trusted_empty_ip_location_count "warning"
$metrics += New-MetricCard "IP Named Locations" $e.ip_named_location_count
$metrics += New-MetricCard "Empty IP Named Locations" $e.empty_ip_named_location_count "warning"
$metrics += New-MetricCard "Country Locations" $e.country_named_location_count
$metrics += New-MetricCard "Enabled Country Block Policies" $e.enabled_country_block_policy_count
$metrics += New-MetricCard "Report-only Country Block Policies" $e.report_only_country_block_policy_count "warning"
$metrics += New-MetricCard "Policies Referencing All Trusted But None Exist" $e.enabled_policy_referencing_all_trusted_but_none_count "warning"
$metrics += New-MetricCard "Policies Referencing All Trusted With Empty Trusted IPs" $e.enabled_policy_referencing_all_trusted_but_only_empty_count "warning"

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

$enabledCountryTable = New-PolicyUsageTable `
    -Title "Validated Control — Enabled Country-Based Block Policies" `
    -Policies $e.enabled_country_block_policies `
    -EmptyMessage "No enabled country-based block policy detected."

$reportOnlyCountryTable = New-PolicyUsageTable `
    -Title "Review Queue — Report-Only Country-Based Block Policies" `
    -Policies $e.report_only_country_block_policies `
    -EmptyMessage "No report-only country-based block policy detected."

$emptyIpTable = New-LocationTable `
    -Title "Action Queue — IP Named Locations With No IP Ranges" `
    -Locations $e.empty_ip_named_locations `
    -EmptyMessage "No empty IP named locations detected."

$allTrustedNoneTable = New-PolicyUsageTable `
    -Title "Review Queue — Policies Referencing All Trusted Locations While None Exist" `
    -Policies $e.enabled_policies_referencing_all_trusted_but_none `
    -EmptyMessage "No enabled policies reference All trusted locations while no trusted locations exist."

$allTrustedOnlyEmptyTable = New-PolicyUsageTable `
    -Title "Review Queue — Policies Referencing All Trusted Locations While Trusted IP Locations Are Empty" `
    -Policies $e.enabled_policies_referencing_all_trusted_but_only_empty `
    -EmptyMessage "No enabled policies reference All trusted locations while trusted IP locations are empty."

$allLocationTable = New-LocationTable `
    -Title "Full Named Location Inventory" `
    -Locations $e.named_locations `
    -EmptyMessage "No named locations detected."

$allPolicyUsageTable = New-PolicyUsageTable `
    -Title "Full Policy Location Usage Inventory" `
    -Policies $e.policy_location_usage `
    -EmptyMessage "No policies using named locations detected."

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
<title>ZTVP - E4 Named Location and Trusted Network Review</title>
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
table { width:100%; border-collapse:collapse; min-width:1000px; }
th { background:#0f172a; color:white; text-align:left; padding:12px 14px; font-size:13px; white-space:nowrap; }
td { border-top:1px solid #e2e8f0; padding:12px 14px; vertical-align:top; font-size:14px; line-height:1.45; }
tr:nth-child(even) td { background:#f8fafc; }
.policy-name { font-weight:700; color:#0f172a; min-width:260px; }
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
    <h2>Named Location Strategy Decision</h2>
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
    <h2>Named Location Evidence</h2>
    <div class="zt-block">
        This scenario validates the tenant location strategy. Country-based controls are valid when the goal is to block access outside an approved country.
        IP named locations are optional and should only be populated when the company has stable office, VPN, or admin workstation public egress IPs.
    </div>
</section>

$enabledCountryTable
$reportOnlyCountryTable
$emptyIpTable
$allTrustedNoneTable
$allTrustedOnlyEmptyTable
$allLocationTable
$allPolicyUsageTable

<div class="footer">
Generated by Zero Trust Validation Platform (ZTVP). Source JSON: $jsonSource
</div>

</div>
</body>
</html>
"@

$htmlFolder = ".\powershell\Reports\Html"
New-Item -ItemType Directory -Path $htmlFolder -Force | Out-Null

$outputPath = Join-Path $htmlFolder "E4-result.html"

Set-Content -Path $outputPath -Value $html -Encoding UTF8

Write-Host "Detailed E4 HTML report generated:" -ForegroundColor Green
Write-Host $outputPath -ForegroundColor Cyan

Start-Process $outputPath

