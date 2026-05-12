param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath
)

function ConvertTo-B3HtmlSafe {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode($Value.ToString())
}

function New-B3Metric {
    param([string]$Label, $Value)

    return "<div class='metric'><div class='metric-value'>$(ConvertTo-B3HtmlSafe $Value)</div><div class='metric-label'>$(ConvertTo-B3HtmlSafe $Label)</div></div>"
}

function New-B3Card {
    param([string]$Title, [string]$Text, [string]$Class)

    return "<div class='card $Class'><strong>$(ConvertTo-B3HtmlSafe $Title)</strong><p>$(ConvertTo-B3HtmlSafe $Text)</p></div>"
}

function New-B3GrantRows {
    param($Items)

    $rows = ""

    foreach ($g in @($Items | Where-Object { $null -ne $_ })) {
        $permissionList = (($g.high_risk_scopes | ForEach-Object { $_ }) -join ", ")

        $rows += "<tr>"
        $rows += "<td>$(ConvertTo-B3HtmlSafe $g.client_id)</td>"
        $rows += "<td>$(ConvertTo-B3HtmlSafe $g.resource_id)</td>"
        $rows += "<td>$(ConvertTo-B3HtmlSafe $permissionList)</td>"
        $rows += "<td>$(ConvertTo-B3HtmlSafe $g.action)</td>"
        $rows += "</tr>"
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='4' class='empty'>No tenant-wide high-risk grants detected.</td></tr>"
    }

    return $rows
}

if (-not (Test-Path $JsonPath)) {
    throw "JSON report not found: $JsonPath"
}

$result = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json

if ($result.scenario_id -ne "B3") {
    throw "This converter is only for B3 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$statusClass = "pass"
$decisionTitle = "App consent is governed."
$decisionText = "Admin consent workflow is enabled and no tenant-wide high-risk app grants were detected."

if ($result.status -eq "PARTIAL") {
    $statusClass = "partial"
    $decisionTitle = "App consent needs review."
    $decisionText = "Some high-risk or custom consent items need validation."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "fail"
    $decisionTitle = "Tenant-wide high-risk app grants need review."
    $decisionText = "Admin consent workflow is enabled, but existing high-risk app permissions already granted tenant-wide need cleanup."
}

$plainMeaning = "B3 checks app permission governance. The admin consent workflow is good because users can request app approval instead of approving risky apps directly. The main issue is existing tenant-wide high-risk grants: these are app permissions already approved broadly for the tenant."

$fixFirst = "Start with the tenant-wide high-risk grants below. For each client ID, find the app in Entra Enterprise Applications, confirm the owner and business need, then remove the grant if it is not required."

$metrics = ""
$metrics += New-B3Metric "Decision" $result.status
$metrics += New-B3Metric "Risk" $result.risk
$metrics += New-B3Metric "Admin Consent Workflow" $e.admin_consent_workflow_state
$metrics += New-B3Metric "Admin Reviewers" $e.admin_consent_reviewer_count
$metrics += New-B3Metric "Tenant-Wide High-Risk Grants" $e.tenant_wide_high_risk_delegated_grant_count
$metrics += New-B3Metric "High-Risk Grants Total" $e.high_risk_delegated_grant_count
$metrics += New-B3Metric "Tenant-Wide Grants Total" $e.tenant_wide_delegated_grant_count
$metrics += New-B3Metric "OAuth Grants Total" $e.oauth_delegated_grant_count

$findingsHtml = ""

foreach ($finding in @($result.findings)) {
    $findingsHtml += New-B3Card -Title $finding.title -Text $finding.detail -Class "finding"
}

if ([string]::IsNullOrWhiteSpace($findingsHtml)) {
    $findingsHtml = New-B3Card -Title "No major finding detected" -Text "No major B3 finding was detected." -Class "good"
}

$recommendationsHtml = ""

foreach ($rec in @($result.recommendations)) {
    $recommendationsHtml += New-B3Card -Title $rec.title -Text $rec.detail -Class "recommendation"
}

$tenantWideHighRows = New-B3GrantRows -Items $e.tenant_wide_high_risk_delegated_grants

$title = ConvertTo-B3HtmlSafe $result.scenario_name
$category = ConvertTo-B3HtmlSafe $result.category
$status = ConvertTo-B3HtmlSafe $result.status
$risk = ConvertTo-B3HtmlSafe $result.risk
$timestamp = ConvertTo-B3HtmlSafe $result.timestamp
$summary = ConvertTo-B3HtmlSafe $e.executive_summary
$currentState = ConvertTo-B3HtmlSafe $result.current_state
$target = ConvertTo-B3HtmlSafe $result.zero_trust_target
$gap = ConvertTo-B3HtmlSafe $result.gap_summary
$jsonSource = ConvertTo-B3HtmlSafe (Resolve-Path $JsonPath)

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ZTVP - B3 App Consent Review</title>
<style>
body { margin:0; font-family:Segoe UI,Arial,sans-serif; background:#f4f7fb; color:#122033; }
.container { max-width:1180px; margin:32px auto; padding:0 24px; }
.header { background:#0f172a; color:white; border-radius:18px; padding:28px 32px; }
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
.metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; }
.metric { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:16px; }
.metric-value { font-size:21px; font-weight:900; color:#0f172a; overflow-wrap:anywhere; }
.metric-label { margin-top:6px; color:#64748b; font-size:14px; }
.review-box { background:#eff6ff; border:1px solid #bfdbfe; border-left:7px solid #2563eb; border-radius:14px; padding:18px; line-height:1.55; }
.card { border-radius:14px; padding:16px 18px; margin-top:12px; line-height:1.5; }
.card p { margin:8px 0 0 0; color:#334155; }
.finding { background:#fff7ed; border-left:6px solid #f97316; }
.recommendation { background:#eff6ff; border-left:6px solid #2563eb; }
.good { background:#f0fdf4; border-left:6px solid #22c55e; }
.zt-block { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:16px; margin-top:12px; line-height:1.55; }
.table-wrap { overflow-x:auto; border:1px solid #e2e8f0; border-radius:14px; }
table { width:100%; border-collapse:collapse; min-width:900px; }
th { background:#0f172a; color:white; text-align:left; padding:12px 14px; font-size:13px; white-space:nowrap; }
td { border-top:1px solid #e2e8f0; padding:12px 14px; vertical-align:top; font-size:14px; line-height:1.45; overflow-wrap:anywhere; }
tr:nth-child(even) td { background:#f8fafc; }
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
        <br><br>
        <strong>Summary:</strong> $summary
    </div>
</section>

<section class="section">
    <h2>What B3 Checks</h2>
    <div class="review-box">$(ConvertTo-B3HtmlSafe $plainMeaning)</div>
</section>

<section class="section">
    <h2>Key Numbers</h2>
    <div class="metrics">$metrics</div>
</section>

<section class="section">
    <h2>What To Fix First</h2>
    <div class="review-box">$(ConvertTo-B3HtmlSafe $fixFirst)</div>
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
    <h2>Priority Queue — Tenant-Wide High-Risk Grants</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Client ID</th>
                    <th>Resource ID</th>
                    <th>High-Risk Permissions</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>$tenantWideHighRows</tbody>
        </table>
    </div>
</section>

<section class="section">
    <h2>Zero Trust Comparison</h2>
    <div class="zt-block"><strong>Current State:</strong><br>$currentState</div>
    <div class="zt-block"><strong>Target:</strong><br>$target</div>
    <div class="zt-block"><strong>Gap:</strong><br>$gap</div>
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

$out = Join-Path $outFolder "B3-result.html"
Set-Content -Path $out -Value $html -Encoding UTF8

Write-Host "Clean simple B3 HTML report generated:" -ForegroundColor Green
Write-Host $out -ForegroundColor Cyan
Start-Process $out
