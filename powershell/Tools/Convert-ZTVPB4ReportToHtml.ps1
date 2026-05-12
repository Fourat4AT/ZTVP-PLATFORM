param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath
)

function ConvertTo-B4HtmlSafe {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode($Value.ToString())
}

function New-B4Metric {
    param([string]$Label, $Value)

    return "<div class='metric'><div class='metric-value'>$(ConvertTo-B4HtmlSafe $Value)</div><div class='metric-label'>$(ConvertTo-B4HtmlSafe $Label)</div></div>"
}

function New-B4Card {
    param([string]$Title, [string]$Text, [string]$Class)

    return "<div class='card $Class'><strong>$(ConvertTo-B4HtmlSafe $Title)</strong><p>$(ConvertTo-B4HtmlSafe $Text)</p></div>"
}

function New-B4MethodRows {
    param($Items)

    $rows = ""

    foreach ($m in @($Items | Where-Object { $null -ne $_ })) {
        $rows += "<tr>"
        $rows += "<td>$(ConvertTo-B4HtmlSafe $m.id)</td>"
        $rows += "<td>$(ConvertTo-B4HtmlSafe $m.state)</td>"
        $rows += "<td>$(ConvertTo-B4HtmlSafe $m.method_class)</td>"
        $rows += "<td>$(ConvertTo-B4HtmlSafe $m.review_reason)</td>"
        $rows += "</tr>"
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='4' class='empty'>No method entries were returned.</td></tr>"
    }

    return $rows
}

if (-not (Test-Path $JsonPath)) {
    throw "JSON report not found: $JsonPath"
}

$result = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json

if ($result.scenario_id -ne "B4") {
    throw "This converter is only for B4 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$statusClass = "pass"
$decisionTitle = "Password and account recovery baseline appears controlled."
$decisionText = "SSPR and authentication method evidence are acceptable."

if ($result.status -eq "PARTIAL") {
    $statusClass = "partial"
    $decisionTitle = "Password and account recovery baseline needs review."
    $decisionText = "SSPR is allowed, but authentication method evidence or weaker methods need validation."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "fail"
    $decisionTitle = "Password and account recovery baseline has a gap."
    $decisionText = "SSPR or recovery control posture is not adequately confirmed."
}

$meaning = "B4 checks password and account recovery posture. It confirms whether SSPR is allowed and whether authentication method policy evidence is available. It also highlights strong methods and weaker recovery methods that need review."

$fixFirst = "SSPR is enabled and authentication methods were assessed. Keep weaker recovery methods such as SMS, voice, and email disabled or tightly justified. Validate SSPR registration coverage, recovery methods, and helpdesk recovery process."

$metrics = ""
$metrics += New-B4Metric "Decision" $result.status
$metrics += New-B4Metric "Risk" $result.risk
$metrics += New-B4Metric "SSPR Allowed" $e.users_allowed_to_use_sspr
$metrics += New-B4Metric "Auth Methods Policy Readable" $e.authentication_methods_policy_readable
$metrics += New-B4Metric "Methods Assessed" $e.authentication_method_count
$metrics += New-B4Metric "Enabled Methods" $e.enabled_authentication_method_count
$metrics += New-B4Metric "Strong Methods" $e.enabled_strong_authentication_method_count
$metrics += New-B4Metric "Methods To Review" $e.enabled_review_authentication_method_count

$findingsHtml = ""

foreach ($finding in @($result.findings)) {
    $findingsHtml += New-B4Card -Title $finding.title -Text $finding.detail -Class "finding"
}

if ([string]::IsNullOrWhiteSpace($findingsHtml)) {
    $findingsHtml = New-B4Card -Title "No major finding detected" -Text "No major B4 finding was detected." -Class "good"
}

$recommendationsHtml = ""

foreach ($rec in @($result.recommendations)) {
    $recommendationsHtml += New-B4Card -Title $rec.title -Text $rec.detail -Class "recommendation"
}

$methodRows = New-B4MethodRows -Items $e.authentication_methods

$title = ConvertTo-B4HtmlSafe $result.scenario_name
$category = ConvertTo-B4HtmlSafe $result.category
$status = ConvertTo-B4HtmlSafe $result.status
$risk = ConvertTo-B4HtmlSafe $result.risk
$timestamp = ConvertTo-B4HtmlSafe $result.timestamp
$summary = ConvertTo-B4HtmlSafe $e.executive_summary
$currentState = ConvertTo-B4HtmlSafe $result.current_state
$target = ConvertTo-B4HtmlSafe $result.zero_trust_target
$gap = ConvertTo-B4HtmlSafe $result.gap_summary
$jsonSource = ConvertTo-B4HtmlSafe (Resolve-Path $JsonPath)

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ZTVP - B4 Password and Account Protection Review</title>
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
table { width:100%; border-collapse:collapse; min-width:850px; }
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
    <h2>What B4 Checks</h2>
    <div class="review-box">$(ConvertTo-B4HtmlSafe $meaning)</div>
</section>

<section class="section">
    <h2>Key Numbers</h2>
    <div class="metrics">$metrics</div>
</section>

<section class="section">
    <h2>What To Fix First</h2>
    <div class="review-box">$(ConvertTo-B4HtmlSafe $fixFirst)</div>
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
    <h2>Authentication Methods Reviewed</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Method</th>
                    <th>State</th>
                    <th>Class</th>
                    <th>Meaning</th>
                </tr>
            </thead>
            <tbody>$methodRows</tbody>
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

$out = Join-Path $outFolder "B4-result.html"
Set-Content -Path $out -Value $html -Encoding UTF8

Write-Host "Clean B4 HTML report generated:" -ForegroundColor Green
Write-Host $out -ForegroundColor Cyan
Start-Process $out

