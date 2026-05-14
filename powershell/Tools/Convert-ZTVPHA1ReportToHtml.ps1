param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath
)

function ConvertTo-HA1HtmlSafe {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode($Value.ToString())
}

function New-HA1Metric {
    param([string]$Label, $Value)

    return "<div class='metric'><div class='metric-value'>$(ConvertTo-HA1HtmlSafe $Value)</div><div class='metric-label'>$(ConvertTo-HA1HtmlSafe $Label)</div></div>"
}

function New-HA1Card {
    param([string]$Title, [string]$Text, [string]$Class)

    return "<div class='card $Class'><strong>$(ConvertTo-HA1HtmlSafe $Title)</strong><p>$(ConvertTo-HA1HtmlSafe $Text)</p></div>"
}

function New-HA1UserRows {
    param($Items)

    $rows = ""

    foreach ($u in @($Items | Where-Object { $null -ne $_ } | Select-Object -First 80)) {
        $methodText = ""

        if ($u.method_types) {
            $methodText = (($u.method_types | ForEach-Object { $_ }) -join ", ")
        }

        $rows += "<tr>"
        $rows += "<td>$(ConvertTo-HA1HtmlSafe $u.user_principal_name)</td>"
        $rows += "<td>$(ConvertTo-HA1HtmlSafe $u.onprem_sam_account_name)</td>"
        $rows += "<td>$(ConvertTo-HA1HtmlSafe $u.strong_method_count)</td>"
        $rows += "<td>$(ConvertTo-HA1HtmlSafe $u.weak_or_recovery_method_count)</td>"
        $rows += "<td>$(ConvertTo-HA1HtmlSafe $u.method_count)</td>"
        $rows += "<td>$(ConvertTo-HA1HtmlSafe $methodText)</td>"
        $rows += "</tr>"
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='6' class='empty'>No users in this section.</td></tr>"
    }

    return $rows
}

if (-not (Test-Path $JsonPath)) {
    throw "JSON report not found: $JsonPath"
}

$result = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json

if ($result.scenario_id -ne "H-A1") {
    throw "This converter is only for H-A1 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$statusClass = "pass"
$decisionTitle = "Hybrid authentication method alignment appears controlled."
$decisionText = "Enabled synced users have strong cloud authentication method evidence."

if ($result.status -eq "PARTIAL") {
    $statusClass = "partial"
    $decisionTitle = "Hybrid authentication method alignment needs review."
    $decisionText = "Some enabled synced users are missing strong cloud authentication method evidence."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "fail"
    $decisionTitle = "Hybrid authentication method alignment has high-risk exposure."
    $decisionText = "Hybrid authentication evidence or method posture requires urgent review."
}

$meaning = "H-A1 checks enabled users synced from on-prem Active Directory to Entra ID. It reads their cloud authentication methods and highlights synced users that do not have strong method evidence."

$fixFirst = "Start with privileged and high-impact synced users. Register strong methods such as Microsoft Authenticator, FIDO2/passkeys, Windows Hello for Business, Temporary Access Pass, or certificate-based authentication. Avoid leaving synced users with only password, SMS, voice, email, or recovery-style evidence."

$metrics = ""
$metrics += New-HA1Metric "Decision" $result.status
$metrics += New-HA1Metric "Risk" $result.risk
$metrics += New-HA1Metric "Synced Users Assessed" $e.synced_user_count
$metrics += New-HA1Metric "With Strong Methods" $e.users_with_strong_method_count
$metrics += New-HA1Metric "Missing Strong Methods" $e.users_missing_strong_method_count
$metrics += New-HA1Metric "Only Weak/Recovery Evidence" $e.users_only_weak_or_recovery_method_count
$metrics += New-HA1Metric "Method Read Errors" $e.method_read_error_count

$findingsHtml = ""

foreach ($finding in @($result.findings)) {
    $findingsHtml += New-HA1Card -Title $finding.title -Text $finding.detail -Class "finding"
}

if ([string]::IsNullOrWhiteSpace($findingsHtml)) {
    $findingsHtml = New-HA1Card -Title "No major finding detected" -Text "No major H-A1 finding was detected." -Class "good"
}

$recommendationsHtml = ""

foreach ($rec in @($result.recommendations)) {
    $recommendationsHtml += New-HA1Card -Title $rec.title -Text $rec.detail -Class "recommendation"
}

$missingRows = New-HA1UserRows -Items $e.users_missing_strong_methods
$strongRows = New-HA1UserRows -Items $e.users_with_strong_methods

$title = ConvertTo-HA1HtmlSafe $result.scenario_name
$category = ConvertTo-HA1HtmlSafe $result.category
$status = ConvertTo-HA1HtmlSafe $result.status
$risk = ConvertTo-HA1HtmlSafe $result.risk
$timestamp = ConvertTo-HA1HtmlSafe $result.timestamp
$summary = ConvertTo-HA1HtmlSafe $e.executive_summary
$currentState = ConvertTo-HA1HtmlSafe $result.current_state
$target = ConvertTo-HA1HtmlSafe $result.zero_trust_target
$gap = ConvertTo-HA1HtmlSafe $result.gap_summary
$jsonSource = ConvertTo-HA1HtmlSafe (Resolve-Path $JsonPath)

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ZTVP - H-A1 Hybrid Authentication Method Alignment</title>
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
table { width:100%; border-collapse:collapse; min-width:950px; }
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
    <h2>What H-A1 Checks</h2>
    <div class="review-box">$(ConvertTo-HA1HtmlSafe $meaning)</div>
</section>

<section class="section">
    <h2>Key Numbers</h2>
    <div class="metrics">$metrics</div>
</section>

<section class="section">
    <h2>What To Fix First</h2>
    <div class="review-box">$(ConvertTo-HA1HtmlSafe $fixFirst)</div>
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
    <h2>Priority Queue — Synced Users Missing Strong Methods</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>User</th>
                    <th>On-Prem SAM</th>
                    <th>Strong Methods</th>
                    <th>Weak/Recovery Methods</th>
                    <th>Total Methods</th>
                    <th>Method Evidence</th>
                </tr>
            </thead>
            <tbody>$missingRows</tbody>
        </table>
    </div>
</section>

<section class="section">
    <h2>Synced Users With Strong Methods</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>User</th>
                    <th>On-Prem SAM</th>
                    <th>Strong Methods</th>
                    <th>Weak/Recovery Methods</th>
                    <th>Total Methods</th>
                    <th>Method Evidence</th>
                </tr>
            </thead>
            <tbody>$strongRows</tbody>
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

$out = Join-Path $outFolder "H-A1-result.html"
Set-Content -Path $out -Value $html -Encoding UTF8

Write-Host "Clean H-A1 HTML report generated:" -ForegroundColor Green
Write-Host $out -ForegroundColor Cyan
Start-Process $out
