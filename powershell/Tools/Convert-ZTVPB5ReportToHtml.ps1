param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath
)

function ConvertTo-B5HtmlSafe {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode($Value.ToString())
}

function New-B5Metric {
    param([string]$Label, $Value)

    return "<div class='metric'><div class='metric-value'>$(ConvertTo-B5HtmlSafe $Value)</div><div class='metric-label'>$(ConvertTo-B5HtmlSafe $Label)</div></div>"
}

function New-B5Card {
    param([string]$Title, [string]$Text, [string]$Class)

    return "<div class='card $Class'><strong>$(ConvertTo-B5HtmlSafe $Title)</strong><p>$(ConvertTo-B5HtmlSafe $Text)</p></div>"
}

function New-B5UserRows {
    param($Items)

    $rows = ""

    foreach ($u in @($Items | Where-Object { $null -ne $_ } | Select-Object -First 50)) {
        $rows += "<tr>"
        $rows += "<td>$(ConvertTo-B5HtmlSafe $u.user_principal_name)</td>"
        $rows += "<td>$(ConvertTo-B5HtmlSafe $u.user_type)</td>"
        $rows += "<td>$(ConvertTo-B5HtmlSafe $u.account_enabled)</td>"
        $rows += "<td>$(ConvertTo-B5HtmlSafe $u.assigned_license_count)</td>"
        $rows += "<td>$(ConvertTo-B5HtmlSafe $u.last_sign_in_age_days)</td>"
        $rows += "<td>$(ConvertTo-B5HtmlSafe $u.password_policies)</td>"
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

if ($result.scenario_id -ne "B5") {
    throw "This converter is only for B5 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$statusClass = "pass"
$decisionTitle = "User account hygiene appears controlled."
$decisionText = "No major stale or unmanaged account issue was detected."

if ($result.status -eq "PARTIAL") {
    $statusClass = "partial"
    $decisionTitle = "User account hygiene needs review."
    $decisionText = "No stale sign-in issue was detected, but enabled guests, unlicensed users, or password policy flags need review."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "fail"
    $decisionTitle = "User account hygiene has significant exposure."
    $decisionText = "Many stale or evidence-limited enabled accounts require action."
}

$meaning = "B5 checks account hygiene. It looks for stale enabled users, enabled guest users, enabled unlicensed member accounts, users with no recent sign-in evidence, and accounts with DisablePasswordExpiration. A finding here does not always mean the account is bad; it means the account needs justification, ownership, or cleanup."

$fixFirst = "Start with enabled unlicensed member accounts and DisablePasswordExpiration accounts. Confirm whether each one is a real user, emergency account, service-like account, test account, or should be disabled. Enabled guests should also have owners and periodic access reviews."

$metrics = ""
$metrics += New-B5Metric "Decision" $result.status
$metrics += New-B5Metric "Risk" $result.risk
$metrics += New-B5Metric "Users Assessed" $e.user_count
$metrics += New-B5Metric "Enabled Users" $e.enabled_user_count
$metrics += New-B5Metric "Disabled Users" $e.disabled_user_count
$metrics += New-B5Metric "Guest Users" $e.guest_user_count
$metrics += New-B5Metric "Enabled Guests" $e.enabled_guest_user_count
$metrics += New-B5Metric "Stale Enabled Users" $e.stale_enabled_user_count
$metrics += New-B5Metric "No Recent Sign-In Evidence" $e.no_recent_sign_in_evidence_user_count
$metrics += New-B5Metric "Enabled Unlicensed Members" $e.enabled_unlicensed_member_count
$metrics += New-B5Metric "DisablePasswordExpiration" $e.disable_password_expiration_user_count

$findingsHtml = ""

foreach ($finding in @($result.findings)) {
    $findingsHtml += New-B5Card -Title $finding.title -Text $finding.detail -Class "finding"
}

if ([string]::IsNullOrWhiteSpace($findingsHtml)) {
    $findingsHtml = New-B5Card -Title "No major account hygiene finding detected" -Text "No major B5 finding was detected." -Class "good"
}

$recommendationsHtml = ""

foreach ($rec in @($result.recommendations)) {
    $recommendationsHtml += New-B5Card -Title $rec.title -Text $rec.detail -Class "recommendation"
}

$unlicensedRows = New-B5UserRows -Items $e.enabled_unlicensed_members
$guestRows = New-B5UserRows -Items $e.enabled_guests
$staleRows = New-B5UserRows -Items $e.stale_enabled_users
$noEvidenceRows = New-B5UserRows -Items $e.no_recent_sign_in_evidence_users

$title = ConvertTo-B5HtmlSafe $result.scenario_name
$category = ConvertTo-B5HtmlSafe $result.category
$status = ConvertTo-B5HtmlSafe $result.status
$risk = ConvertTo-B5HtmlSafe $result.risk
$timestamp = ConvertTo-B5HtmlSafe $result.timestamp
$summary = ConvertTo-B5HtmlSafe $e.executive_summary
$currentState = ConvertTo-B5HtmlSafe $result.current_state
$target = ConvertTo-B5HtmlSafe $result.zero_trust_target
$gap = ConvertTo-B5HtmlSafe $result.gap_summary
$jsonSource = ConvertTo-B5HtmlSafe (Resolve-Path $JsonPath)

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ZTVP - B5 User Account Hygiene Review</title>
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
    <h2>What B5 Checks</h2>
    <div class="review-box">$(ConvertTo-B5HtmlSafe $meaning)</div>
</section>

<section class="section">
    <h2>Key Numbers</h2>
    <div class="metrics">$metrics</div>
</section>

<section class="section">
    <h2>What To Fix First</h2>
    <div class="review-box">$(ConvertTo-B5HtmlSafe $fixFirst)</div>
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
    <h2>Priority Queue — Enabled Unlicensed Member Accounts</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>User</th>
                    <th>Type</th>
                    <th>Enabled</th>
                    <th>Licenses</th>
                    <th>Last Sign-In Age Days</th>
                    <th>Password Policies</th>
                </tr>
            </thead>
            <tbody>$unlicensedRows</tbody>
        </table>
    </div>
</section>

<section class="section">
    <h2>Enabled Guest Accounts</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>User</th>
                    <th>Type</th>
                    <th>Enabled</th>
                    <th>Licenses</th>
                    <th>Last Sign-In Age Days</th>
                    <th>Password Policies</th>
                </tr>
            </thead>
            <tbody>$guestRows</tbody>
        </table>
    </div>
</section>

<section class="section">
    <h2>Stale / No Evidence Accounts</h2>
    <h3>Stale Enabled Users</h3>
    <div class="table-wrap"><table><thead><tr><th>User</th><th>Type</th><th>Enabled</th><th>Licenses</th><th>Last Sign-In Age Days</th><th>Password Policies</th></tr></thead><tbody>$staleRows</tbody></table></div>
    <h3>No Recent Sign-In Evidence</h3>
    <div class="table-wrap"><table><thead><tr><th>User</th><th>Type</th><th>Enabled</th><th>Licenses</th><th>Last Sign-In Age Days</th><th>Password Policies</th></tr></thead><tbody>$noEvidenceRows</tbody></table></div>
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

$out = Join-Path $outFolder "B5-result.html"
Set-Content -Path $out -Value $html -Encoding UTF8

Write-Host "Clean B5 HTML report generated:" -ForegroundColor Green
Write-Host $out -ForegroundColor Cyan
Start-Process $out
