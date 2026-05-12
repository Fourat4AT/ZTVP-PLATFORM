param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath
)

function ConvertTo-B2HtmlSafe {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode($Value.ToString())
}

function New-B2Metric {
    param(
        [string]$Label,
        $Value
    )

    return @"
<div class="metric">
    <div class="metric-value">$(ConvertTo-B2HtmlSafe $Value)</div>
    <div class="metric-label">$(ConvertTo-B2HtmlSafe $Label)</div>
</div>
"@
}

function New-B2Card {
    param(
        [string]$Title,
        [string]$Text,
        [string]$Class
    )

    return @"
<div class="card $Class">
    <strong>$(ConvertTo-B2HtmlSafe $Title)</strong>
    <p>$(ConvertTo-B2HtmlSafe $Text)</p>
</div>
"@
}

function New-B2SettingRows {
    param($Items)

    $rows = ""

    foreach ($s in @($Items | Where-Object { $null -ne $_ })) {
        $rows += @"
<tr>
    <td class="setting">$(ConvertTo-B2HtmlSafe $s.setting)</td>
    <td>$(ConvertTo-B2HtmlSafe $s.state)</td>
    <td>$(ConvertTo-B2HtmlSafe $s.severity)</td>
    <td>$(ConvertTo-B2HtmlSafe $s.scenario_owner)</td>
    <td>$(ConvertTo-B2HtmlSafe $s.interpretation)</td>
</tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='5' class='empty'>No settings in this section.</td></tr>"
    }

    return $rows
}

if (-not (Test-Path $JsonPath)) {
    throw "JSON report not found: $JsonPath"
}

$result = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json

if ($result.scenario_id -ne "B2") {
    throw "This converter is only for B2 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$statusClass = "pass"
$decisionTitle = "Default user permissions are controlled."
$decisionText = "No major risky default user permission setting was detected."

if ($result.status -eq "PARTIAL") {
    $statusClass = "partial"
    $decisionTitle = "Default user permissions are mostly controlled, but review is needed."
    $decisionText = "Core high-risk defaults are restricted, but one or more medium-risk self-service settings should be justified or disabled."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "fail"
    $decisionTitle = "Default user permissions are too permissive."
    $decisionText = "One or more high-risk default user permissions are enabled."
}

$whatThisChecks = "B2 checks tenant-wide default user permissions: app registration creation, security group creation, tenant creation, guest invitation openness, email-verified join behavior, and email-based subscription sign-up. OAuth consent is handled in B3. Password and SSPR posture is handled in B4."

$nextStep = "Restrict or justify the medium-risk settings. Then run B3 for user/app consent and B4 for password/SSPR posture."

$metrics = ""
$metrics += New-B2Metric "High-Risk Settings" $e.high_risk_default_permission_count
$metrics += New-B2Metric "Medium-Risk Settings" $e.medium_risk_default_permission_count
$metrics += New-B2Metric "Controlled Settings" $e.controlled_default_permission_count
$metrics += New-B2Metric "App Registration" $(if ($e.users_can_register_applications -eq $true) { "Allowed" } else { "Restricted" })
$metrics += New-B2Metric "Security Group Creation" $(if ($e.users_can_create_security_groups -eq $true) { "Allowed" } else { "Restricted" })
$metrics += New-B2Metric "Tenant Creation" $(if ($e.users_can_create_tenants -eq $true) { "Allowed" } else { "Restricted" })
$metrics += New-B2Metric "Guest Invites" $e.guest_invite_meaning
$metrics += New-B2Metric "Email-Verified Join" $(if ($e.email_verified_users_can_join_organization -eq $true) { "Allowed" } else { "Restricted" })
$metrics += New-B2Metric "Email Sign-Up" $(if ($e.email_based_subscription_signup_allowed -eq $true) { "Allowed" } else { "Restricted" })

$findingsHtml = ""

foreach ($finding in @($result.findings)) {
    $findingsHtml += New-B2Card -Title $finding.title -Text $finding.detail -Class "finding"
}

if ([string]::IsNullOrWhiteSpace($findingsHtml)) {
    $findingsHtml = New-B2Card -Title "No problematic default user permission detected" -Text "No high or medium-risk B2 finding was detected." -Class "good"
}

$recommendationsHtml = ""

foreach ($rec in @($result.recommendations)) {
    $recommendationsHtml += New-B2Card -Title $rec.title -Text $rec.detail -Class "recommendation"
}

$settingsRows = New-B2SettingRows -Items $e.settings
$highRows = New-B2SettingRows -Items $e.high_risk_settings
$mediumRows = New-B2SettingRows -Items $e.medium_risk_settings

$title = ConvertTo-B2HtmlSafe $result.scenario_name
$category = ConvertTo-B2HtmlSafe $result.category
$status = ConvertTo-B2HtmlSafe $result.status
$risk = ConvertTo-B2HtmlSafe $result.risk
$timestamp = ConvertTo-B2HtmlSafe $result.timestamp
$summary = ConvertTo-B2HtmlSafe $e.executive_summary
$currentState = ConvertTo-B2HtmlSafe $result.current_state
$target = ConvertTo-B2HtmlSafe $result.zero_trust_target
$gap = ConvertTo-B2HtmlSafe $result.gap_summary
$jsonSource = ConvertTo-B2HtmlSafe (Resolve-Path $JsonPath)

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ZTVP - B2 Default User Permissions Review</title>
<style>
body { margin:0; font-family:"Segoe UI",Arial,sans-serif; background:#f4f7fb; color:#122033; }
.container { max-width:1280px; margin:32px auto; padding:0 24px; }
.header { background:linear-gradient(135deg,#0f172a,#334155); color:white; border-radius:18px; padding:28px 32px; box-shadow:0 12px 30px rgba(15,23,42,.18); }
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
.metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; }
.metric { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:16px; }
.metric-value { font-size:22px; font-weight:900; color:#0f172a; }
.metric-label { margin-top:6px; color:#64748b; font-size:14px; }
.review-box { background:#eff6ff; border:1px solid #bfdbfe; border-left:7px solid #2563eb; border-radius:14px; padding:18px; line-height:1.55; }
.card { border-radius:14px; padding:16px 18px; margin-top:12px; line-height:1.5; }
.card p { margin:8px 0 0 0; color:#334155; }
.finding { background:#fffbeb; border-left:6px solid #f59e0b; }
.recommendation { background:#eff6ff; border-left:6px solid #2563eb; }
.good { background:#f0fdf4; border-left:6px solid #22c55e; }
.zt-block { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:16px; margin-top:12px; line-height:1.55; }
.table-wrap { overflow-x:auto; border:1px solid #e2e8f0; border-radius:14px; }
table { width:100%; border-collapse:collapse; min-width:1000px; }
th { background:#0f172a; color:white; text-align:left; padding:12px 14px; font-size:13px; white-space:nowrap; }
td { border-top:1px solid #e2e8f0; padding:12px 14px; vertical-align:top; font-size:14px; line-height:1.45; }
tr:nth-child(even) td { background:#f8fafc; }
.setting { font-weight:700; color:#0f172a; min-width:260px; }
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
    <h2>What This Scenario Checks</h2>
    <div class="review-box">$whatThisChecks</div>
</section>

<section class="section">
    <h2>Key Numbers</h2>
    <div class="metrics">$metrics</div>
</section>

<section class="section">
    <h2>What To Do Next</h2>
    <div class="review-box">$nextStep</div>
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
    <h2>Settings Reviewed</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Setting</th>
                    <th>State</th>
                    <th>Severity</th>
                    <th>Reviewed In</th>
                    <th>Interpretation</th>
                </tr>
            </thead>
            <tbody>$settingsRows</tbody>
        </table>
    </div>
</section>

<section class="section">
    <h2>Action Queue</h2>
    <h3>High-Risk Settings</h3>
    <div class="table-wrap"><table><thead><tr><th>Setting</th><th>State</th><th>Severity</th><th>Reviewed In</th><th>Interpretation</th></tr></thead><tbody>$highRows</tbody></table></div>
    <h3>Medium-Risk Settings</h3>
    <div class="table-wrap"><table><thead><tr><th>Setting</th><th>State</th><th>Severity</th><th>Reviewed In</th><th>Interpretation</th></tr></thead><tbody>$mediumRows</tbody></table></div>
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

$out = Join-Path $outFolder "B2-result.html"
Set-Content -Path $out -Value $html -Encoding UTF8

Write-Host "Clean B2 HTML report generated:" -ForegroundColor Green
Write-Host $out -ForegroundColor Cyan
Start-Process $out
