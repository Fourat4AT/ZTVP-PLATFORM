param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath
)

function ConvertTo-ID4HtmlSafe {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode($Value.ToString())
}

function New-ID4Metric {
    param(
        [string]$Label,
        $Value
    )

    return @"
<div class="metric">
    <div class="metric-value">$(ConvertTo-ID4HtmlSafe $Value)</div>
    <div class="metric-label">$(ConvertTo-ID4HtmlSafe $Label)</div>
</div>
"@
}

function New-ID4Card {
    param(
        [string]$Title,
        [string]$Text,
        [string]$Class
    )

    return @"
<div class="card $Class">
    <strong>$(ConvertTo-ID4HtmlSafe $Title)</strong>
    <p>$(ConvertTo-ID4HtmlSafe $Text)</p>
</div>
"@
}

function New-ID4ExclusionRows {
    param($Items)

    $rows = ""

    foreach ($x in @($Items | Where-Object { $null -ne $_ })) {
        $rows += @"
<tr>
    <td class="policy">$(ConvertTo-ID4HtmlSafe $x.policy_name)</td>
    <td>$(ConvertTo-ID4HtmlSafe $x.policy_state)</td>
    <td>$(ConvertTo-ID4HtmlSafe $x.risk_type)</td>
    <td>$(ConvertTo-ID4HtmlSafe $x.object_type)</td>
    <td>$(ConvertTo-ID4HtmlSafe $x.object_name)</td>
    <td>$(ConvertTo-ID4HtmlSafe $x.classification)</td>
    <td>$(ConvertTo-ID4HtmlSafe $x.confidence)</td>
    <td>$(ConvertTo-ID4HtmlSafe $x.reason)</td>
    <td>$(ConvertTo-ID4HtmlSafe $x.member_count)</td>
    <td>$(ConvertTo-ID4HtmlSafe $x.emergency_member_count)</td>
    <td>$(ConvertTo-ID4HtmlSafe $x.normal_member_count)</td>
</tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='11' class='empty'>No exclusions in this queue.</td></tr>"
    }

    return $rows
}

function New-ID4PolicyRows {
    param($Items)

    $rows = ""

    foreach ($p in @($Items | Where-Object { $null -ne $_ })) {
        $excluded = "None"

        if ($p.excluded_object_names -and $p.excluded_object_names.Count -gt 0) {
            $excluded = (($p.excluded_object_names | ForEach-Object { ConvertTo-ID4HtmlSafe $_ }) -join "<br>")
        }

        $rows += @"
<tr>
    <td class="policy">$(ConvertTo-ID4HtmlSafe $p.policy_name)</td>
    <td>$(ConvertTo-ID4HtmlSafe $p.state_label)</td>
    <td>$(ConvertTo-ID4HtmlSafe $p.risk_type)</td>
    <td>$(ConvertTo-ID4HtmlSafe $p.exclude_users_count)</td>
    <td>$(ConvertTo-ID4HtmlSafe $p.exclude_groups_count)</td>
    <td>$(ConvertTo-ID4HtmlSafe $p.exclude_roles_count)</td>
    <td>$excluded</td>
</tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='7' class='empty'>No risk-policy exclusions detected.</td></tr>"
    }

    return $rows
}

if (-not (Test-Path $JsonPath)) {
    throw "JSON report not found: $JsonPath"
}

$result = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json

if ($result.scenario_id -ne "ID4") {
    throw "This converter is only for ID4 reports. Current scenario_id: $($result.scenario_id)"
}

$e = $result.evidence

$statusClass = "pass"
$decisionTitle = "Identity Protection exclusions look controlled."
$decisionText = "No non-emergency risk-policy exclusion gap was detected."

if ($result.status -eq "PARTIAL") {
    $statusClass = "partial"
    $decisionTitle = "Identity Protection exclusions require review."
    $decisionText = "Normal or unresolved exclusions were detected and need validation."
}
elseif ($result.status -eq "FAIL" -or $result.status -eq "ERROR") {
    $statusClass = "fail"
    $decisionTitle = "High-risk Identity Protection exclusions detected."
    $decisionText = "Broad or role-based exclusions may weaken user-risk or sign-in-risk enforcement."
}

$reviewText = "No enabled risk-policy exclusion requires action."

if ($e.enabled_broad_exclusion_count -gt 0 -or $e.enabled_role_exclusion_count -gt 0) {
    $reviewText = "Remove or strictly justify broad and role-based exclusions. These can create a major bypass of Identity Protection enforcement."
}
elseif ($e.enabled_normal_exclusion_count -gt 0) {
    $reviewText = "Remove or formally justify normal user/group exclusions from risk-based policies."
}
elseif ($e.enabled_unknown_exclusion_count -gt 0) {
    $reviewText = "Resolve unknown exclusions and confirm they are not normal users, broad groups, or roles."
}
elseif ($e.enabled_emergency_exclusion_count -gt 0) {
    $reviewText = "Emergency exclusions were detected. Validate them in A4 and confirm they are limited, monitored, tested, and not used for daily administration."
}

$metrics = ""
$metrics += New-ID4Metric "Risk Policies" $e.risk_policy_count
$metrics += New-ID4Metric "Policies With Exclusions" $e.enabled_risk_policy_with_exclusion_count
$metrics += New-ID4Metric "Emergency Exclusions" $e.enabled_emergency_exclusion_count
$metrics += New-ID4Metric "Normal Exclusions" $e.enabled_normal_exclusion_count
$metrics += New-ID4Metric "Broad Exclusions" $e.enabled_broad_exclusion_count
$metrics += New-ID4Metric "Role Exclusions" $e.enabled_role_exclusion_count
$metrics += New-ID4Metric "Unknown Exclusions" $e.enabled_unknown_exclusion_count
$metrics += New-ID4Metric "A4 Evidence Values" $e.a4_emergency_value_count

$findingsHtml = ""

foreach ($finding in @($result.findings)) {
    $findingsHtml += New-ID4Card -Title $finding.title -Text $finding.detail -Class "finding"
}

if ([string]::IsNullOrWhiteSpace($findingsHtml)) {
    $findingsHtml = New-ID4Card -Title "No problematic exclusions detected" -Text "No normal, broad, role-based, or unresolved enabled risk-policy exclusions were detected." -Class "good"
}

$recommendationsHtml = ""

foreach ($rec in @($result.recommendations)) {
    $recommendationsHtml += New-ID4Card -Title $rec.title -Text $rec.detail -Class "recommendation"
}

if ([string]::IsNullOrWhiteSpace($recommendationsHtml)) {
    $recommendationsHtml = New-ID4Card -Title "No immediate recommendation" -Text "No immediate action is required for this scenario." -Class "good"
}

$allRows = New-ID4ExclusionRows -Items $e.exclusion_inventory
$emergencyRows = New-ID4ExclusionRows -Items $e.emergency_exclusions
$normalRows = New-ID4ExclusionRows -Items $e.normal_exclusions
$unknownRows = New-ID4ExclusionRows -Items $e.unknown_exclusions
$broadRows = New-ID4ExclusionRows -Items $e.broad_exclusions
$roleRows = New-ID4ExclusionRows -Items $e.role_exclusions
$policyRows = New-ID4PolicyRows -Items $e.risk_policies_with_exclusions

$title = ConvertTo-ID4HtmlSafe $result.scenario_name
$category = ConvertTo-ID4HtmlSafe $result.category
$status = ConvertTo-ID4HtmlSafe $result.status
$risk = ConvertTo-ID4HtmlSafe $result.risk
$timestamp = ConvertTo-ID4HtmlSafe $result.timestamp
$currentState = ConvertTo-ID4HtmlSafe $result.current_state
$target = ConvertTo-ID4HtmlSafe $result.zero_trust_target
$gap = ConvertTo-ID4HtmlSafe $result.gap_summary
$a4Source = ConvertTo-ID4HtmlSafe $e.a4_evidence_source
$jsonSource = ConvertTo-ID4HtmlSafe (Resolve-Path $JsonPath)

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ZTVP - ID4 Identity Protection Exclusion Review</title>
<style>
body { margin:0; font-family:"Segoe UI",Arial,sans-serif; background:#f4f7fb; color:#122033; }
.container { max-width:1280px; margin:32px auto; padding:0 24px; }
.header { background:linear-gradient(135deg,#0f172a,#1e3a8a); color:white; border-radius:18px; padding:28px 32px; box-shadow:0 12px 30px rgba(15,23,42,.18); }
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
.metric-value { font-size:25px; font-weight:900; color:#0f172a; }
.metric-label { margin-top:6px; color:#64748b; font-size:14px; }
.review-box { background:#eff6ff; border:1px solid #bfdbfe; border-left:7px solid #2563eb; border-radius:14px; padding:18px; line-height:1.55; }
.card { border-radius:14px; padding:16px 18px; margin-top:12px; line-height:1.5; }
.card p { margin:8px 0 0 0; color:#334155; }
.finding { background:#fff1f2; border-left:6px solid #ef4444; }
.recommendation { background:#eff6ff; border-left:6px solid #2563eb; }
.good { background:#f0fdf4; border-left:6px solid #22c55e; }
.zt-block { background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:16px; margin-top:12px; line-height:1.55; }
.table-wrap { overflow-x:auto; border:1px solid #e2e8f0; border-radius:14px; }
table { width:100%; border-collapse:collapse; min-width:1200px; }
th { background:#0f172a; color:white; text-align:left; padding:12px 14px; font-size:13px; white-space:nowrap; }
td { border-top:1px solid #e2e8f0; padding:12px 14px; vertical-align:top; font-size:14px; line-height:1.45; }
tr:nth-child(even) td { background:#f8fafc; }
.policy { font-weight:700; color:#0f172a; min-width:260px; }
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
    </div>
</section>

<section class="section">
    <h2>Key Numbers</h2>
    <div class="metrics">$metrics</div>
</section>

<section class="section">
    <h2>What To Review</h2>
    <div class="review-box">$reviewText</div>
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
    <h2>Zero Trust Comparison</h2>
    <div class="zt-block"><strong>Current State:</strong><br>$currentState</div>
    <div class="zt-block"><strong>Target:</strong><br>$target</div>
    <div class="zt-block"><strong>Gap:</strong><br>$gap</div>
    <div class="zt-block"><strong>A4 Evidence Source:</strong><br>$a4Source</div>
</section>

<section class="section">
    <h2>Risk Policy Exclusion Summary</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Policy</th>
                    <th>State</th>
                    <th>Risk Type</th>
                    <th>Excluded Users</th>
                    <th>Excluded Groups</th>
                    <th>Excluded Roles</th>
                    <th>Excluded Objects</th>
                </tr>
            </thead>
            <tbody>$policyRows</tbody>
        </table>
    </div>
</section>

<section class="section">
    <h2>All Exclusions</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Policy</th>
                    <th>State</th>
                    <th>Risk Type</th>
                    <th>Object Type</th>
                    <th>Object Name</th>
                    <th>Classification</th>
                    <th>Confidence</th>
                    <th>Reason</th>
                    <th>Members</th>
                    <th>Emergency Members</th>
                    <th>Normal Members</th>
                </tr>
            </thead>
            <tbody>$allRows</tbody>
        </table>
    </div>
</section>

<section class="section">
    <h2>Emergency Exclusions</h2>
    <div class="table-wrap"><table><thead><tr><th>Policy</th><th>State</th><th>Risk Type</th><th>Object Type</th><th>Object Name</th><th>Classification</th><th>Confidence</th><th>Reason</th><th>Members</th><th>Emergency Members</th><th>Normal Members</th></tr></thead><tbody>$emergencyRows</tbody></table></div>
</section>

<section class="section">
    <h2>Action Queue — Normal / Broad / Role / Unknown</h2>
    <h3>Normal Exclusions</h3>
    <div class="table-wrap"><table><thead><tr><th>Policy</th><th>State</th><th>Risk Type</th><th>Object Type</th><th>Object Name</th><th>Classification</th><th>Confidence</th><th>Reason</th><th>Members</th><th>Emergency Members</th><th>Normal Members</th></tr></thead><tbody>$normalRows</tbody></table></div>
    <h3>Broad Exclusions</h3>
    <div class="table-wrap"><table><thead><tr><th>Policy</th><th>State</th><th>Risk Type</th><th>Object Type</th><th>Object Name</th><th>Classification</th><th>Confidence</th><th>Reason</th><th>Members</th><th>Emergency Members</th><th>Normal Members</th></tr></thead><tbody>$broadRows</tbody></table></div>
    <h3>Role Exclusions</h3>
    <div class="table-wrap"><table><thead><tr><th>Policy</th><th>State</th><th>Risk Type</th><th>Object Type</th><th>Object Name</th><th>Classification</th><th>Confidence</th><th>Reason</th><th>Members</th><th>Emergency Members</th><th>Normal Members</th></tr></thead><tbody>$roleRows</tbody></table></div>
    <h3>Unknown Exclusions</h3>
    <div class="table-wrap"><table><thead><tr><th>Policy</th><th>State</th><th>Risk Type</th><th>Object Type</th><th>Object Name</th><th>Classification</th><th>Confidence</th><th>Reason</th><th>Members</th><th>Emergency Members</th><th>Normal Members</th></tr></thead><tbody>$unknownRows</tbody></table></div>
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

$out = Join-Path $outFolder "ID4-result.html"
Set-Content -Path $out -Value $html -Encoding UTF8

Write-Host "Detailed ID4 HTML report generated:" -ForegroundColor Green
Write-Host $out -ForegroundColor Cyan
Start-Process $out
