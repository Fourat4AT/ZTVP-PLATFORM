param(
    [string]$JsonPath,
    [string]$OutputPath
)

function ConvertTo-ZTVPHtmlText {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode($Value.ToString())
}

function Get-ZTVPBadgeClass {
    param([string]$Value)

    switch -Regex ($Value) {
        "PASS|LOW|READY" { return "badge good" }
        "PARTIAL|MEDIUM|HIGH|PLANNED" { return "badge warn" }
        "FAIL|CRITICAL|ERROR" { return "badge bad" }
        default { return "badge neutral" }
    }
}

function ConvertTo-ZTVPDisplayName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return ""
    }

    $text = $Name -replace "_", " "
    $text = [System.Globalization.CultureInfo]::InvariantCulture.TextInfo.ToTitleCase($text.ToLowerInvariant())

    return $text
}

function New-ZTVPMetricCards {
    param($Evidence)

    if ($null -eq $Evidence) {
        return ""
    }

    function New-MetricCard {
        param(
            [string]$Label,
            [string]$Value
        )

        $safeLabel = ConvertTo-ZTVPHtmlText $Label
        $safeValue = ConvertTo-ZTVPHtmlText $Value

        return @"
        <div class="metric-card">
            <div class="metric-value">$safeValue</div>
            <div class="metric-label">$safeLabel</div>
        </div>
"@
    }

    $html = ""

    if ($Evidence.PSObject.Properties["emergency_account_count"]) {
        $html += New-MetricCard -Label "Emergency Accounts" -Value $Evidence.emergency_account_count
        $html += New-MetricCard -Label "Active Emergency Accounts" -Value $Evidence.active_emergency_account_count
        $html += New-MetricCard -Label "Emergency Groups" -Value $Evidence.emergency_group_count
        $html += New-MetricCard -Label "Cloud-Only Accounts" -Value "$($Evidence.cloud_only_emergency_account_count) / $($Evidence.emergency_account_count)"
        $html += New-MetricCard -Label "Global Admin Emergency Accounts" -Value "$($Evidence.global_admin_emergency_account_count) / $($Evidence.emergency_account_count)"
        $html += New-MetricCard -Label "Missing MFA" -Value $Evidence.missing_mfa_user_count
        $html += New-MetricCard -Label "Phishing-Resistant Ready" -Value $Evidence.phishing_resistant_user_count
        $html += New-MetricCard -Label "CA-Excluded Accounts" -Value $Evidence.ca_excluded_emergency_account_count
        $html += New-MetricCard -Label "Critical Backdoor Risk" -Value $Evidence.critical_backdoor_risk_count
        $html += New-MetricCard -Label "Unexpected Group Members" -Value $Evidence.unexpected_emergency_group_member_count
        return $html
    }

    if ($Evidence.PSObject.Properties["standard_users_assessed"]) {
        $html += New-MetricCard -Label "Standard Users Assessed" -Value $Evidence.standard_users_assessed
        $html += New-MetricCard -Label "MFA Coverage" -Value "$($Evidence.mfa_coverage_percent)%"
        $html += New-MetricCard -Label "MFA Registered Users" -Value $Evidence.mfa_registered_user_count
        $html += New-MetricCard -Label "Missing MFA Users" -Value $Evidence.missing_mfa_user_count
        $html += New-MetricCard -Label "Weak MFA Users" -Value $Evidence.weak_mfa_user_count
        $html += New-MetricCard -Label "Unknown Evidence" -Value $Evidence.unknown_mfa_user_count
        return $html
    }

    if ($Evidence.PSObject.Properties["privileged_users_assessed"]) {
        $html += New-MetricCard -Label "Privileged Users Assessed" -Value $Evidence.privileged_users_assessed
        $html += New-MetricCard -Label "Phishing-Resistant Users" -Value $Evidence.phishing_resistant_user_count
        $html += New-MetricCard -Label "Strong But Not Confirmed" -Value $Evidence.strong_but_not_confirmed_user_count
        $html += New-MetricCard -Label "Missing MFA Users" -Value $Evidence.missing_mfa_user_count
        $html += New-MetricCard -Label "Unknown MFA Evidence" -Value $Evidence.unknown_mfa_user_count
        return $html
    }

    $skip = @(
        "assessed_users",
        "admin_users",
        "conditional_access",
        "executive_summary"
    )

    foreach ($prop in $Evidence.PSObject.Properties) {
        if ($skip -contains $prop.Name) {
            continue
        }

        $value = $prop.Value

        if ($null -eq $value) {
            continue
        }

        if ($value -is [System.Array]) {
            continue
        }

        if ($value -is [pscustomobject]) {
            continue
        }

        $label = ConvertTo-ZTVPDisplayName $prop.Name
        $displayValue = ConvertTo-ZTVPHtmlText $value

        $html += New-MetricCard -Label $label -Value $displayValue
    }

    return $html
}







function New-ZTVPCardList {
    param(
        [string]$Title,
        $Items,
        [string]$Type
    )

    if ($null -eq $Items -or @($Items).Count -eq 0) {
        return ""
    }

    $itemsHtml = ""

    foreach ($item in @($Items)) {
        $itemTitle = ""
        $itemDetail = ""

        if ($item.PSObject.Properties["title"]) {
            $itemTitle = ConvertTo-ZTVPHtmlText $item.title
        }
        else {
            $itemTitle = ConvertTo-ZTVPHtmlText $item
        }

        if ($item.PSObject.Properties["detail"]) {
            $rawDetail = $item.detail.ToString()

            if ($Title -eq "Findings") {
                $patterns = @(
                    "Affected users:",
                    "Affected accounts:",
                    "Affected user:",
                    "Affected account:",
                    "Affected members:",
                    "Affected policies:",
                    "Policies:",
                    "Sample:",
                    "Synced accounts detected:"
                )

                foreach ($pattern in $patterns) {
                    $idx = $rawDetail.IndexOf($pattern, [System.StringComparison]::OrdinalIgnoreCase)

                    if ($idx -ge 0) {
                        $rawDetail = $rawDetail.Substring(0, $idx).Trim()
                        $rawDetail = $rawDetail.TrimEnd(".", " ")

                        if ($pattern -match "Policies|Affected policies") {
                            $rawDetail = $rawDetail + ". See the Policy Evidence section for the full policy list."
                        }
                        elseif ($pattern -match "Sample") {
                            $rawDetail = $rawDetail + ". See the Evidence section for the full sample."
                        }
                        else {
                            $rawDetail = $rawDetail + ". See the Affected Accounts section for the full account list."
                        }

                        break
                    }
                }
            }

            $itemDetail = ConvertTo-ZTVPHtmlText $rawDetail
        }

        $itemsHtml += @"
        <div class="finding-card $Type">
            <div class="finding-title">$itemTitle</div>
            <div class="finding-detail">$itemDetail</div>
        </div>
"@
    }

    return @"
    <section class="section">
        <h2>$Title</h2>
        <div class="card-list">
            $itemsHtml
        </div>
    </section>
"@
}

function New-ZTVPUserGroup {
    param(
        [string]$Title,
        $Users,
        [string]$Class
    )

    if ($null -eq $Users -or @($Users).Count -eq 0) {
        return ""
    }

    $list = ""

    foreach ($u in @($Users | Sort-Object)) {
        $safe = ConvertTo-ZTVPHtmlText $u
        $list += "<li>$safe</li>`n"
    }

    return @"
    <div class="user-group $Class">
        <h3>$Title</h3>
        <ul>
            $list
        </ul>
    </div>
"@
}

function New-ZTVPAffectedAccounts {
    param($Evidence)

    if ($null -eq $Evidence) {
        return ""
    }

    $groups = ""

    $groups += New-ZTVPUserGroup -Title "Emergency Accounts Detected" -Users $Evidence.emergency_accounts -Class "neutral"
    $groups += New-ZTVPUserGroup -Title "Missing MFA" -Users $Evidence.missing_mfa_users -Class "bad"
    $groups += New-ZTVPUserGroup -Title "Weak MFA" -Users $Evidence.weak_mfa_users -Class "warn"
    $groups += New-ZTVPUserGroup -Title "Weak or Phishable Only" -Users $Evidence.weak_or_phishable_only_users -Class "warn"
    $groups += New-ZTVPUserGroup -Title "Strong MFA but Phishing-Resistant Not Confirmed" -Users $Evidence.strong_but_not_confirmed_users -Class "warn"
    $groups += New-ZTVPUserGroup -Title "Confirmed Phishing-Resistant" -Users $Evidence.phishing_resistant_users -Class "good"
    $groups += New-ZTVPUserGroup -Title "Unknown MFA Evidence" -Users $Evidence.unknown_mfa_users -Class "neutral"
    $groups += New-ZTVPUserGroup -Title "Emergency Accounts Not Phishing-Ready" -Users $Evidence.emergency_without_phishing_resistant_users -Class "bad"
    $groups += New-ZTVPUserGroup -Title "CA-Excluded Emergency Accounts" -Users $Evidence.ca_excluded_emergency_accounts -Class "warn"
    $groups += New-ZTVPUserGroup -Title "Critical Backdoor Risk Accounts" -Users $Evidence.critical_backdoor_risk_accounts -Class "bad"
    $groups += New-ZTVPUserGroup -Title "Unexpected Emergency Group Members" -Users $Evidence.unexpected_emergency_group_members -Class "warn"
    $groups += New-ZTVPUserGroup -Title "Synced Emergency Accounts" -Users $Evidence.synced_emergency_accounts -Class "bad"
    $groups += New-ZTVPUserGroup -Title "MFA Registered Users" -Users $Evidence.mfa_registered_users -Class "good"
    $groups += New-ZTVPUserGroup -Title "No MFA Users" -Users $Evidence.no_mfa_users -Class "bad"
    $groups += New-ZTVPUserGroup -Title "Strong MFA Users" -Users $Evidence.strong_mfa_users -Class "good"

    if ([string]::IsNullOrWhiteSpace($groups)) {
        return ""
    }

    return @"
    <section class="section">
        <h2>Affected Accounts</h2>
        <div class="user-grid">
            $groups
        </div>
    </section>
"@
}


function New-ZTVPAssessedUsersTable {
    param($Evidence)

    if ($null -eq $Evidence -or $null -eq $Evidence.assessed_users) {
        return ""
    }

    $rows = ""
    $users = @($Evidence.assessed_users | Select-Object -First 200)

    foreach ($u in $users) {
        $upn = ConvertTo-ZTVPHtmlText $u.userPrincipalName
        $displayName = ConvertTo-ZTVPHtmlText $u.displayName
        $role = ConvertTo-ZTVPHtmlText $u.role
        $readiness = ConvertTo-ZTVPHtmlText $u.readiness
        $mfaEnabled = ConvertTo-ZTVPHtmlText $u.mfa_enabled
        $methods = ""

        if ($u.mfa_methods) {
            $methods = ConvertTo-ZTVPHtmlText (@($u.mfa_methods) -join ", ")
        }

        $rows += @"
        <tr>
            <td>$upn</td>
            <td>$displayName</td>
            <td>$role</td>
            <td>$readiness</td>
            <td>$mfaEnabled</td>
            <td>$methods</td>
        </tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        return ""
    }

    return @"
    <section class="section">
        <h2>Assessed Users</h2>
        <p class="muted">Showing up to 200 assessed users.</p>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>User Principal Name</th>
                        <th>Display Name</th>
                        <th>Role</th>
                        <th>Readiness</th>
                        <th>MFA Enabled</th>
                        <th>Methods</th>
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

function New-ZTVPE1PolicyTable {
    param(
        [string]$Title,
        $Policies,
        [string]$EmptyMessage
    )

    $rows = ""

    foreach ($p in @($Policies)) {
        $name  = ConvertTo-ZTVPHtmlText $p.name
        $state = ConvertTo-ZTVPHtmlText $p.state
        $grant = ConvertTo-ZTVPHtmlText $p.grant_type

        $allUsers = "No"
        if ($p.includes_all_users -eq $true) {
            $allUsers = "Yes"
        }

        $allApps = "No"
        if ($p.includes_all_apps -eq $true) {
            $allApps = "Yes"
        }

        $exclusions = ConvertTo-ZTVPHtmlText ("Users: {0}, Groups: {1}, Roles: {2}" -f $p.excluded_users_count, $p.excluded_groups_count, $p.excluded_roles_count)

        $rows += @"
            <tr>
                <td>$name</td>
                <td>$state</td>
                <td>$grant</td>
                <td>$allUsers</td>
                <td>$allApps</td>
                <td>$exclusions</td>
            </tr>
"@
    }

    if ([string]::IsNullOrWhiteSpace($rows)) {
        $safeEmpty = ConvertTo-ZTVPHtmlText $EmptyMessage

        $rows = @"
            <tr>
                <td colspan="6">$safeEmpty</td>
            </tr>
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
                        <th>Grant / Control Type</th>
                        <th>All Users</th>
                        <th>All Apps</th>
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

function New-ZTVPE1EvidenceSection {
    param($Result)

    if ($null -eq $Result -or $null -eq $Result.evidence) {
        return ""
    }

    if ($Result.scenario_id -ne "E1") {
        return ""
    }

    $e = $Result.evidence
    $assessed = @($e.assessed_policies)

    $reportOnlyPolicies = @($assessed | Where-Object { $_.report_only -eq $true })
    $disabledPolicies = @($assessed | Where-Object { $_.disabled -eq $true })
    $enabledExclusionPolicies = @($assessed | Where-Object { $_.enabled -eq $true -and $_.has_exclusions -eq $true })
    $enabledPolicies = @($assessed | Where-Object { $_.enabled -eq $true })

    $decisionClass = "good"
    $decisionText = "Conditional Access policy state appears controlled."

    if ($Result.status -eq "FAIL" -or $Result.status -eq "ERROR") {
        $decisionClass = "bad"
        $decisionText = "Conditional Access policy state requires urgent remediation."
    }
    elseif ($Result.status -eq "PARTIAL") {
        $decisionClass = "warn"
        $decisionText = "Conditional Access policies exist, but report-only policies, disabled policies, or exclusions reduce enforcement confidence."
    }

    $reportOnlyTable = New-ZTVPE1PolicyTable `
        -Title "Policy Evidence — Report-Only Policies" `
        -Policies $reportOnlyPolicies `
        -EmptyMessage "No report-only Conditional Access policies detected."

    $disabledTable = New-ZTVPE1PolicyTable `
        -Title "Policy Evidence — Disabled Policies" `
        -Policies $disabledPolicies `
        -EmptyMessage "No disabled Conditional Access policies detected."

    $exclusionTable = New-ZTVPE1PolicyTable `
        -Title "Policy Evidence — Enabled Policies With Exclusions" `
        -Policies $enabledExclusionPolicies `
        -EmptyMessage "No enabled Conditional Access policies with exclusions detected."

    $enabledTable = New-ZTVPE1PolicyTable `
        -Title "Policy Evidence — Enabled Policy Inventory" `
        -Policies $enabledPolicies `
        -EmptyMessage "No enabled Conditional Access policies detected."

    return @"
    <section class="section">
        <h2>E1 Conditional Access Governance Decision</h2>
        <div class="finding-card $decisionClass">
            <div class="finding-title">$decisionText</div>
            <div class="finding-detail">
                The platform assessed $($e.conditional_access_policy_count) Conditional Access policies.
                Enabled: $($e.enabled_policy_count) ($($e.enabled_policy_percent)%).
                Report-only: $($e.report_only_policy_count) ($($e.report_only_policy_percent)%).
                Disabled: $($e.disabled_policy_count) ($($e.disabled_policy_percent)%).
                Enabled policies with exclusions: $($e.enabled_policy_with_exclusion_count).
            </div>
        </div>
    </section>

    $reportOnlyTable
    $disabledTable
    $exclusionTable
    $enabledTable
"@
}

function New-ZTVPScenarioSpecificEvidence {
    param($Result)

    if ($null -eq $Result) {
        return ""
    }

    switch ($Result.scenario_id) {
        "E1" {
            return New-ZTVPE1EvidenceSection -Result $Result
        }

        "A5" {
            if (Get-Command New-ZTVPA5EvidenceSection -ErrorAction SilentlyContinue) {
                return New-ZTVPA5EvidenceSection -Result $Result
            }

            return ""
        }

        default {
            return ""
        }
    }
}

if ([string]::IsNullOrWhiteSpace($JsonPath)) {
    $latest = Get-ChildItem ".\powershell\Reports\*-result.json" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $latest) {
        throw "No JSON reports found in .\powershell\Reports."
    }

    $JsonPath = $latest.FullName
}

if (-not (Test-Path $JsonPath)) {
    throw "JSON report not found: $JsonPath"
}

$result = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($JsonPath)
    $OutputPath = ".\powershell\Reports\Html\$baseName.html"
}

$scenarioId = ConvertTo-ZTVPHtmlText $result.scenario_id
$scenarioName = ConvertTo-ZTVPHtmlText $result.scenario_name
$category = ConvertTo-ZTVPHtmlText $result.category
$status = ConvertTo-ZTVPHtmlText $result.status
$risk = ConvertTo-ZTVPHtmlText $result.risk
$timestamp = ConvertTo-ZTVPHtmlText $result.timestamp
$currentState = ConvertTo-ZTVPHtmlText $result.current_state
$target = ConvertTo-ZTVPHtmlText $result.zero_trust_target
$gap = ConvertTo-ZTVPHtmlText $result.gap_summary

$statusClass = Get-ZTVPBadgeClass $result.status
$riskClass = Get-ZTVPBadgeClass $result.risk

$executiveSummary = "No executive summary available."
if ($result.evidence -and $result.evidence.executive_summary) {
    $executiveSummary = ConvertTo-ZTVPHtmlText $result.evidence.executive_summary
}

$metricCards = New-ZTVPMetricCards -Evidence $result.evidence
$findings = New-ZTVPCardList -Title "Findings" -Items $result.findings -Type "bad"
$recommendations = New-ZTVPCardList -Title "Recommendations" -Items $result.recommendations -Type "good"
$affectedAccounts = New-ZTVPAffectedAccounts -Evidence $result.evidence
$assessedUsersTable = New-ZTVPAssessedUsersTable -Evidence $result.evidence

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ZTVP Report - $scenarioId</title>
<style>
    :root {
        --bg: #0f172a;
        --panel: #111827;
        --panel2: #ffffff;
        --text: #111827;
        --muted: #6b7280;
        --line: #e5e7eb;
        --blue: #2563eb;
        --cyan: #0891b2;
        --green: #16a34a;
        --yellow: #d97706;
        --red: #dc2626;
        --soft-red: #fef2f2;
        --soft-yellow: #fffbeb;
        --soft-green: #f0fdf4;
        --soft-blue: #eff6ff;
    }

    * {
        box-sizing: border-box;
    }

    body {
        margin: 0;
        font-family: "Segoe UI", Arial, sans-serif;
        background: #f3f4f6;
        color: var(--text);
    }

    .hero {
        background: linear-gradient(135deg, #0f172a, #1e3a8a);
        color: white;
        padding: 36px 42px;
    }

    .hero h1 {
        margin: 0 0 8px 0;
        font-size: 30px;
        letter-spacing: -0.03em;
    }

    .hero p {
        margin: 0;
        color: #cbd5e1;
        font-size: 15px;
    }

    .container {
        max-width: 1180px;
        margin: -24px auto 40px auto;
        padding: 0 22px;
    }

    .summary-panel {
        background: white;
        border-radius: 18px;
        box-shadow: 0 18px 45px rgba(15, 23, 42, 0.18);
        padding: 24px;
        border: 1px solid var(--line);
    }

    .top-row {
        display: flex;
        justify-content: space-between;
        gap: 18px;
        align-items: flex-start;
        flex-wrap: wrap;
    }

    .scenario-title h2 {
        margin: 0;
        font-size: 24px;
    }

    .scenario-meta {
        margin-top: 10px;
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
    }

    .badge {
        display: inline-flex;
        align-items: center;
        padding: 6px 10px;
        border-radius: 999px;
        font-size: 12px;
        font-weight: 700;
        border: 1px solid transparent;
    }

    .badge.good {
        background: var(--soft-green);
        color: var(--green);
        border-color: #bbf7d0;
    }

    .badge.warn {
        background: var(--soft-yellow);
        color: var(--yellow);
        border-color: #fde68a;
    }

    .badge.bad {
        background: var(--soft-red);
        color: var(--red);
        border-color: #fecaca;
    }

    .badge.neutral {
        background: #f3f4f6;
        color: #374151;
        border-color: #d1d5db;
    }

    .executive {
        margin-top: 22px;
        padding: 18px;
        border-radius: 14px;
        background: var(--soft-blue);
        border-left: 5px solid var(--blue);
        line-height: 1.55;
    }

    .metric-grid {
        margin-top: 22px;
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
        gap: 14px;
    }

    .metric-card {
        background: white;
        border: 1px solid var(--line);
        border-radius: 14px;
        padding: 16px;
    }

    .metric-value {
        font-size: 25px;
        font-weight: 800;
        color: #0f172a;
    }

    .metric-label {
        color: var(--muted);
        margin-top: 6px;
        font-size: 13px;
    }

    .section {
        background: white;
        border: 1px solid var(--line);
        border-radius: 18px;
        padding: 22px;
        margin-top: 20px;
        box-shadow: 0 8px 22px rgba(15, 23, 42, 0.06);
    }

    .section h2 {
        margin: 0 0 16px 0;
        font-size: 20px;
    }

    .zt-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
        gap: 14px;
    }

    .zt-card {
        border: 1px solid var(--line);
        border-radius: 14px;
        padding: 16px;
        background: #fafafa;
        line-height: 1.55;
    }

    .zt-card h3 {
        margin: 0 0 8px 0;
        font-size: 15px;
        color: #334155;
    }

    .card-list {
        display: grid;
        gap: 12px;
    }

    .finding-card {
        border-radius: 14px;
        padding: 16px;
        border-left: 5px solid #64748b;
        background: #f8fafc;
    }

    .finding-card.bad {
        background: var(--soft-red);
        border-left-color: var(--red);
    }

    .finding-card.good {
        background: var(--soft-green);
        border-left-color: var(--green);
    }

    .finding-title {
        font-weight: 800;
        margin-bottom: 8px;
    }

    .finding-detail {
        color: #374151;
        line-height: 1.55;
    }

    .user-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 14px;
    }

    .user-group {
        border: 1px solid var(--line);
        border-radius: 14px;
        padding: 15px;
        background: #fafafa;
    }

    .user-group h3 {
        margin: 0 0 10px 0;
        font-size: 15px;
    }

    .user-group.bad {
        background: var(--soft-red);
    }

    .user-group.warn {
        background: var(--soft-yellow);
    }

    .user-group.good {
        background: var(--soft-green);
    }

    .user-group.neutral {
        background: #f8fafc;
    }

    ul {
        margin: 0;
        padding-left: 18px;
    }

    li {
        margin: 6px 0;
        overflow-wrap: anywhere;
    }

    .table-wrap {
        overflow-x: auto;
        border: 1px solid var(--line);
        border-radius: 14px;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
    }

    th {
        background: #f8fafc;
        text-align: left;
        padding: 11px;
        color: #334155;
        border-bottom: 1px solid var(--line);
    }

    td {
        padding: 10px 11px;
        border-bottom: 1px solid var(--line);
        vertical-align: top;
    }

    tr:last-child td {
        border-bottom: none;
    }

    .muted {
        color: var(--muted);
        font-size: 13px;
    }

    .footer {
        color: #64748b;
        font-size: 12px;
        text-align: center;
        margin-top: 24px;
    }

    @media print {
        .hero {
            background: #0f172a !important;
            -webkit-print-color-adjust: exact;
            print-color-adjust: exact;
        }

        .container {
            margin-top: 20px;
        }

        .section, .summary-panel {
            box-shadow: none;
        }
    }
</style>
</head>
<body>
    <div class="hero">
        <h1>Zero Trust Validation Platform</h1>
        <p>Scenario validation report generated from ZTVP evidence.</p>
    </div>

    <main class="container">
        <section class="summary-panel">
            <div class="top-row">
                <div class="scenario-title">
                    <h2>$scenarioId - $scenarioName</h2>
                    <div class="scenario-meta">
                        <span class="badge neutral">$category</span>
                        <span class="$statusClass">Status: $status</span>
                        <span class="$riskClass">Risk: $risk</span>
                        <span class="badge neutral">$timestamp</span>
                    </div>
                </div>
            </div>

            <div class="executive">
                <strong>Executive Summary:</strong><br>
                $executiveSummary
            </div>

            <div class="metric-grid">
                $metricCards
            </div>
        </section>

        <section class="section">
            <h2>Zero Trust Comparison</h2>
            <div class="zt-grid">
                <div class="zt-card">
                    <h3>Current State</h3>
                    $currentState
                </div>
                <div class="zt-card">
                    <h3>Zero Trust Target</h3>
                    $target
                </div>
                <div class="zt-card">
                    <h3>Gap Summary</h3>
                    $gap
                </div>
            </div>
        </section>

        $findings
        $recommendations
        $scenarioSpecificEvidence
        $affectedAccounts
        $assessedUsersTable

        <div class="footer">
            Generated by Zero Trust Validation Platform (ZTVP). Source JSON: $(ConvertTo-ZTVPHtmlText $JsonPath)
        </div>
    </main>
</body>
</html>
"@

Set-Content -Path $OutputPath -Value $html -Encoding UTF8

Write-Host "HTML report generated:" -ForegroundColor Green
Write-Host $OutputPath -ForegroundColor Cyan

Start-Process $OutputPath





