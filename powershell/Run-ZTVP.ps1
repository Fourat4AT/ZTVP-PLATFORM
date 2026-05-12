Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
. "$PSScriptRoot\ScenarioCatalog.ps1"
Import-Module "$PSScriptRoot\Modules\Graph\ZTVP.Connection.psm1" -Force
Import-Module "$PSScriptRoot\Modules\Reporting\ZTVP.Reporting.psm1" -Force

function Show-ZTVPHeader {
    Write-Host ""
    Write-Host "======================================================" -ForegroundColor Yellow
    Write-Host " Zero Trust Validation Platform (ZTVP) - CLI Runner " -ForegroundColor Yellow
    Write-Host "======================================================" -ForegroundColor Yellow
    Write-Host ""
}

function Ensure-ZTVPConnectionInteractive {
    $status = Get-ZTVPGraphStatus

    if ($status.Connected) {
        return $status
    }

    Write-Host "Microsoft Graph is not connected." -ForegroundColor Yellow
    $choice = Read-Host "Do you want to connect now? (Y/N)"

    if ($choice -match '^[Yy]$') {
        . "$PSScriptRoot\connect_graph.ps1"
        return Get-ZTVPGraphStatus
    }

    return $null
}

function Show-ZTVPConnectionInfo {
    param($Status)

    Write-Host "Connected account : $($Status.Account)" -ForegroundColor Green
    Write-Host "Tenant ID         : $($Status.TenantId)" -ForegroundColor Green
    Write-Host ""
}

function Select-ZTVPPillar {
    while ($true) {
        $pillars = Get-ZTVPPillars

        Write-Host "Available Zero Trust Pillars" -ForegroundColor Cyan
        Write-Host "----------------------------" -ForegroundColor Cyan

        for ($i = 0; $i -lt $pillars.Count; $i++) {
            Write-Host "[$($i + 1)] $($pillars[$i].Name)"
        }

        Write-Host "[Q] Quit"
        Write-Host ""

        $choice = Read-Host "Select a pillar"

        if ($choice -eq "Q") { return $null }

        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $pillars.Count) {
                return $pillars[$index]
            }
        }

        Write-Host ""
        Write-Host "Invalid pillar choice." -ForegroundColor Red
        Write-Host ""
    }
}

function Select-ZTVPCategory {
    param($Pillar)

    while ($true) {
        $categories = Get-ZTVPCategoriesByPillar -PillarId $Pillar.Id

        Write-Host ""
        Write-Host "Pillar: $($Pillar.Name)" -ForegroundColor Cyan
        Write-Host "----------------------------" -ForegroundColor Cyan

        for ($i = 0; $i -lt $categories.Count; $i++) {
            Write-Host "[$($i + 1)] $($categories[$i].Name)"
        }

        Write-Host "[B] Back"
        Write-Host "[Q] Quit"
        Write-Host ""

        $choice = Read-Host "Select a category"

        if ($choice -eq "B") { return "BACK" }
        if ($choice -eq "Q") { return $null }

        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $categories.Count) {
                return $categories[$index]
            }
        }

        Write-Host ""
        Write-Host "Invalid category choice." -ForegroundColor Red
        Write-Host ""
    }
}

function Select-ZTVPScenario {
    param($Category)

    while ($true) {
        if ($Category.Name -eq "Baseline Security" -or $Category.Id -match "(?i)baseline|^5$") {
    $allScenarios = @()

    $allScenarios += [PSCustomObject]@{
        ScenarioId   = "B1"
        Name         = "Tenant Security Defaults and Baseline Control Review"
        CategoryId   = $Category.Id
        CategoryName = "Baseline Security"
        PillarId     = "IDENTITY"
        PillarName   = "Identity"
        Objective    = "Validate whether the tenant has a baseline protection model through Security Defaults or enabled custom Conditional Access controls."
        EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B1.ps1"
        FunctionName = "Invoke-ZTVP-B1"
        Implemented  = $true
        Scope        = "Cloud"
        Priority     = "High"
        Phase        = "Phase 1"
    }

    $allScenarios += [PSCustomObject]@{
        ScenarioId   = "B2"
        Name         = "Default User Permissions and App Registration Review"
        CategoryId   = $Category.Id
        CategoryName = "Baseline Security"
        PillarId     = "IDENTITY"
        PillarName   = "Identity"
        Objective    = "Review default user permissions such as app registration, group creation, and directory self-service capabilities."
        EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B2.ps1"
        FunctionName = "Invoke-ZTVP-B2"
        Implemented  = $true
        Scope        = "Cloud"
        Priority     = "High"
        Phase        = "Phase 1"
    }

    $allScenarios += [PSCustomObject]@{
        ScenarioId   = "B3"
        Name         = "User Consent and Enterprise App Baseline Review"
        CategoryId   = $Category.Id
        CategoryName = "Baseline Security"
        PillarId     = "IDENTITY"
        PillarName   = "Identity"
        Objective    = "Review user consent, admin consent workflow, and enterprise application consent baseline posture."
        EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B3.ps1"
        FunctionName = "Invoke-ZTVP-B3"
        Implemented  = $true
        Scope        = "Cloud"
        Priority     = "High"
        Phase        = "Phase 1"
    }

    $allScenarios += [PSCustomObject]@{
        ScenarioId   = "B4"
        Name         = "Password and Account Protection Baseline Review"
        CategoryId   = $Category.Id
        CategoryName = "Baseline Security"
        PillarId     = "IDENTITY"
        PillarName   = "Identity"
        Objective    = "Review password protection, account protection, lockout, and self-service password reset baseline posture."
        EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B4.ps1"
        FunctionName = "Invoke-ZTVP-B4"
        Implemented  = $true
        Scope        = "Cloud"
        Priority     = "Medium"
        Phase        = "Phase 1"
    }

    $allScenarios += [PSCustomObject]@{
        ScenarioId   = "B5"
        Name         = "User Account Hygiene Review"
        CategoryId   = $Category.Id
        CategoryName = "Baseline Security"
        PillarId     = "IDENTITY"
        PillarName   = "Identity"
        Objective    = "Review stale, disabled, guest, unlicensed, and potentially unmanaged user account hygiene indicators."
        EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B5.ps1"
        FunctionName = "Invoke-ZTVP-B5"
        Implemented  = $true
        Scope        = "Cloud"
        Priority     = "Medium"
        Phase        = "Phase 1"
    }
}
else {
    $allScenarios = @(Get-ZTVPScenariosByCategory -CategoryId $Category.Id)
}

        Write-Host ""
        Write-Host "Category: $($Category.Name)" -ForegroundColor Cyan
        Write-Host "----------------------------------------" -ForegroundColor Cyan
        Write-Host "[1] Cloud" -ForegroundColor Cyan
        Write-Host "[2] On-Premises" -ForegroundColor Cyan
        Write-Host "[B] Back"
        Write-Host "[Q] Quit"
        Write-Host ""

        $scopeChoice = Read-Host "Select environment scope"

        if ($scopeChoice -eq "B") { return "BACK" }
        if ($scopeChoice -eq "Q") { return $null }

        $selectedScope = $null

        switch ($scopeChoice) {
            "1" { $selectedScope = "Cloud" }
            "2" { $selectedScope = "On-Premises" }
            default {
                Write-Host ""
                Write-Host "Invalid environment scope." -ForegroundColor Red
                continue
            }
        }

        while ($true) {
            $scenarios = @(
                $allScenarios | Where-Object {
                    $scope = $_.Scope
                    if ([string]::IsNullOrWhiteSpace($scope)) {
                        $scope = "Cloud"
                    }

                    $scope -eq $selectedScope
                }
            )

            Write-Host ""
            Write-Host "Category: $($Category.Name)" -ForegroundColor Cyan
            Write-Host "Environment: $selectedScope" -ForegroundColor Cyan
            Write-Host "----------------------------------------" -ForegroundColor Cyan

            if ($scenarios.Count -eq 0) {
                Write-Host "No scenarios are currently defined for this environment scope." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "[B] Back to environment scope"
                Write-Host "[Q] Quit"
                Write-Host ""

                $emptyChoice = Read-Host "Select an option"

                if ($emptyChoice -eq "B") { break }
                if ($emptyChoice -eq "Q") { return $null }

                Write-Host "Invalid choice." -ForegroundColor Red
                continue
            }

            for ($i = 0; $i -lt $scenarios.Count; $i++) {
                $scenario = $scenarios[$i]

                $statusText = if ($scenario.Implemented) { "READY" } else { "PLANNED" }
                $statusColor = if ($scenario.Implemented) { "Green" } else { "Yellow" }

                $scope = $scenario.Scope
                if ([string]::IsNullOrWhiteSpace($scope)) {
                    $scope = "Cloud"
                }

                $priority = $scenario.Priority
                if ([string]::IsNullOrWhiteSpace($priority)) {
                    $priority = "Not set"
                }

                $phase = $scenario.Phase
                if ([string]::IsNullOrWhiteSpace($phase)) {
                    $phase = "Not set"
                }

                $priorityColor = "White"
                switch ($priority) {
                    "Critical" { $priorityColor = "Red" }
                    "High"     { $priorityColor = "Yellow" }
                    "Medium"   { $priorityColor = "Cyan" }
                    default    { $priorityColor = "White" }
                }

                Write-Host "[$($i + 1)] " -NoNewline
                Write-Host "$($scenario.ScenarioId)" -ForegroundColor Yellow -NoNewline
                Write-Host " - $($scenario.Name) " -NoNewline
                Write-Host "[$statusText]" -ForegroundColor $statusColor

                Write-Host "    Scope    : " -NoNewline
                Write-Host "$scope" -ForegroundColor Cyan

                Write-Host "    Priority : " -NoNewline
                Write-Host "$priority" -ForegroundColor $priorityColor

                Write-Host "    Phase    : $phase"
                Write-Host "    Objective: $($scenario.Objective)" -ForegroundColor DarkGray
                Write-Host ""
            }

            Write-Host "[B] Back to environment scope"
            Write-Host "[Q] Quit"
            Write-Host ""

            $choice = Read-Host "Select a scenario"

            if ($choice -eq "B") { break }
            if ($choice -eq "Q") { return $null }

            if ($choice -match '^\d+$') {
                $index = [int]$choice - 1

                if ($index -ge 0 -and $index -lt $scenarios.Count) {
                    return $scenarios[$index]
                }
            }

            Write-Host ""
            Write-Host "Invalid scenario choice." -ForegroundColor Red
        }
    }
}


function Select-ZTVPOutputMode {
    while ($true) {
        Write-Host ""
        Write-Host "Output Mode" -ForegroundColor Cyan
        Write-Host "-----------" -ForegroundColor Cyan
        Write-Host "[1] Brief"
        Write-Host "[2] Detailed"
        Write-Host ""

        $choice = Read-Host "Select output mode"

        switch ($choice) {
            "1" { return "Brief" }
            "2" { return "Detailed" }
            default { Write-Host "Invalid output mode." -ForegroundColor Red }
        }
    }
}

function Ask-ZTVPSaveReport {
    while ($true) {
        $choice = Read-Host "Do you want to save the report? (Y/N)"
        if ($choice -match '^[Yy]$') { return $true }
        if ($choice -match '^[Nn]$') { return $false }
        Write-Host "Invalid choice." -ForegroundColor Red
    }
}

function Get-ZTVPConsoleColor {
    param([string]$Value)

    switch -Regex ($Value) {
        "PASS|LOW|READY" {
            return "Green"
        }

        "PARTIAL|MEDIUM|HIGH|PLANNED" {
            return "Yellow"
        }

        "FAIL|CRITICAL|ERROR" {
            return "Red"
        }

        default {
            return "White"
        }
    }
}

function Format-ZTVPFindingDetailForConsole {
    param([string]$Detail)

    if ([string]::IsNullOrWhiteSpace($Detail)) {
        return ""
    }

    $clean = $Detail

    $patterns = @(
        "Affected users:",
        "Affected accounts:",
        "Affected user:",
        "Affected account:",
        "Affected members:",
        "Synced accounts detected:"
    )

    foreach ($pattern in $patterns) {
        $idx = $clean.IndexOf($pattern, [System.StringComparison]::OrdinalIgnoreCase)

        if ($idx -ge 0) {
            $clean = $clean.Substring(0, $idx).Trim()
            $clean = $clean.TrimEnd(".", " ")
            $clean = $clean + ". Full affected account details are available in Detailed mode and the HTML report."
            break
        }
    }

    return $clean
}


function Write-ZTVPWrappedText {
    param(
        [string]$Text,
        [int]$Width = 110,
        [string]$Indent = "  ",
        [string]$Color = "White"
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return
    }

    $remaining = $Text.Trim()

    while ($remaining.Length -gt $Width) {
        $cut = $remaining.LastIndexOf(" ", [Math]::Min($Width, $remaining.Length - 1))

        if ($cut -le 0) {
            $cut = $Width
        }

        Write-Host "$Indent$($remaining.Substring(0, $cut).Trim())" -ForegroundColor $Color
        $remaining = $remaining.Substring($cut).Trim()
    }

    if ($remaining.Length -gt 0) {
        Write-Host "$Indent$remaining" -ForegroundColor $Color
    }
}

function Show-ZTVPQuickMetrics_Base {
    param($Result)

    if (-not $Result.evidence) {
        return
    }

    Write-Host ""
    Write-Host "Key Metrics" -ForegroundColor Cyan
    Write-Host "-----------" -ForegroundColor Cyan

    switch ($Result.scenario_id) {
        "A2" {
            Write-Host "Privileged users assessed                  : $($Result.evidence.privileged_users_assessed)"
            Write-Host "Confirmed phishing-resistant users         : $($Result.evidence.phishing_resistant_user_count)" -ForegroundColor Green
            Write-Host "Strong MFA but phishing-resistant unknown  : $($Result.evidence.strong_but_not_confirmed_user_count)" -ForegroundColor Yellow
            Write-Host "Missing MFA users                          : $($Result.evidence.missing_mfa_user_count)" -ForegroundColor Red
            Write-Host "Emergency accounts not phishing-ready      : $($Result.evidence.emergency_without_phishing_resistant_count)" -ForegroundColor Red
        }

        "A3" {
            $assessed = [double]$Result.evidence.standard_users_assessed
            $registered = [double]$Result.evidence.mfa_registered_user_count
            $missing = [double]$Result.evidence.missing_mfa_user_count
            $weak = [double]$Result.evidence.weak_mfa_user_count
            $unknown = [double]$Result.evidence.unknown_mfa_user_count

            $registeredPct = 0
            $missingPct = 0
            $weakPct = 0
            $unknownPct = 0

            if ($assessed -gt 0) {
                $registeredPct = [math]::Round(($registered / $assessed) * 100, 2)
                $missingPct = [math]::Round(($missing / $assessed) * 100, 2)
                $weakPct = [math]::Round(($weak / $assessed) * 100, 2)
                $unknownPct = [math]::Round(($unknown / $assessed) * 100, 2)
            }

            Write-Host "Standard users assessed      : $($Result.evidence.standard_users_assessed)"
            Write-Host "MFA registered               : $($Result.evidence.mfa_registered_user_count) / $($Result.evidence.standard_users_assessed) ($registeredPct%)" -ForegroundColor Green
            Write-Host "Missing MFA                  : $($Result.evidence.missing_mfa_user_count) / $($Result.evidence.standard_users_assessed) ($missingPct%)" -ForegroundColor Red
            Write-Host "Weak MFA-only                : $($Result.evidence.weak_mfa_user_count) / $($Result.evidence.standard_users_assessed) ($weakPct%)" -ForegroundColor Yellow
            Write-Host "Unknown MFA evidence         : $($Result.evidence.unknown_mfa_user_count) / $($Result.evidence.standard_users_assessed) ($unknownPct%)" -ForegroundColor Yellow
            Write-Host "Privileged users excluded    : $($Result.evidence.privileged_users_excluded)"
        }

        "A4" {
            Write-Host "Emergency accounts detected        : $($Result.evidence.emergency_account_count)" -ForegroundColor Yellow
            Write-Host "Active emergency accounts          : $($Result.evidence.active_emergency_account_count)" -ForegroundColor Yellow
            Write-Host "Emergency groups detected          : $($Result.evidence.emergency_group_count)"
            Write-Host "Cloud-only emergency accounts      : $($Result.evidence.cloud_only_emergency_account_count) / $($Result.evidence.emergency_account_count)" -ForegroundColor Green
            Write-Host "Global Admin emergency accounts    : $($Result.evidence.global_admin_emergency_account_count) / $($Result.evidence.emergency_account_count)" -ForegroundColor Yellow
            Write-Host "Missing MFA emergency accounts     : $($Result.evidence.missing_mfa_user_count)" -ForegroundColor Red
            Write-Host "Confirmed phishing-resistant       : $($Result.evidence.phishing_resistant_user_count)" -ForegroundColor Green
            Write-Host "CA-excluded emergency accounts     : $($Result.evidence.ca_excluded_emergency_account_count)" -ForegroundColor Yellow
            Write-Host "Critical backdoor risk accounts    : $($Result.evidence.critical_backdoor_risk_count)" -ForegroundColor Red
            Write-Host "Unexpected emergency group members : $($Result.evidence.unexpected_emergency_group_member_count)" -ForegroundColor Yellow
        }

        default {
            if ($Result.evidence.executive_summary) {
                Write-ZTVPWrappedText -Text $Result.evidence.executive_summary -Indent "  " -Color "White"
            }
        }
    }
}





function Show-ZTVPQuickMetrics {
    param($Result)

    if ($Result.scenario_id -eq "E2" -and $Result.evidence) {
        $e = $Result.evidence

        Write-Host ""
        Write-Host "Privileged Exclusion Snapshot" -ForegroundColor Cyan
        Write-Host "-----------------------------" -ForegroundColor Cyan

        Write-Host "Conditional Access policies assessed       : $($e.conditional_access_policy_count)"
        Write-Host "Policies with any exclusions               : $($e.policy_with_exclusion_count)"
        Write-Host "Privileged users assessed                  : $($e.privileged_user_count)"
        Write-Host "Policies with privileged exclusions        : $($e.privileged_exclusion_policy_count)" -ForegroundColor Yellow
        Write-Host "Enabled policies with privileged exclusions: $($e.enabled_privileged_exclusion_policy_count)" -ForegroundColor Red
        Write-Host "Report-only policies with privileged exclusions: $($e.report_only_privileged_exclusion_policy_count)" -ForegroundColor Yellow
        Write-Host "Direct privileged user exclusions          : $($e.direct_privileged_user_exclusion_count)"
        Write-Host "Privileged role exclusions                 : $($e.privileged_role_exclusion_count)"
        Write-Host "Admin-containing group exclusions          : $($e.admin_group_exclusion_count)"
        Write-Host "Unresolved excluded groups                 : $($e.unresolved_excluded_group_count)"

        Write-Host ""
        Write-Host "Review Targets" -ForegroundColor Cyan
        Write-Host "--------------" -ForegroundColor Cyan

        $hasTargets = $false

        if (@($e.direct_privileged_user_exclusions).Count -gt 0) {
            $hasTargets = $true
            Write-Host "Excluded privileged users:" -ForegroundColor Red
            foreach ($item in @($e.direct_privileged_user_exclusions | Select-Object -First 10)) {
                Write-Host "  - $item"
            }
        }

        if (@($e.privileged_role_exclusions).Count -gt 0) {
            $hasTargets = $true
            Write-Host "Excluded privileged roles:" -ForegroundColor Red
            foreach ($item in @($e.privileged_role_exclusions | Select-Object -First 10)) {
                Write-Host "  - $item"
            }
        }

        if (@($e.admin_group_exclusions).Count -gt 0) {
            $hasTargets = $true
            Write-Host "Excluded groups containing privileged users:" -ForegroundColor Red
            foreach ($item in @($e.admin_group_exclusions | Select-Object -First 10)) {
                Write-Host "  - $item"
            }
        }

        if (-not $hasTargets) {
            Write-Host "No direct privileged user, privileged role, or admin-containing group names were available in brief mode." -ForegroundColor DarkGray
            Write-Host "Use Detailed mode or the E2 HTML report to review policy-level evidence." -ForegroundColor DarkGray
        }

        Write-Host ""
        Write-Host "Report Tip" -ForegroundColor Cyan
        Write-Host "----------" -ForegroundColor Cyan
        Write-Host "Save with Y, then generate the E2 HTML report to see exact policy-to-exclusion mapping." -ForegroundColor DarkGray

        return
    }

    Show-ZTVPQuickMetrics_Base -Result $Result
}

function Show-ZTVPResultBrief {
    param($Result)

    $statusColor = Get-ZTVPConsoleColor -Value $Result.status
    $riskColor = Get-ZTVPConsoleColor -Value $Result.risk

    Write-Host ""
    Write-Host "Result Summary" -ForegroundColor Cyan
    Write-Host "--------------" -ForegroundColor Cyan
    Write-Host "Scenario ID   : $($Result.scenario_id)"
    Write-Host "Scenario Name : $($Result.scenario_name)"

    Write-Host "Status        : " -NoNewline
    Write-Host "$($Result.status)" -ForegroundColor $statusColor

    Write-Host "Risk          : " -NoNewline
    Write-Host "$($Result.risk)" -ForegroundColor $riskColor

    Show-ZTVPQuickMetrics -Result $Result

    Write-Host ""
    Write-Host "Findings" -ForegroundColor Cyan
    Write-Host "--------" -ForegroundColor Cyan

    if ($Result.findings -and @($Result.findings).Count -gt 0) {
        foreach ($finding in @($Result.findings)) {
            Write-Host ""
            Write-Host "[!] $($finding.title)" -ForegroundColor Red
            $detail = Format-ZTVPFindingDetailForConsole -Detail $finding.detail
            Write-ZTVPWrappedText -Text $detail -Indent "    " -Color "White"
        }
    }
    else {
        Write-Host "No findings." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "Recommendations" -ForegroundColor Cyan
    Write-Host "---------------" -ForegroundColor Cyan

    if ($Result.recommendations -and @($Result.recommendations).Count -gt 0) {
        foreach ($recommendation in @($Result.recommendations)) {
            Write-Host ""
            Write-Host "[>] $($recommendation.title)" -ForegroundColor Green
            Write-ZTVPWrappedText -Text $recommendation.detail -Indent "    " -Color "White"
        }
    }
    else {
        Write-Host "No recommendations." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "Report Tip" -ForegroundColor Cyan
    Write-Host "----------" -ForegroundColor Cyan
    Write-Host "Save the report with Y to generate JSON and HTML reports with full account details." -ForegroundColor DarkGray
}


function Show-ZTVPResultDetailed_Base {
    param($Result)

    function Write-ZTVPAccountList {
        param(
            [string]$Title,
            $Users,
            [string]$Color = "White"
        )

        if ($null -eq $Users -or @($Users).Count -eq 0) {
            return
        }

        Write-Host ""
        Write-Host $Title -ForegroundColor $Color
        foreach ($u in @($Users | Sort-Object)) {
            Write-Host "  - $u"
        }
    }

    Show-ZTVPResultBrief -Result $Result

    Write-Host ""
    Write-Host "Executive Summary" -ForegroundColor Cyan
    Write-Host "-----------------" -ForegroundColor Cyan

    if ($Result.evidence -and $Result.evidence.executive_summary) {
        Write-ZTVPWrappedText -Text $Result.evidence.executive_summary -Indent "  " -Color "White"
    }
    else {
        Write-Host "  No executive summary available."
    }

    Write-Host ""
    Write-Host "Zero Trust Comparison" -ForegroundColor Cyan
    Write-Host "---------------------" -ForegroundColor Cyan
    Write-Host "Current State:" -ForegroundColor Cyan
    Write-ZTVPWrappedText -Text $Result.current_state -Indent "  " -Color "White"
    Write-Host ""
    Write-Host "Zero Trust Target:" -ForegroundColor Cyan
    Write-ZTVPWrappedText -Text $Result.zero_trust_target -Indent "  " -Color "White"
    Write-Host ""
    Write-Host "Gap Summary:" -ForegroundColor Cyan
    Write-ZTVPWrappedText -Text $Result.gap_summary -Indent "  " -Color "White"

    if (-not $Result.evidence) {
        return
    }

    Write-Host ""
    Write-Host "Scenario Evidence" -ForegroundColor Cyan
    Write-Host "-----------------" -ForegroundColor Cyan

    switch ($Result.scenario_id) {
        "A4" {
            Write-Host "Emergency Design"
            Write-Host "  Emergency accounts detected        : $($Result.evidence.emergency_account_count)"
            Write-Host "  Active emergency accounts          : $($Result.evidence.active_emergency_account_count)"
            Write-Host "  Emergency groups detected          : $($Result.evidence.emergency_group_count)"
            Write-Host "  Cloud-only emergency accounts      : $($Result.evidence.cloud_only_emergency_account_count) / $($Result.evidence.emergency_account_count)"
            Write-Host "  Global Admin emergency accounts    : $($Result.evidence.global_admin_emergency_account_count) / $($Result.evidence.emergency_account_count)"

            Write-Host ""
            Write-Host "Risk Indicators"
            Write-Host "  Missing MFA emergency accounts     : $($Result.evidence.missing_mfa_user_count)" -ForegroundColor Red
            Write-Host "  Not phishing-resistant ready       : $(@($Result.evidence.emergency_without_phishing_resistant_users).Count)" -ForegroundColor Yellow
            Write-Host "  CA-excluded emergency accounts     : $($Result.evidence.ca_excluded_emergency_account_count)" -ForegroundColor Yellow
            Write-Host "  Critical backdoor risk accounts    : $($Result.evidence.critical_backdoor_risk_count)" -ForegroundColor Red
            Write-Host "  Unexpected emergency group members : $($Result.evidence.unexpected_emergency_group_member_count)" -ForegroundColor Yellow

            Write-Host ""
            Write-Host "Affected Accounts" -ForegroundColor Cyan
            Write-Host "-----------------" -ForegroundColor Cyan

            Write-ZTVPAccountList -Title "Emergency accounts detected:" -Users $Result.evidence.emergency_accounts -Color "White"
            Write-ZTVPAccountList -Title "Missing MFA:" -Users $Result.evidence.missing_mfa_users -Color "Red"
            Write-ZTVPAccountList -Title "Not phishing-resistant ready:" -Users $Result.evidence.emergency_without_phishing_resistant_users -Color "Yellow"
            Write-ZTVPAccountList -Title "CA-excluded emergency accounts:" -Users $Result.evidence.ca_excluded_emergency_accounts -Color "Yellow"
            Write-ZTVPAccountList -Title "Critical backdoor risk accounts:" -Users $Result.evidence.critical_backdoor_risk_accounts -Color "Red"
            Write-ZTVPAccountList -Title "Unexpected emergency group members:" -Users $Result.evidence.unexpected_emergency_group_members -Color "Yellow"
            Write-ZTVPAccountList -Title "Confirmed phishing-resistant:" -Users $Result.evidence.phishing_resistant_users -Color "Green"
            Write-ZTVPAccountList -Title "Strong MFA but phishing-resistant not confirmed:" -Users $Result.evidence.strong_but_not_confirmed_users -Color "Yellow"
        }

        "A3" {
            $assessed = [double]$Result.evidence.standard_users_assessed
            $registered = [double]$Result.evidence.mfa_registered_user_count
            $missing = [double]$Result.evidence.missing_mfa_user_count
            $weak = [double]$Result.evidence.weak_mfa_user_count
            $unknown = [double]$Result.evidence.unknown_mfa_user_count

            $registeredPct = 0
            $missingPct = 0
            $weakPct = 0
            $unknownPct = 0

            if ($assessed -gt 0) {
                $registeredPct = [math]::Round(($registered / $assessed) * 100, 2)
                $missingPct = [math]::Round(($missing / $assessed) * 100, 2)
                $weakPct = [math]::Round(($weak / $assessed) * 100, 2)
                $unknownPct = [math]::Round(($unknown / $assessed) * 100, 2)
            }

            Write-Host "Workforce MFA Coverage"
            Write-Host "  Standard users assessed : $($Result.evidence.standard_users_assessed)"
            Write-Host "  MFA registered          : $($Result.evidence.mfa_registered_user_count) / $($Result.evidence.standard_users_assessed) ($registeredPct%)" -ForegroundColor Green
            Write-Host "  Missing MFA             : $($Result.evidence.missing_mfa_user_count) / $($Result.evidence.standard_users_assessed) ($missingPct%)" -ForegroundColor Red
            Write-Host "  Weak MFA-only           : $($Result.evidence.weak_mfa_user_count) / $($Result.evidence.standard_users_assessed) ($weakPct%)" -ForegroundColor Yellow
            Write-Host "  Unknown MFA evidence    : $($Result.evidence.unknown_mfa_user_count) / $($Result.evidence.standard_users_assessed) ($unknownPct%)" -ForegroundColor Yellow

            Write-Host ""
            Write-Host "Affected Accounts" -ForegroundColor Cyan
            Write-Host "-----------------" -ForegroundColor Cyan
            Write-ZTVPAccountList -Title "Missing MFA users:" -Users $Result.evidence.missing_mfa_users -Color "Red"
            Write-ZTVPAccountList -Title "Weak MFA-only users:" -Users $Result.evidence.weak_mfa_users -Color "Yellow"
            Write-ZTVPAccountList -Title "Unknown MFA evidence users:" -Users $Result.evidence.unknown_mfa_users -Color "Yellow"
        }

        "A2" {
            Write-Host "Privileged Authentication Readiness"
            Write-Host "  Privileged users assessed                  : $($Result.evidence.privileged_users_assessed)"
            Write-Host "  Confirmed phishing-resistant users         : $($Result.evidence.phishing_resistant_user_count)" -ForegroundColor Green
            Write-Host "  Strong MFA but phishing-resistant unknown  : $($Result.evidence.strong_but_not_confirmed_user_count)" -ForegroundColor Yellow
            Write-Host "  Missing MFA users                          : $($Result.evidence.missing_mfa_user_count)" -ForegroundColor Red
            Write-Host "  Emergency accounts not phishing-ready      : $($Result.evidence.emergency_without_phishing_resistant_count)" -ForegroundColor Red

            Write-Host ""
            Write-Host "Affected Accounts" -ForegroundColor Cyan
            Write-Host "-----------------" -ForegroundColor Cyan
            Write-ZTVPAccountList -Title "Missing MFA:" -Users $Result.evidence.missing_mfa_users -Color "Red"
            Write-ZTVPAccountList -Title "Strong MFA but phishing-resistant not confirmed:" -Users $Result.evidence.strong_but_not_confirmed_users -Color "Yellow"
            Write-ZTVPAccountList -Title "Emergency accounts not phishing-ready:" -Users $Result.evidence.emergency_without_phishing_resistant_users -Color "Red"
            Write-ZTVPAccountList -Title "Confirmed phishing-resistant:" -Users $Result.evidence.phishing_resistant_users -Color "Green"
        }

        default {
            Write-Host "No scenario-specific detailed evidence renderer is available yet for $($Result.scenario_id)." -ForegroundColor Yellow
        }
    }
}


function Invoke-ZTVPSelectedScenario {
    param($Scenario)

    Write-Host ""
    Write-Host "Selected Scenario" -ForegroundColor Yellow
    Write-Host "-----------------" -ForegroundColor Yellow
    Write-Host "ID        : $($Scenario.ScenarioId)"
    Write-Host "Name      : $($Scenario.Name)"
    Write-Host "Pillar    : $($Scenario.PillarName)"
    Write-Host "Category  : $($Scenario.CategoryName)"
    $scope = $Scenario.Scope
    if ([string]::IsNullOrWhiteSpace($scope)) { $scope = "Cloud" }
    $priority = $Scenario.Priority
    if ([string]::IsNullOrWhiteSpace($priority)) { $priority = "Not set" }
    $phase = $Scenario.Phase
    if ([string]::IsNullOrWhiteSpace($phase)) { $phase = "Not set" }
    Write-Host "Scope     : $scope"
    Write-Host "Priority  : $priority"
    Write-Host "Phase     : $phase"
    Write-Host "Objective : $($Scenario.Objective)"
    Write-Host ""

    if (-not $Scenario.Implemented) {
        Write-Host "This scenario is not implemented yet." -ForegroundColor Yellow
        Write-Host "For now, it is part of the planned roadmap only." -ForegroundColor Yellow
        Write-Host ""
        return
    }

    $outputMode = Select-ZTVPOutputMode

    $relativeEnginePath = $Scenario.EnginePath
    if ([string]::IsNullOrWhiteSpace($relativeEnginePath)) {
        Write-Host "Scenario has no engine path." -ForegroundColor Red
        Write-Host ""
        return
    }

    if ($relativeEnginePath.StartsWith(".\")) {
        $relativeEnginePath = $relativeEnginePath.Substring(2)
    }

    $projectRoot = Split-Path $PSScriptRoot -Parent
    $enginePath = Join-Path $projectRoot $relativeEnginePath

    if (-not (Test-Path $enginePath)) {
        Write-Host "Engine file not found: $enginePath" -ForegroundColor Red
        Write-Host ""
        return
    }

    $result = $null

    try {
        . $enginePath

        if (-not [string]::IsNullOrWhiteSpace($Scenario.FunctionName) -and (Get-Command -Name $Scenario.FunctionName -ErrorAction SilentlyContinue)) {
            $result = & $Scenario.FunctionName
        }
        else {
            $result = & $enginePath
        }
    }
    catch {
        Write-Host "Engine execution failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        return
    }

    if ($null -eq $result) {
        Write-Host "Scenario returned no result." -ForegroundColor Red
        Write-Host ""
        return
    }

    if ($outputMode -eq "Detailed") {
        Show-ZTVPResultDetailed -Result $result
    }
    else {
        Show-ZTVPResultBrief -Result $result
    }

    Write-Host ""
    $saveReport = Ask-ZTVPSaveReport

    if ($saveReport) {
        $outputPath = Join-Path $PSScriptRoot "Reports\$($Scenario.ScenarioId)-result.json"
        Save-ZTVPResultJson -Result $result -OutputPath $outputPath
        Write-Host "Report saved to: $outputPath" -ForegroundColor Green
    }
    else {
        Write-Host "Report was not saved." -ForegroundColor Yellow
    }

    Write-Host ""
}

function Show-ZTVPResultDetailedA2 {
    param($Result)

    Show-ZTVPResultBrief -Result $Result

    Write-Host ""
    Write-Host "Executive Summary" -ForegroundColor Cyan
    Write-Host "-----------------" -ForegroundColor Cyan
    if ($Result.evidence -and $Result.evidence.executive_summary) {
        Write-Host $Result.evidence.executive_summary
    }
    else {
        Write-Host "No executive summary available."
    }

    Write-Host ""
    Write-Host "Zero Trust Comparison" -ForegroundColor Cyan
    Write-Host "---------------------" -ForegroundColor Cyan
    Write-Host "Current State     : $($Result.current_state)"
    Write-Host "Zero Trust Target : $($Result.zero_trust_target)"
    Write-Host "Gap Summary       : $($Result.gap_summary)"

    Write-Host ""
    Write-Host "Evidence Summary" -ForegroundColor Cyan
    Write-Host "----------------" -ForegroundColor Cyan

    if (-not $Result.evidence) {
        Write-Host "No evidence available."
        return
    }

    Write-Host "Privileged users assessed                       : $($Result.evidence.privileged_users_assessed)"
    Write-Host "Confirmed phishing-resistant users              : $($Result.evidence.phishing_resistant_user_count)"
    Write-Host "Strong MFA but phishing-resistant not confirmed : $($Result.evidence.strong_but_not_confirmed_user_count)"
    Write-Host "Weak or phishable-only users                    : $($Result.evidence.weak_or_phishable_only_user_count)"
    Write-Host "Missing MFA users                               : $($Result.evidence.missing_mfa_user_count)"
    Write-Host "Unknown MFA users                               : $($Result.evidence.unknown_mfa_user_count)"
    Write-Host "Emergency accounts not phishing-ready           : $($Result.evidence.emergency_without_phishing_resistant_count)"

    Write-Host ""
    Write-Host "Affected Accounts" -ForegroundColor Cyan
    Write-Host "-----------------" -ForegroundColor Cyan

    if ($Result.evidence.phishing_resistant_users -and @($Result.evidence.phishing_resistant_users).Count -gt 0) {
        Write-Host "Phishing-resistant:"
        foreach ($u in $Result.evidence.phishing_resistant_users) {
            Write-Host "  - $u"
        }
    }

    if ($Result.evidence.strong_but_not_confirmed_users -and @($Result.evidence.strong_but_not_confirmed_users).Count -gt 0) {
        Write-Host "Strong MFA but phishing-resistant not confirmed:"
        foreach ($u in $Result.evidence.strong_but_not_confirmed_users) {
            Write-Host "  - $u"
        }
    }

    if ($Result.evidence.weak_or_phishable_only_users -and @($Result.evidence.weak_or_phishable_only_users).Count -gt 0) {
        Write-Host "Weak or phishable-only:"
        foreach ($u in $Result.evidence.weak_or_phishable_only_users) {
            Write-Host "  - $u"
        }
    }

    if ($Result.evidence.missing_mfa_users -and @($Result.evidence.missing_mfa_users).Count -gt 0) {
        Write-Host "Missing MFA:"
        foreach ($u in $Result.evidence.missing_mfa_users) {
            Write-Host "  - $u"
        }
    }

    if ($Result.evidence.unknown_mfa_users -and @($Result.evidence.unknown_mfa_users).Count -gt 0) {
        Write-Host "Unknown MFA evidence:"
        foreach ($u in $Result.evidence.unknown_mfa_users) {
            Write-Host "  - $u"
        }
    }

    if ($Result.evidence.emergency_without_phishing_resistant_users -and @($Result.evidence.emergency_without_phishing_resistant_users).Count -gt 0) {
        Write-Host "Emergency accounts not phishing-resistant ready:"
        foreach ($u in $Result.evidence.emergency_without_phishing_resistant_users) {
            Write-Host "  - $u"
        }
    }
}

function Show-ZTVPResultDetailedA3 {
    param($Result)

    Show-ZTVPResultBrief -Result $Result

    Write-Host ""
    Write-Host "Executive Summary" -ForegroundColor Cyan
    Write-Host "-----------------" -ForegroundColor Cyan
    if ($Result.evidence -and $Result.evidence.executive_summary) {
        Write-Host $Result.evidence.executive_summary
    }
    else {
        Write-Host "No executive summary available."
    }

    Write-Host ""
    Write-Host "Zero Trust Comparison" -ForegroundColor Cyan
    Write-Host "---------------------" -ForegroundColor Cyan
    Write-Host "Current State     : $($Result.current_state)"
    Write-Host "Zero Trust Target : $($Result.zero_trust_target)"
    Write-Host "Gap Summary       : $($Result.gap_summary)"

    Write-Host ""
    Write-Host "Evidence Summary" -ForegroundColor Cyan
    Write-Host "----------------" -ForegroundColor Cyan

    if (-not $Result.evidence) {
        Write-Host "No evidence available."
        return
    }

    $assessed = [double]$Result.evidence.standard_users_assessed
    $registered = [double]$Result.evidence.mfa_registered_user_count
    $missing = [double]$Result.evidence.missing_mfa_user_count
    $weak = [double]$Result.evidence.weak_mfa_user_count
    $unknown = [double]$Result.evidence.unknown_mfa_user_count

    $registeredPct = 0
    $missingPct = 0
    $weakPct = 0
    $unknownPct = 0

    if ($assessed -gt 0) {
        $registeredPct = [math]::Round(($registered / $assessed) * 100, 2)
        $missingPct = [math]::Round(($missing / $assessed) * 100, 2)
        $weakPct = [math]::Round(($weak / $assessed) * 100, 2)
        $unknownPct = [math]::Round(($unknown / $assessed) * 100, 2)
    }

    Write-Host "Total enabled member users        : $($Result.evidence.total_enabled_member_users)"
    Write-Host "Privileged users excluded         : $($Result.evidence.privileged_users_excluded)"
    Write-Host "Standard users assessed           : $($Result.evidence.standard_users_assessed)"
    Write-Host ""
    Write-Host "MFA registered users              : $($Result.evidence.mfa_registered_user_count) / $($Result.evidence.standard_users_assessed) ($registeredPct%)" -ForegroundColor Green
    Write-Host "Users missing MFA                 : $($Result.evidence.missing_mfa_user_count) / $($Result.evidence.standard_users_assessed) ($missingPct%)" -ForegroundColor Red
    Write-Host "Weak MFA-only users               : $($Result.evidence.weak_mfa_user_count) / $($Result.evidence.standard_users_assessed) ($weakPct%)" -ForegroundColor Yellow
    Write-Host "Unknown MFA evidence users        : $($Result.evidence.unknown_mfa_user_count) / $($Result.evidence.standard_users_assessed) ($unknownPct%)" -ForegroundColor Yellow

    Write-Host ""
    Write-Host "Affected Accounts" -ForegroundColor Cyan
    Write-Host "-----------------" -ForegroundColor Cyan

    if ($Result.evidence.mfa_registered_users -and @($Result.evidence.mfa_registered_users).Count -gt 0) {
        Write-Host "MFA registered users:"
        foreach ($u in @($Result.evidence.mfa_registered_users | Sort-Object)) {
            Write-Host "  - $u"
        }
    }

    if ($Result.evidence.missing_mfa_users -and @($Result.evidence.missing_mfa_users).Count -gt 0) {
        Write-Host ""
        Write-Host "Missing MFA users:" -ForegroundColor Red
        foreach ($u in @($Result.evidence.missing_mfa_users | Sort-Object)) {
            Write-Host "  - $u"
        }
    }

    if ($Result.evidence.weak_mfa_users -and @($Result.evidence.weak_mfa_users).Count -gt 0) {
        Write-Host ""
        Write-Host "Weak MFA-only users:" -ForegroundColor Yellow
        foreach ($u in @($Result.evidence.weak_mfa_users | Sort-Object)) {
            Write-Host "  - $u"
        }
    }

    if ($Result.evidence.unknown_mfa_users -and @($Result.evidence.unknown_mfa_users).Count -gt 0) {
        Write-Host ""
        Write-Host "Unknown MFA evidence users:" -ForegroundColor Yellow
        foreach ($u in @($Result.evidence.unknown_mfa_users | Sort-Object)) {
            Write-Host "  - $u"
        }
    }
}

Show-ZTVPHeader

$status = Ensure-ZTVPConnectionInteractive
if (-not $status -or -not $status.Connected) {
    Write-Host "No active Graph connection. Exiting." -ForegroundColor Red
    return
}

Show-ZTVPConnectionInfo -Status $status

while ($true) {
    $pillar = Select-ZTVPPillar
    if ($null -eq $pillar) {
        Write-Host ""
        Write-Host "Goodbye." -ForegroundColor Yellow
        Write-Host ""
        break
    }

    while ($true) {
        $category = Select-ZTVPCategory -Pillar $pillar

        if ($null -eq $category) {
            Write-Host ""
            Write-Host "Goodbye." -ForegroundColor Yellow
            Write-Host ""
            return
        }

        if ($category -eq "BACK") {
            Write-Host ""
            break
        }

        while ($true) {
            $scenario = Select-ZTVPScenario -Category $category

            if ($null -eq $scenario) {
                Write-Host ""
                Write-Host "Goodbye." -ForegroundColor Yellow
                Write-Host ""
                return
            }

            if ($scenario -eq "BACK") {
                Write-Host ""
                break
            }

            Invoke-ZTVPSelectedScenario -Scenario $scenario
        }
    }
}

function Write-ZTVPE1PolicyList {
    param(
        [string]$Title,
        $Names,
        [int]$MaxItems = 12,
        [string]$Color = "White"
    )

    $items = @($Names)

    if ($items.Count -eq 0) {
        return
    }

    Write-Host ""
    Write-Host $Title -ForegroundColor $Color

    foreach ($name in @($items | Select-Object -First $MaxItems)) {
        Write-Host "  - $name"
    }

    if ($items.Count -gt $MaxItems) {
        Write-Host "  ... plus $($items.Count - $MaxItems) more. Full list is available in the HTML report." -ForegroundColor DarkGray
    }
}




function Show-ZTVPResultDetailed {
    param($Result)

    if ($Result.scenario_id -ne "E1") {
        Show-ZTVPResultDetailed_Base -Result $Result
        return
    }

    Show-ZTVPResultBrief -Result $Result

    if (-not $Result.evidence) {
        return
    }

    $e = $Result.evidence

    Write-Host ""
    Write-Host "E1 Technical Evidence" -ForegroundColor Cyan
    Write-Host "---------------------" -ForegroundColor Cyan

    Write-Host "Policy State Distribution"
    Write-Host "  Total policies       : $($e.conditional_access_policy_count)"
    Write-Host "  Enabled              : $($e.enabled_policy_count) ($($e.enabled_policy_percent)%)" -ForegroundColor Green
    Write-Host "  Report-only          : $($e.report_only_policy_count) ($($e.report_only_policy_percent)%)" -ForegroundColor Yellow
    Write-Host "  Disabled             : $($e.disabled_policy_count) ($($e.disabled_policy_percent)%)" -ForegroundColor Red
    Write-Host "  With exclusions      : $($e.policy_with_exclusion_count)"
    Write-Host "  Enabled + exclusions : $($e.enabled_policy_with_exclusion_count)" -ForegroundColor Yellow

    Write-Host ""
    Write-Host "Decision Reason" -ForegroundColor Cyan
    Write-Host "---------------" -ForegroundColor Cyan
    Write-ZTVPWrappedText -Text $Result.gap_summary -Indent "  " -Color "White"

    Write-ZTVPE1PolicyList -Title "Report-only policies requiring enforcement review:" -Names $e.report_only_policy_names -Color "Yellow"
    Write-ZTVPE1PolicyList -Title "Disabled policies requiring cleanup/documentation:" -Names $e.disabled_policy_names -Color "Red"
    Write-ZTVPE1PolicyList -Title "Enabled policies with exclusions requiring review:" -Names $e.enabled_policy_with_exclusion_names -Color "Yellow"

    Write-Host ""
    Write-Host "Report Tip" -ForegroundColor Cyan
    Write-Host "----------" -ForegroundColor Cyan
    Write-Host "Save the report with Y, then use the E1 HTML report for the full policy evidence tables." -ForegroundColor DarkGray
}















