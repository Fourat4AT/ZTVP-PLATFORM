Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking

function Convert-ZTVPE1ToLowerArray {
    param($Value)

    $result = @()

    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $result += $item.ToString().ToLowerInvariant()
        }
    }

    return $result
}




function Get-ZTVPE1GrantType {
    param($Policy)

    $labels = @()
    $builtIn = @()

    if ($Policy.GrantControls -and $Policy.GrantControls.BuiltInControls) {
        $builtIn = @(Convert-ZTVPE1ToLowerArray -Value $Policy.GrantControls.BuiltInControls)
    }

    $hasRealAuthStrength = $false

    if ($Policy.GrantControls -and $Policy.GrantControls.AuthenticationStrength) {
        $strength = $Policy.GrantControls.AuthenticationStrength

        $strengthId = $null
        $strengthName = $null

        if ($strength.PSObject.Properties["Id"]) {
            $strengthId = $strength.Id
        }

        if ($strength.PSObject.Properties["DisplayName"]) {
            $strengthName = $strength.DisplayName
        }

        if (-not [string]::IsNullOrWhiteSpace($strengthId) -or -not [string]::IsNullOrWhiteSpace($strengthName)) {
            $hasRealAuthStrength = $true
        }
    }

    if ($builtIn -contains "block") {
        $labels += "Block access"
    }

    if ($builtIn -contains "mfa") {
        $labels += "Require MFA"
    }

    if ($hasRealAuthStrength) {
        $labels += "Authentication Strength"
    }

    if ($builtIn -contains "compliantdevice") {
        $labels += "Require compliant device"
    }

    if ($builtIn -contains "domainjoineddevice" -or $builtIn -contains "hybridazureadjoineddevice") {
        $labels += "Require hybrid/domain joined device"
    }

    if ($builtIn -contains "approvedapplication") {
        $labels += "Require approved client app"
    }

    if ($builtIn -contains "compliantapplication") {
        $labels += "Require app protection policy"
    }

    if ($builtIn -contains "passwordchange") {
        $labels += "Require password change"
    }

    if ($builtIn -contains "termsofuse") {
        $labels += "Require terms of use"
    }

    if ($Policy.SessionControls) {
        $sessionLabels = @()

        if ($Policy.SessionControls.ApplicationEnforcedRestrictions) {
            $sessionLabels += "app-enforced restrictions"
        }

        if ($Policy.SessionControls.CloudAppSecurity) {
            $sessionLabels += "Defender for Cloud Apps"
        }

        if ($Policy.SessionControls.SignInFrequency) {
            $sessionLabels += "sign-in frequency"
        }

        if ($Policy.SessionControls.PersistentBrowser) {
            $sessionLabels += "persistent browser"
        }

        if ($sessionLabels.Count -gt 0) {
            $labels += ("Session control: " + ($sessionLabels -join ", "))
        }
        else {
            $labels += "Session control"
        }
    }

    if ($labels.Count -eq 0 -and $builtIn.Count -gt 0) {
        $labels += ($builtIn -join ", ")
    }

    if ($labels.Count -eq 0) {
        return "Other / Not classified"
    }

    return (($labels | Sort-Object -Unique) -join " + ")
}

function Get-ZTVPE1UserScope {
    param($UsersCondition)

    if ($null -eq $UsersCondition) {
        return [PSCustomObject]@{
            includes_all_users    = $false
            include_users_count   = 0
            include_groups_count  = 0
            include_roles_count   = 0
            has_exclusions        = $false
            excluded_users_count  = 0
            excluded_groups_count = 0
            excluded_roles_count  = 0
        }
    }

    $includeUsers = @(Convert-ZTVPE1ToLowerArray -Value $UsersCondition.IncludeUsers)
    $includeGroups = @($UsersCondition.IncludeGroups | Where-Object { $null -ne $_ })
    $includeRoles = @($UsersCondition.IncludeRoles | Where-Object { $null -ne $_ })

    $excludeUsers = @($UsersCondition.ExcludeUsers | Where-Object { $null -ne $_ })
    $excludeGroups = @($UsersCondition.ExcludeGroups | Where-Object { $null -ne $_ })
    $excludeRoles = @($UsersCondition.ExcludeRoles | Where-Object { $null -ne $_ })

    return [PSCustomObject]@{
        includes_all_users    = ($includeUsers -contains "all")
        include_users_count   = $includeUsers.Count
        include_groups_count  = $includeGroups.Count
        include_roles_count   = $includeRoles.Count
        has_exclusions        = [bool]($excludeUsers.Count -gt 0 -or $excludeGroups.Count -gt 0 -or $excludeRoles.Count -gt 0)
        excluded_users_count  = $excludeUsers.Count
        excluded_groups_count = $excludeGroups.Count
        excluded_roles_count  = $excludeRoles.Count
    }
}

function Get-ZTVPE1AppScope {
    param($ApplicationsCondition)

    if ($null -eq $ApplicationsCondition) {
        return [PSCustomObject]@{
            includes_all_apps   = $false
            include_apps_count  = 0
            excluded_apps_count = 0
        }
    }

    $includeApps = @(Convert-ZTVPE1ToLowerArray -Value $ApplicationsCondition.IncludeApplications)
    $excludeApps = @($ApplicationsCondition.ExcludeApplications | Where-Object { $null -ne $_ })

    return [PSCustomObject]@{
        includes_all_apps   = ($includeApps -contains "all")
        include_apps_count  = $includeApps.Count
        excluded_apps_count = $excludeApps.Count
    }
}

function Invoke-ZTVP-E1 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== E1 - Conditional Access Policy State Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        try {
            $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        }
        catch {
            return New-ZTVPResult `
                -ScenarioId "E1" `
                -ScenarioName "Conditional Access Policy State Review" `
                -Category "Access Enforcement" `
                -Status "ERROR" `
                -Risk "CRITICAL" `
                -Findings @(
                    New-ZTVPFinding `
                        -Title "Conditional Access evidence unavailable" `
                        -Detail $_.Exception.Message
                ) `
                -Recommendations @(
                    New-ZTVPRecommendation `
                        -Title "Fix Conditional Access collection" `
                        -Detail "Grant or consent the required Microsoft Graph permissions to read Conditional Access policies."
                ) `
                -Evidence $null `
                -CurrentState "Conditional Access policies could not be collected." `
                -ZeroTrustTarget "Conditional Access policies should be intentionally managed, with production controls enabled and report-only/disabled policies reviewed." `
                -GapSummary "The scenario could not be evaluated because Conditional Access evidence was unavailable."
        }

        $assessedPolicies = @()

        foreach ($policy in $policies) {
            if ($null -eq $policy) {
                continue
            }

            $state = ""
            if ($null -ne $policy.State) {
                $state = $policy.State.ToString()
            }

            $isEnabled = ($state -eq "enabled")
            $isReportOnly = ($state -eq "enabledForReportingButNotEnforced")
            $isDisabled = ($state -eq "disabled")

            $grantType = Get-ZTVPE1GrantType -Policy $policy
            $userScope = Get-ZTVPE1UserScope -UsersCondition $policy.Conditions.Users
            $appScope = Get-ZTVPE1AppScope -ApplicationsCondition $policy.Conditions.Applications

            $assessedPolicies += [PSCustomObject]@{
                name                  = $policy.DisplayName
                state                 = $state
                enabled               = $isEnabled
                report_only           = $isReportOnly
                disabled              = $isDisabled
                grant_type            = $grantType

                includes_all_users    = $userScope.includes_all_users
                include_users_count   = $userScope.include_users_count
                include_groups_count  = $userScope.include_groups_count
                include_roles_count   = $userScope.include_roles_count
                has_exclusions        = $userScope.has_exclusions
                excluded_users_count  = $userScope.excluded_users_count
                excluded_groups_count = $userScope.excluded_groups_count
                excluded_roles_count  = $userScope.excluded_roles_count

                includes_all_apps     = $appScope.includes_all_apps
                include_apps_count    = $appScope.include_apps_count
                excluded_apps_count   = $appScope.excluded_apps_count
            }
        }

        $enabledPolicies = @($assessedPolicies | Where-Object { $_.enabled -eq $true })
        $reportOnlyPolicies = @($assessedPolicies | Where-Object { $_.report_only -eq $true })
        $disabledPolicies = @($assessedPolicies | Where-Object { $_.disabled -eq $true })
        $policiesWithExclusions = @($assessedPolicies | Where-Object { $_.has_exclusions -eq $true })
        $enabledPoliciesWithExclusions = @($enabledPolicies | Where-Object { $_.has_exclusions -eq $true })

        $totalPolicies = $assessedPolicies.Count

        $enabledPercent = 0
        $reportOnlyPercent = 0
        $disabledPercent = 0

        if ($totalPolicies -gt 0) {
            $enabledPercent = [math]::Round(($enabledPolicies.Count / $totalPolicies) * 100, 2)
            $reportOnlyPercent = [math]::Round(($reportOnlyPolicies.Count / $totalPolicies) * 100, 2)
            $disabledPercent = [math]::Round(($disabledPolicies.Count / $totalPolicies) * 100, 2)
        }

        if ($totalPolicies -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No Conditional Access policies detected" `
                -Detail "No Conditional Access policies were found in the tenant."

            $recommendations += New-ZTVPRecommendation `
                -Title "Create Conditional Access baseline" `
                -Detail "Create baseline Conditional Access policies for MFA, legacy authentication blocking, privileged access, device trust, and session protection."
        }

        if ($totalPolicies -gt 0 -and $enabledPolicies.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No enabled Conditional Access policies detected" `
                -Detail "Conditional Access policies exist, but none are enabled. Report-only and disabled policies do not enforce protection."

            $recommendations += New-ZTVPRecommendation `
                -Title "Move validated policies to enforcement" `
                -Detail "Review report-only impact and enable production Conditional Access policies after validation."
        }

        if ($reportOnlyPolicies.Count -gt 0) {
            $affected = $reportOnlyPolicies | ForEach-Object { $_.name }

            $findings += New-ZTVPFinding `
                -Title "Report-only Conditional Access policies detected" `
                -Detail ("Report-only policies do not enforce protection. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review report-only policies" `
                -Detail "Keep report-only mode for testing only. Move validated policies to enabled state or remove stale report-only policies."
        }

        if ($disabledPolicies.Count -gt 0) {
            $affected = $disabledPolicies | ForEach-Object { $_.name }

            $findings += New-ZTVPFinding `
                -Title "Disabled Conditional Access policies detected" `
                -Detail ("Disabled policies do not enforce protection and may create false confidence. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review disabled policies" `
                -Detail "Remove stale disabled policies or document why they are retained. Production security controls should not remain disabled."
        }

        if ($reportOnlyPolicies.Count -gt $enabledPolicies.Count -and $totalPolicies -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "More report-only policies than enabled policies" `
                -Detail "The tenant has more report-only Conditional Access policies than enabled policies. This suggests controls may still be in testing rather than enforcement."

            $recommendations += New-ZTVPRecommendation `
                -Title "Prioritize enforcement readiness" `
                -Detail "Review report-only policies by priority and move validated baseline protections to enabled state."
        }

        if ($enabledPoliciesWithExclusions.Count -gt 0) {
            $affected = $enabledPoliciesWithExclusions | ForEach-Object {
                "$($_.name) [users=$($_.excluded_users_count), groups=$($_.excluded_groups_count), roles=$($_.excluded_roles_count)]"
            }

            $findings += New-ZTVPFinding `
                -Title "Enabled Conditional Access policies contain exclusions" `
                -Detail ("Some enabled policies contain exclusions. Affected policies: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Track Conditional Access exclusions" `
                -Detail "Document exclusions and review them regularly. Exclusions should be minimal, justified, and monitored."
        }

        $status = "PASS"
        $risk = "LOW"

        if ($totalPolicies -eq 0 -or $enabledPolicies.Count -eq 0) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif ($reportOnlyPolicies.Count -gt 0 -or $disabledPolicies.Count -gt 0 -or $enabledPoliciesWithExclusions.Count -gt 0) {
            $status = "PARTIAL"

            if ($reportOnlyPolicies.Count -gt $enabledPolicies.Count) {
                $risk = "HIGH"
            }
            else {
                $risk = "MEDIUM"
            }
        }

        $currentState = @(
            "Conditional Access policies assessed: $totalPolicies."
            "Enabled policies: $($enabledPolicies.Count) ($enabledPercent%)."
            "Report-only policies: $($reportOnlyPolicies.Count) ($reportOnlyPercent%)."
            "Disabled policies: $($disabledPolicies.Count) ($disabledPercent%)."
            "Policies with exclusions: $($policiesWithExclusions.Count)."
            "Enabled policies with exclusions: $($enabledPoliciesWithExclusions.Count)."
        ) -join " "

        $zeroTrustTarget = "Conditional Access policies should be intentionally managed. Production controls should be enabled, report-only policies should be used only for testing, disabled policies should be removed or documented, and exclusions should be minimal and reviewed."

        if ($status -eq "PASS") {
            $gapSummary = "Conditional Access policy state appears aligned with the Zero Trust target."
            $executiveSummary = "Conditional Access policy governance is strong. Policies are enabled and no major report-only, disabled, or exclusion-related state issues were detected."
        }
        elseif ($status -eq "PARTIAL") {
            $gapSummary = "Conditional Access policy state is partially aligned, but report-only policies, disabled policies, or exclusions require review."
            $executiveSummary = "Conditional Access governance is partially controlled. Enabled policies exist, but report-only policies, disabled policies, or exclusions reduce enforcement confidence."
        }
        else {
            $gapSummary = "Conditional Access policy state is not aligned with the target because no effective enabled Conditional Access enforcement was confirmed."
            $executiveSummary = "Conditional Access governance is insufficient. The platform did not confirm enabled Conditional Access enforcement."
        }

        return New-ZTVPResult `
            -ScenarioId "E1" `
            -ScenarioName "Conditional Access Policy State Review" `
            -Category "Access Enforcement" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary                   = $executiveSummary
                conditional_access_policy_count     = $totalPolicies
                enabled_policy_count                = $enabledPolicies.Count
                report_only_policy_count            = $reportOnlyPolicies.Count
                disabled_policy_count               = $disabledPolicies.Count
                policy_with_exclusion_count         = $policiesWithExclusions.Count
                enabled_policy_with_exclusion_count = $enabledPoliciesWithExclusions.Count
                enabled_policy_percent              = $enabledPercent
                report_only_policy_percent          = $reportOnlyPercent
                disabled_policy_percent             = $disabledPercent

                enabled_policy_names                = @($enabledPolicies | ForEach-Object { $_.name })
                report_only_policy_names            = @($reportOnlyPolicies | ForEach-Object { $_.name })
                disabled_policy_names               = @($disabledPolicies | ForEach-Object { $_.name })
                enabled_policy_with_exclusion_names = @($enabledPoliciesWithExclusions | ForEach-Object { $_.name })

                assessed_policies                   = $assessedPolicies
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gapSummary
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "E1" `
            -ScenarioName "Conditional Access Policy State Review" `
            -Category "Access Enforcement" `
            -Status "ERROR" `
            -Risk "CRITICAL" `
            -Findings @(
                New-ZTVPFinding `
                    -Title "Execution error" `
                    -Detail $_.Exception.Message
            ) `
            -Recommendations @(
                New-ZTVPRecommendation `
                    -Title "Fix execution issue" `
                    -Detail "Review Graph connection, permissions, and Conditional Access policy collection."
            ) `
            -Evidence $null `
            -CurrentState "The engine could not complete Conditional Access policy state assessment." `
            -ZeroTrustTarget "Conditional Access policies should be intentionally managed and enforced." `
            -GapSummary "The scenario could not be evaluated because execution failed."
    }
}

