Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking

function Convert-ZTVPA6ToLowerArray {
    param($Value)

    $result = @()

    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $result += $item.ToString().ToLowerInvariant()
        }
    }

    return $result
}

function Get-ZTVPA6ObjectProperty {
    param(
        [object]$Object,
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        return $null
    }

    $prop = $Object.PSObject.Properties[$PropertyName]

    if ($null -eq $prop) {
        return $null
    }

    return $prop.Value
}

function Test-ZTVPA6HasRealAuthenticationStrength {
    param($GrantControls)

    if ($null -eq $GrantControls) {
        return $false
    }

    $strength = Get-ZTVPA6ObjectProperty -Object $GrantControls -PropertyName "AuthenticationStrength"

    if ($null -eq $strength) {
        return $false
    }

    $id = Get-ZTVPA6ObjectProperty -Object $strength -PropertyName "Id"
    $displayName = Get-ZTVPA6ObjectProperty -Object $strength -PropertyName "DisplayName"

    if (-not [string]::IsNullOrWhiteSpace($id)) {
        return $true
    }

    if (-not [string]::IsNullOrWhiteSpace($displayName)) {
        return $true
    }

    return $false
}

function Get-ZTVPA6GrantControlSummary {
    param($GrantControls)

    $builtIn = @()
    $requiresMfa = $false
    $requiresAuthStrength = $false
    $blocksAccess = $false
    $passwordChangeOnly = $false
    $deviceOnly = $false
    $otherControls = @()

    if ($null -ne $GrantControls) {
        $builtIn = @(Convert-ZTVPA6ToLowerArray -Value $GrantControls.BuiltInControls)
    }

    $requiresAuthStrength = Test-ZTVPA6HasRealAuthenticationStrength -GrantControls $GrantControls
    $requiresMfa = ($builtIn -contains "mfa") -or $requiresAuthStrength
    $blocksAccess = ($builtIn -contains "block")

    $passwordChangeOnly = (
        ($builtIn -contains "passwordchange") -and
        -not ($builtIn -contains "mfa") -and
        -not $requiresAuthStrength
    )

    $deviceControls = @(
        "compliantdevice",
        "domainjoineddevice",
        "hybridazureadjoineddevice",
        "approvedapplication",
        "compliantapplication"
    )

    $hasDeviceControl = $false

    foreach ($control in $builtIn) {
        if ($deviceControls -contains $control) {
            $hasDeviceControl = $true
        }
    }

    $deviceOnly = (
        $hasDeviceControl -and
        -not ($builtIn -contains "mfa") -and
        -not $requiresAuthStrength
    )

    foreach ($control in $builtIn) {
        if ($control -ne "mfa" -and $control -ne "block") {
            $otherControls += $control
        }
    }

    return [PSCustomObject]@{
        built_in_controls              = $builtIn
        built_in_controls_text         = ($builtIn -join ", ")
        requires_mfa                   = [bool]$requiresMfa
        requires_authentication_strength = [bool]$requiresAuthStrength
        blocks_access                  = [bool]$blocksAccess
        password_change_only           = [bool]$passwordChangeOnly
        device_only                    = [bool]$deviceOnly
        other_controls                 = @($otherControls | Sort-Object -Unique)
    }
}

function Get-ZTVPA6UserScope {
    param($UsersCondition)

    if ($null -eq $UsersCondition) {
        return [PSCustomObject]@{
            includes_all_users     = $false
            includes_roles         = $false
            includes_groups        = $false
            includes_users         = $false
            include_users_count    = 0
            include_groups_count   = 0
            include_roles_count    = 0
            has_exclusions         = $false
            excluded_users_count   = 0
            excluded_groups_count  = 0
            excluded_roles_count   = 0
        }
    }

    $includeUsers = @(Convert-ZTVPA6ToLowerArray -Value $UsersCondition.IncludeUsers)
    $includeGroups = @($UsersCondition.IncludeGroups | Where-Object { $null -ne $_ })
    $includeRoles = @($UsersCondition.IncludeRoles | Where-Object { $null -ne $_ })

    $excludeUsers = @($UsersCondition.ExcludeUsers | Where-Object { $null -ne $_ })
    $excludeGroups = @($UsersCondition.ExcludeGroups | Where-Object { $null -ne $_ })
    $excludeRoles = @($UsersCondition.ExcludeRoles | Where-Object { $null -ne $_ })

    return [PSCustomObject]@{
        includes_all_users     = ($includeUsers -contains "all")
        includes_roles         = ($includeRoles.Count -gt 0)
        includes_groups        = ($includeGroups.Count -gt 0)
        includes_users         = ($includeUsers.Count -gt 0)
        include_users_count    = $includeUsers.Count
        include_groups_count   = $includeGroups.Count
        include_roles_count    = $includeRoles.Count
        has_exclusions         = [bool]($excludeUsers.Count -gt 0 -or $excludeGroups.Count -gt 0 -or $excludeRoles.Count -gt 0)
        excluded_users_count   = $excludeUsers.Count
        excluded_groups_count  = $excludeGroups.Count
        excluded_roles_count   = $excludeRoles.Count
    }
}

function Get-ZTVPA6AppScope {
    param($ApplicationsCondition)

    if ($null -eq $ApplicationsCondition) {
        return [PSCustomObject]@{
            includes_all_apps   = $false
            include_apps_count  = 0
            excluded_apps_count = 0
            include_apps_text   = ""
        }
    }

    $includeApps = @(Convert-ZTVPA6ToLowerArray -Value $ApplicationsCondition.IncludeApplications)
    $excludeApps = @($ApplicationsCondition.ExcludeApplications | Where-Object { $null -ne $_ })

    return [PSCustomObject]@{
        includes_all_apps   = ($includeApps -contains "all")
        include_apps_count  = $includeApps.Count
        excluded_apps_count = $excludeApps.Count
        include_apps_text   = ($includeApps -join ", ")
    }
}

function Test-ZTVPA6RiskCondition {
    param($Conditions)

    if ($null -eq $Conditions) {
        return $false
    }

    $signInRisk = @($Conditions.SignInRiskLevels | Where-Object { $null -ne $_ })
    $userRisk = @($Conditions.UserRiskLevels | Where-Object { $null -ne $_ })

    return [bool]($signInRisk.Count -gt 0 -or $userRisk.Count -gt 0)
}

function Test-ZTVPA6LimitedPurposePolicy {
    param(
        [string]$Name,
        $Conditions
    )

    $nameLower = ""

    if (-not [string]::IsNullOrWhiteSpace($Name)) {
        $nameLower = $Name.ToLowerInvariant()
    }

    if ($nameLower -match "securityinfo|security.info|registration|device.registration|deviceregistration|intune|guest|external|ext-|mdca|session") {
        return $true
    }

    return $false
}

function Test-ZTVPA6AdminPolicyName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    return ($Name -match "(?i)admin|adm|privileged|paw|portal")
}

function Invoke-ZTVP-A6 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== A6 - MFA Enforcement Through Conditional Access ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        $policies = @()

        try {
            $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        }
        catch {
            return New-ZTVPResult `
                -ScenarioId "A6" `
                -ScenarioName "MFA Enforcement Through Conditional Access" `
                -Category "Authentication Security" `
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
                -ZeroTrustTarget "MFA should be enforced by enabled Conditional Access policies." `
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

            $enabled = ($state -eq "enabled")
            $reportOnly = ($state -eq "enabledForReportingButNotEnforced")
            $disabled = ($state -eq "disabled")

            $grant = Get-ZTVPA6GrantControlSummary -GrantControls $policy.GrantControls
            $users = Get-ZTVPA6UserScope -UsersCondition $policy.Conditions.Users
            $apps = Get-ZTVPA6AppScope -ApplicationsCondition $policy.Conditions.Applications
            $riskBased = Test-ZTVPA6RiskCondition -Conditions $policy.Conditions
            $limitedPurpose = Test-ZTVPA6LimitedPurposePolicy -Name $policy.DisplayName -Conditions $policy.Conditions
            $adminByName = Test-ZTVPA6AdminPolicyName -Name $policy.DisplayName

            $isMfaPolicy = (
                $grant.requires_mfa -eq $true -and
                $grant.blocks_access -ne $true -and
                $grant.password_change_only -ne $true -and
                $grant.device_only -ne $true
            )

            $isBroadWorkforceMfa = (
                $isMfaPolicy -eq $true -and
                $users.includes_all_users -eq $true -and
                $apps.includes_all_apps -eq $true -and
                $riskBased -ne $true -and
                $limitedPurpose -ne $true
            )

            $isAdminMfa = (
                $isMfaPolicy -eq $true -and
                (
                    $users.includes_roles -eq $true -or
                    $adminByName -eq $true
                ) -and
                $limitedPurpose -ne $true
            )

            $assessedPolicies += [PSCustomObject]@{
                name                                = $policy.DisplayName
                state                               = $state
                enabled                             = $enabled
                report_only                         = $reportOnly
                disabled                            = $disabled

                is_mfa_policy                       = $isMfaPolicy
                is_broad_workforce_mfa_policy       = $isBroadWorkforceMfa
                is_admin_mfa_policy                 = $isAdminMfa
                is_risk_based_policy                = $riskBased
                is_limited_purpose_policy           = $limitedPurpose

                requires_mfa                        = $grant.requires_mfa
                requires_authentication_strength    = $grant.requires_authentication_strength
                blocks_access                       = $grant.blocks_access
                password_change_only                = $grant.password_change_only
                device_only                         = $grant.device_only
                built_in_controls                   = $grant.built_in_controls
                built_in_controls_text              = $grant.built_in_controls_text

                includes_all_users                  = $users.includes_all_users
                includes_roles                      = $users.includes_roles
                includes_groups                     = $users.includes_groups
                includes_users                      = $users.includes_users
                include_users_count                 = $users.include_users_count
                include_groups_count                = $users.include_groups_count
                include_roles_count                 = $users.include_roles_count
                has_exclusions                      = $users.has_exclusions
                excluded_users_count                = $users.excluded_users_count
                excluded_groups_count               = $users.excluded_groups_count
                excluded_roles_count                = $users.excluded_roles_count

                includes_all_apps                   = $apps.includes_all_apps
                include_apps_count                  = $apps.include_apps_count
                excluded_apps_count                 = $apps.excluded_apps_count
                include_apps_text                   = $apps.include_apps_text
            }
        }

        $mfaPolicies = @($assessedPolicies | Where-Object { $_.is_mfa_policy -eq $true })
        $enabledMfaPolicies = @($mfaPolicies | Where-Object { $_.enabled -eq $true })
        $reportOnlyMfaPolicies = @($mfaPolicies | Where-Object { $_.report_only -eq $true })
        $disabledMfaPolicies = @($mfaPolicies | Where-Object { $_.disabled -eq $true })

        $broadWorkforceMfaPolicies = @($mfaPolicies | Where-Object { $_.is_broad_workforce_mfa_policy -eq $true })
        $enabledBroadWorkforceMfaPolicies = @($broadWorkforceMfaPolicies | Where-Object { $_.enabled -eq $true })
        $reportOnlyBroadWorkforceMfaPolicies = @($broadWorkforceMfaPolicies | Where-Object { $_.report_only -eq $true })

        $adminMfaPolicies = @($mfaPolicies | Where-Object { $_.is_admin_mfa_policy -eq $true })
        $enabledAdminMfaPolicies = @($adminMfaPolicies | Where-Object { $_.enabled -eq $true })
        $reportOnlyAdminMfaPolicies = @($adminMfaPolicies | Where-Object { $_.report_only -eq $true })

        $riskBasedMfaPolicies = @($mfaPolicies | Where-Object { $_.is_risk_based_policy -eq $true })
        $limitedPurposeMfaPolicies = @($mfaPolicies | Where-Object { $_.is_limited_purpose_policy -eq $true })

        $enabledMfaPoliciesWithExclusions = @($enabledMfaPolicies | Where-Object { $_.has_exclusions -eq $true })
        $enabledAuthStrengthPolicies = @($enabledMfaPolicies | Where-Object { $_.requires_authentication_strength -eq $true })

        # ----------------------------------------------------
        # Findings
        # ----------------------------------------------------

        if ($mfaPolicies.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No MFA Conditional Access policy detected" `
                -Detail "No Conditional Access policy was detected that explicitly requires MFA or authentication strength."

            $recommendations += New-ZTVPRecommendation `
                -Title "Create MFA Conditional Access enforcement" `
                -Detail "Create an enabled Conditional Access policy that requires MFA for users and critical applications."
        }

        if ($enabledMfaPolicies.Count -eq 0 -and $mfaPolicies.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "MFA Conditional Access policies are not enforced" `
                -Detail "MFA policies exist, but none are enabled. Report-only and disabled policies do not enforce protection."

            $recommendations += New-ZTVPRecommendation `
                -Title "Move MFA policies to enforcement" `
                -Detail "Review report-only results and enable MFA enforcement after validating impact."
        }

        if ($enabledBroadWorkforceMfaPolicies.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No enabled broad workforce MFA policy detected" `
                -Detail "No enabled MFA policy was detected that includes All users, includes All cloud apps, and requires MFA without being limited to registration, guests, session control, or risk-only use."

            $recommendations += New-ZTVPRecommendation `
                -Title "Create or enable broad workforce MFA enforcement" `
                -Detail "Use an enabled Conditional Access policy that includes All users and All cloud apps, requires MFA, and contains only documented exclusions."
        }

        if ($enabledAdminMfaPolicies.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No enabled admin MFA enforcement policy detected" `
                -Detail "No enabled MFA or authentication-strength policy was detected for administrative roles or admin access."

            $recommendations += New-ZTVPRecommendation `
                -Title "Create or enable admin MFA enforcement" `
                -Detail "Use an enabled policy that targets administrative roles or admin portals and requires MFA or phishing-resistant authentication strength."
        }

        if ($reportOnlyBroadWorkforceMfaPolicies.Count -gt 0) {
            $affected = $reportOnlyBroadWorkforceMfaPolicies | ForEach-Object { $_.name }

            $findings += New-ZTVPFinding `
                -Title "Broad workforce MFA policy is report-only" `
                -Detail ("A broad workforce MFA policy exists but is report-only and does not enforce protection. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Move broad workforce MFA from report-only to enabled" `
                -Detail "Validate impact, then enable the broad workforce MFA policy."
        }

        if ($reportOnlyAdminMfaPolicies.Count -gt 0) {
            $affected = $reportOnlyAdminMfaPolicies | ForEach-Object { $_.name }

            $findings += New-ZTVPFinding `
                -Title "Admin MFA policy is report-only" `
                -Detail ("Admin MFA or authentication-strength policy exists but is report-only. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Move admin MFA policy to enforcement" `
                -Detail "Validate impact, then enable admin MFA or phishing-resistant authentication policy."
        }

        if ($disabledMfaPolicies.Count -gt 0) {
            $affected = $disabledMfaPolicies | ForEach-Object { $_.name }

            $findings += New-ZTVPFinding `
                -Title "MFA policies are disabled" `
                -Detail ("Disabled MFA policies do not enforce protection. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review disabled MFA policies" `
                -Detail "Enable required policies after testing or remove stale disabled policies to avoid false confidence."
        }

        if ($enabledMfaPoliciesWithExclusions.Count -gt 0) {
            $affected = $enabledMfaPoliciesWithExclusions | ForEach-Object {
                "$($_.name) [users=$($_.excluded_users_count), groups=$($_.excluded_groups_count), roles=$($_.excluded_roles_count)]"
            }

            $findings += New-ZTVPFinding `
                -Title "Enabled MFA policies contain exclusions" `
                -Detail ("Enabled MFA policies contain exclusions. Affected policies: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review MFA policy exclusions" `
                -Detail "Keep MFA exclusions minimal, documented, justified, and monitored. Avoid excluding normal users or broad groups."
        }

        if ($enabledAuthStrengthPolicies.Count -eq 0 -and $enabledMfaPolicies.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "No enabled authentication-strength policy detected" `
                -Detail "Enabled MFA policies exist, but no enabled policy uses authentication strength. Phishing-resistant enforcement may not be guaranteed."

            $recommendations += New-ZTVPRecommendation `
                -Title "Use authentication strength for high-assurance access" `
                -Detail "Use phishing-resistant authentication strength for privileged or high-risk access where possible."
        }

        if ($limitedPurposeMfaPolicies.Count -gt 0) {
            $affected = $limitedPurposeMfaPolicies | ForEach-Object { $_.name }

            $findings += New-ZTVPFinding `
                -Title "Limited-purpose MFA policies detected" `
                -Detail ("Some MFA policies appear limited to registration, guests, session control, or device workflows and should not be treated as broad MFA enforcement. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Separate limited-purpose MFA from baseline MFA" `
                -Detail "Do not rely on registration, guest-only, risk-only, or session-control policies as proof of broad MFA enforcement."
        }

        # ----------------------------------------------------
        # Result logic
        # ----------------------------------------------------

        $status = "PASS"
        $risk = "LOW"

        if ($mfaPolicies.Count -eq 0 -or $enabledMfaPolicies.Count -eq 0) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif (
            $enabledBroadWorkforceMfaPolicies.Count -eq 0 -and
            $enabledAdminMfaPolicies.Count -eq 0
        ) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif (
            $enabledBroadWorkforceMfaPolicies.Count -eq 0 -or
            $enabledAdminMfaPolicies.Count -eq 0 -or
            $enabledMfaPoliciesWithExclusions.Count -gt 0 -or
            $reportOnlyMfaPolicies.Count -gt 0 -or
            $disabledMfaPolicies.Count -gt 0 -or
            $enabledAuthStrengthPolicies.Count -eq 0
        ) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }

        $currentState = @(
            "Conditional Access policies assessed: $($assessedPolicies.Count)."
            "Explicit MFA or authentication-strength policies detected: $($mfaPolicies.Count)."
            "Enabled MFA policies: $($enabledMfaPolicies.Count)."
            "Report-only MFA policies: $($reportOnlyMfaPolicies.Count)."
            "Disabled MFA policies: $($disabledMfaPolicies.Count)."
            "Enabled broad workforce MFA policies: $($enabledBroadWorkforceMfaPolicies.Count)."
            "Enabled admin MFA policies: $($enabledAdminMfaPolicies.Count)."
            "Enabled MFA policies with exclusions: $($enabledMfaPoliciesWithExclusions.Count)."
            "Enabled authentication-strength policies: $($enabledAuthStrengthPolicies.Count)."
            "Risk-based MFA policies detected: $($riskBasedMfaPolicies.Count)."
            "Limited-purpose MFA policies detected: $($limitedPurposeMfaPolicies.Count)."
        ) -join " "

        $zeroTrustTarget = "MFA should be enforced by enabled Conditional Access policies. Broad workforce access should be covered by an enabled All users and All apps MFA policy, administrative access should be covered by an enabled MFA or authentication-strength policy, exclusions should be minimal and documented, and limited-purpose MFA policies should not be treated as broad enforcement."

        if ($status -eq "PASS") {
            $gapSummary = "MFA Conditional Access enforcement appears aligned with the Zero Trust target."
            $executiveSummary = "MFA enforcement is strong. Enabled Conditional Access policies provide broad workforce and administrative MFA coverage with no major enforcement gaps detected."
        }
        elseif ($status -eq "PARTIAL") {
            $gapSummary = "MFA Conditional Access enforcement is partially aligned, but broad workforce coverage, admin coverage, exclusions, report-only state, disabled policies, or authentication strength require review."
            $executiveSummary = "MFA enforcement is partially controlled. MFA policies exist, but enforcement confidence is reduced by missing broad coverage, missing admin coverage, exclusions, report-only policies, disabled policies, or lack of authentication strength."
        }
        else {
            $gapSummary = "MFA Conditional Access enforcement is not aligned with the target because no effective baseline MFA enforcement was confirmed."
            $executiveSummary = "MFA enforcement is insufficient. The platform did not confirm enabled Conditional Access coverage for broad workforce or administrative MFA enforcement."
        }

        return New-ZTVPResult `
            -ScenarioId "A6" `
            -ScenarioName "MFA Enforcement Through Conditional Access" `
            -Category "Authentication Security" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary                              = $executiveSummary
                conditional_access_policy_count                = $assessedPolicies.Count
                explicit_mfa_policy_count                      = $mfaPolicies.Count
                enabled_mfa_policy_count                       = $enabledMfaPolicies.Count
                report_only_mfa_policy_count                   = $reportOnlyMfaPolicies.Count
                disabled_mfa_policy_count                      = $disabledMfaPolicies.Count
                enabled_broad_workforce_mfa_policy_count       = $enabledBroadWorkforceMfaPolicies.Count
                report_only_broad_workforce_mfa_policy_count   = $reportOnlyBroadWorkforceMfaPolicies.Count
                enabled_admin_mfa_policy_count                 = $enabledAdminMfaPolicies.Count
                report_only_admin_mfa_policy_count             = $reportOnlyAdminMfaPolicies.Count
                enabled_mfa_policy_with_exclusion_count        = $enabledMfaPoliciesWithExclusions.Count
                enabled_authentication_strength_policy_count   = $enabledAuthStrengthPolicies.Count
                risk_based_mfa_policy_count                    = $riskBasedMfaPolicies.Count
                limited_purpose_mfa_policy_count               = $limitedPurposeMfaPolicies.Count

                explicit_mfa_policy_names                      = @($mfaPolicies | ForEach-Object { $_.name })
                enabled_mfa_policy_names                       = @($enabledMfaPolicies | ForEach-Object { $_.name })
                report_only_mfa_policy_names                   = @($reportOnlyMfaPolicies | ForEach-Object { $_.name })
                disabled_mfa_policy_names                      = @($disabledMfaPolicies | ForEach-Object { $_.name })
                enabled_broad_workforce_mfa_policy_names       = @($enabledBroadWorkforceMfaPolicies | ForEach-Object { $_.name })
                report_only_broad_workforce_mfa_policy_names   = @($reportOnlyBroadWorkforceMfaPolicies | ForEach-Object { $_.name })
                enabled_admin_mfa_policy_names                 = @($enabledAdminMfaPolicies | ForEach-Object { $_.name })
                report_only_admin_mfa_policy_names             = @($reportOnlyAdminMfaPolicies | ForEach-Object { $_.name })
                enabled_mfa_policy_with_exclusion_names        = @($enabledMfaPoliciesWithExclusions | ForEach-Object { $_.name })
                enabled_authentication_strength_policy_names   = @($enabledAuthStrengthPolicies | ForEach-Object { $_.name })
                risk_based_mfa_policy_names                    = @($riskBasedMfaPolicies | ForEach-Object { $_.name })
                limited_purpose_mfa_policy_names               = @($limitedPurposeMfaPolicies | ForEach-Object { $_.name })

                assessed_policies                              = $assessedPolicies
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gapSummary
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "A6" `
            -ScenarioName "MFA Enforcement Through Conditional Access" `
            -Category "Authentication Security" `
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
                    -Detail "Review Graph connection, permissions, Conditional Access policy collection, and MFA grant control parsing."
            ) `
            -Evidence $null `
            -CurrentState "The engine could not complete MFA Conditional Access enforcement assessment." `
            -ZeroTrustTarget "MFA should be enforced by enabled Conditional Access policies." `
            -GapSummary "The scenario could not be evaluated because execution failed."
    }
}
