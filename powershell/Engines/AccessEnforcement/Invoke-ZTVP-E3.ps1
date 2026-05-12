Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking

function Convert-ZTVPE3ToLowerArray {
    param($Value)

    $result = @()

    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $result += $item.ToString().ToLowerInvariant()
        }
    }

    return $result
}

function Test-ZTVPE3HasAuthenticationStrength {
    param($GrantControls)

    if ($null -eq $GrantControls) {
        return $false
    }

    if ($null -eq $GrantControls.AuthenticationStrength) {
        return $false
    }

    $strength = $GrantControls.AuthenticationStrength
    $id = $null
    $displayName = $null

    if ($strength.PSObject.Properties["Id"]) {
        $id = $strength.Id
    }

    if ($strength.PSObject.Properties["DisplayName"]) {
        $displayName = $strength.DisplayName
    }

    return (-not [string]::IsNullOrWhiteSpace($id) -or -not [string]::IsNullOrWhiteSpace($displayName))
}

function Get-ZTVPE3PolicyStateLabel {
    param([string]$State)

    switch ($State) {
        "enabled" { return "Enabled" }
        "enabledForReportingButNotEnforced" { return "Report-only" }
        "disabled" { return "Disabled" }
        default { return $State }
    }
}

function Get-ZTVPE3PolicyScope {
    param($Policy)

    $includeUsers = @()
    $includeGroups = @()
    $includeRoles = @()
    $includeApps = @()
    $clientAppTypes = @()
    $includeLocations = @()
    $excludeLocations = @()
    $includePlatforms = @()

    if ($Policy.Conditions -and $Policy.Conditions.Users) {
        $includeUsers = @(Convert-ZTVPE3ToLowerArray -Value $Policy.Conditions.Users.IncludeUsers)
        $includeGroups = @($Policy.Conditions.Users.IncludeGroups | Where-Object { $null -ne $_ })
        $includeRoles = @($Policy.Conditions.Users.IncludeRoles | Where-Object { $null -ne $_ })
    }

    if ($Policy.Conditions -and $Policy.Conditions.Applications) {
        $includeApps = @(Convert-ZTVPE3ToLowerArray -Value $Policy.Conditions.Applications.IncludeApplications)
    }

    if ($Policy.Conditions -and $Policy.Conditions.ClientAppTypes) {
        $clientAppTypes = @(Convert-ZTVPE3ToLowerArray -Value $Policy.Conditions.ClientAppTypes)
    }

    if ($Policy.Conditions -and $Policy.Conditions.Locations) {
        $includeLocations = @($Policy.Conditions.Locations.IncludeLocations | Where-Object { $null -ne $_ })
        $excludeLocations = @($Policy.Conditions.Locations.ExcludeLocations | Where-Object { $null -ne $_ })
    }

    if ($Policy.Conditions -and $Policy.Conditions.Platforms) {
        $includePlatforms = @(Convert-ZTVPE3ToLowerArray -Value $Policy.Conditions.Platforms.IncludePlatforms)
    }

    $signInRisk = @()
    $userRisk = @()

    if ($Policy.Conditions) {
        $signInRisk = @($Policy.Conditions.SignInRiskLevels | Where-Object { $null -ne $_ })
        $userRisk = @($Policy.Conditions.UserRiskLevels | Where-Object { $null -ne $_ })
    }

    $name = ""
    if ($Policy.DisplayName) {
        $name = $Policy.DisplayName.ToLowerInvariant()
    }

    $isAdminNamed = ($name -match "admin|adm|privileged|paw|portal")
    $isRiskBased = [bool]($signInRisk.Count -gt 0 -or $userRisk.Count -gt 0)
    $hasLocationCondition = [bool]($includeLocations.Count -gt 0 -or $excludeLocations.Count -gt 0)
    $hasPlatformCondition = [bool]($includePlatforms.Count -gt 0)

    return [PSCustomObject]@{
        includes_all_users     = ($includeUsers -contains "all")
        includes_roles         = ($includeRoles.Count -gt 0)
        includes_groups        = ($includeGroups.Count -gt 0)
        includes_all_apps      = ($includeApps -contains "all")
        include_users_count    = $includeUsers.Count
        include_groups_count   = $includeGroups.Count
        include_roles_count    = $includeRoles.Count
        include_apps_count     = $includeApps.Count
        client_app_types       = $clientAppTypes
        is_admin_scope         = [bool]($includeRoles.Count -gt 0 -or $isAdminNamed)
        is_risk_based          = $isRiskBased
        has_location_condition = $hasLocationCondition
        has_platform_condition = $hasPlatformCondition
    }
}




function Test-ZTVPE3HasRealSessionControl {
    param($Policy)

    if ($null -eq $Policy -or $null -eq $Policy.SessionControls) {
        return $false
    }

    $sc = $Policy.SessionControls

    $sessionProps = @(
        "ApplicationEnforcedRestrictions",
        "CloudAppSecurity",
        "SignInFrequency",
        "PersistentBrowser",
        "DisableResilienceDefaults",
        "ContinuousAccessEvaluation"
    )

    foreach ($propName in $sessionProps) {
        $prop = $sc.PSObject.Properties[$propName]

        if ($null -ne $prop -and $null -ne $prop.Value) {
            if ($prop.Value -is [bool]) {
                if ($prop.Value -eq $true) {
                    return $true
                }
            }
            else {
                return $true
            }
        }
    }

    if ($sc.PSObject.Properties["AdditionalProperties"] -and $sc.AdditionalProperties) {
        foreach ($key in $sc.AdditionalProperties.Keys) {
            if ($null -ne $sc.AdditionalProperties[$key]) {
                return $true
            }
        }
    }

    return $false
}

function Get-ZTVPE3PolicyClassification {
    param($Policy)

    $name = ""
    if ($Policy.DisplayName) {
        $name = $Policy.DisplayName.ToLowerInvariant()
    }

    $builtIn = @()

    if ($Policy.GrantControls -and $Policy.GrantControls.BuiltInControls) {
        $builtIn = @(Convert-ZTVPE3ToLowerArray -Value $Policy.GrantControls.BuiltInControls)
    }

    $scope = Get-ZTVPE3PolicyScope -Policy $Policy

    $hasAuthStrength = Test-ZTVPE3HasAuthenticationStrength -GrantControls $Policy.GrantControls

    $nameLooksLikeMfa = [bool](
        $name -match "mfa" -or
        $name -match "duomfa" -or
        $name -match "duo" -or
        $name -match "phishres" -or
        $name -match "phish-res" -or
        $name -match "passwordless" -or
        $name -match "fido"
    )

    $hasMfa = [bool]($builtIn -contains "mfa" -or $hasAuthStrength -or $nameLooksLikeMfa)
    $hasBlock = ($builtIn -contains "block")
    $hasPasswordChange = ($builtIn -contains "passwordchange")

    $hasTermsOfUse = [bool](
        $builtIn -contains "termsofuse" -or
        $name -match "termsofuse" -or
        $name -match "terms of use"
    )

    $hasDeviceControl = [bool](
        $builtIn -contains "compliantdevice" -or
        $builtIn -contains "domainjoineddevice" -or
        $builtIn -contains "hybridazureadjoineddevice" -or
        $builtIn -contains "approvedapplication" -or
        $builtIn -contains "compliantapplication"
    )

    $hasLegacyClient = [bool](
        $scope.client_app_types -contains "exchangeactivesync" -or
        $scope.client_app_types -contains "other"
    )

    $hasRealSessionControl = Test-ZTVPE3HasRealSessionControl -Policy $Policy

    $nameLooksLikeSession = [bool](
        $name -match "session" -or
        $name -match "signinfrequency" -or
        $name -match "sign-in" -or
        $name -match "persistent" -or
        $name -match "mdca" -or
        $name -match "appcontrol" -or
        $name -match "app control"
    )

    $hasSessionControl = [bool]($hasRealSessionControl -or $nameLooksLikeSession)

    $purposeKey = "other"
    $purpose = "Other / Not classified"
    $severity = "LOW"
    $isImportant = $false

    if (($name -match "legacy|legacyauth|legacy auth") -or ($hasBlock -and $hasLegacyClient)) {
        $purposeKey = "legacy_auth_block"
        $purpose = "Legacy authentication blocking"
        $severity = "CRITICAL"
        $isImportant = $true
    }
    elseif ($name -match "devicecode|device code") {
        $purposeKey = "device_code_block"
        $purpose = "Device code authentication blocking"
        $severity = "HIGH"
        $isImportant = $true
    }
    elseif ($hasMfa -and $scope.is_admin_scope) {
        if ($hasAuthStrength -or $name -match "phish|passwordless|fido|phishres") {
            $purposeKey = "admin_phishing_resistant_mfa"
            $purpose = "Admin phishing-resistant MFA / authentication strength"
            $severity = "CRITICAL"
        }
        else {
            $purposeKey = "admin_mfa"
            $purpose = "Admin MFA enforcement"
            $severity = "CRITICAL"
        }

        $isImportant = $true
    }
    elseif ($hasMfa -and $scope.includes_all_users -and $scope.includes_all_apps -and -not $scope.is_risk_based) {
        $purposeKey = "baseline_mfa"
        $purpose = "Broad workforce MFA enforcement"
        $severity = "CRITICAL"
        $isImportant = $true
    }
    elseif ($hasMfa -and $scope.is_risk_based) {
        $purposeKey = "risk_based_mfa"
        $purpose = "Risk-based MFA or risk response"
        $severity = "HIGH"
        $isImportant = $true
    }
    elseif ($hasPasswordChange -and $scope.is_risk_based) {
        $purposeKey = "user_risk_password_change"
        $purpose = "User risk password change response"
        $severity = "HIGH"
        $isImportant = $true
    }
    elseif ($hasDeviceControl -and $scope.is_admin_scope) {
        $purposeKey = "admin_device_trust"
        $purpose = "Admin device trust enforcement"
        $severity = "HIGH"
        $isImportant = $true
    }
    elseif ($hasDeviceControl) {
        $purposeKey = "device_trust"
        $purpose = "Device trust / compliance enforcement"
        $severity = "HIGH"
        $isImportant = $true
    }
    elseif ($hasBlock -and ($scope.has_location_condition -or $name -match "location|untrusted|trusted")) {
        $purposeKey = "location_block"
        $purpose = "Location-based blocking"
        $severity = "HIGH"
        $isImportant = $true
    }
    elseif ($hasBlock -and ($scope.has_platform_condition -or $name -match "unsupportedplatform|unsupported platform|platform")) {
        $purposeKey = "platform_block"
        $purpose = "Unsupported platform blocking"
        $severity = "HIGH"
        $isImportant = $true
    }
    elseif ($hasBlock -and $scope.is_admin_scope) {
        $purposeKey = "admin_block"
        $purpose = "Admin access blocking control"
        $severity = "HIGH"
        $isImportant = $true
    }
    elseif ($hasBlock) {
        $purposeKey = "general_block"
        $purpose = "General blocking control"
        $severity = "HIGH"
        $isImportant = $true
    }
    elseif ($hasTermsOfUse) {
        $purposeKey = "terms_of_use"
        $purpose = "Terms of use"
        $severity = "LOW"
        $isImportant = $false
    }
    elseif ($hasSessionControl) {
        $purposeKey = "session_control"
        $purpose = "Session control / app control"
        $severity = "MEDIUM"
        $isImportant = $true
    }
    elseif ($hasMfa) {
        $purposeKey = "mfa_other"
        $purpose = "MFA enforcement"
        $severity = "HIGH"
        $isImportant = $true
    }

    return [PSCustomObject]@{
        purpose_key             = $purposeKey
        purpose                 = $purpose
        severity                = $severity
        important               = $isImportant
        built_in_controls       = $builtIn
        has_mfa                 = $hasMfa
        has_auth_strength       = $hasAuthStrength
        has_block               = $hasBlock
        has_device_control      = $hasDeviceControl
        has_session_control     = $hasSessionControl
        includes_all_users      = $scope.includes_all_users
        includes_all_apps       = $scope.includes_all_apps
        is_admin_scope          = $scope.is_admin_scope
        is_risk_based           = $scope.is_risk_based
        has_location_condition  = $scope.has_location_condition
        has_platform_condition  = $scope.has_platform_condition
    }
}

function Invoke-ZTVP-E3 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== E3 - Report-Only Policy Dependency Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        try {
            $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        }
        catch {
            return New-ZTVPResult `
                -ScenarioId "E3" `
                -ScenarioName "Report-Only Policy Dependency Review" `
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
                        -Detail "Grant or consent permissions to read Conditional Access policies, then rerun E3."
                ) `
                -Evidence $null `
                -CurrentState "Conditional Access policies could not be collected." `
                -ZeroTrustTarget "Important Conditional Access protections should be enabled, not only report-only." `
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

            $classification = Get-ZTVPE3PolicyClassification -Policy $policy

            $assessedPolicies += [PSCustomObject]@{
                name                    = $policy.DisplayName
                state                   = $state
                state_label             = Get-ZTVPE3PolicyStateLabel -State $state
                enabled                 = ($state -eq "enabled")
                report_only             = ($state -eq "enabledForReportingButNotEnforced")
                disabled                = ($state -eq "disabled")

                purpose_key             = $classification.purpose_key
                purpose                 = $classification.purpose
                severity                = $classification.severity
                important               = $classification.important

                has_mfa                 = $classification.has_mfa
                has_auth_strength       = $classification.has_auth_strength
                has_block               = $classification.has_block
                has_device_control      = $classification.has_device_control
                has_session_control     = $classification.has_session_control

                includes_all_users      = $classification.includes_all_users
                includes_all_apps       = $classification.includes_all_apps
                is_admin_scope          = $classification.is_admin_scope
                is_risk_based           = $classification.is_risk_based
                has_location_condition  = $classification.has_location_condition
                has_platform_condition  = $classification.has_platform_condition

                enabled_alternative_exists = $false
                enabled_alternative_policy_names = @()
            }
        }

        $enabledImportant = @($assessedPolicies | Where-Object { $_.enabled -eq $true -and $_.important -eq $true })
        $reportOnlyPolicies = @($assessedPolicies | Where-Object { $_.report_only -eq $true })
        $reportOnlyImportant = @($assessedPolicies | Where-Object { $_.report_only -eq $true -and $_.important -eq $true })

        foreach ($policy in $reportOnlyImportant) {
            $alternatives = @($enabledImportant | Where-Object { $_.purpose_key -eq $policy.purpose_key })

            if ($alternatives.Count -gt 0) {
                $policy.enabled_alternative_exists = $true
                $policy.enabled_alternative_policy_names = @($alternatives | ForEach-Object { $_.name })
            }
        }

        $criticalReportOnly = @($reportOnlyImportant | Where-Object { $_.severity -eq "CRITICAL" })
        $highReportOnly = @($reportOnlyImportant | Where-Object { $_.severity -eq "HIGH" })
        $mediumReportOnly = @($reportOnlyImportant | Where-Object { $_.severity -eq "MEDIUM" })

        $criticalWithoutEnabled = @($criticalReportOnly | Where-Object { $_.enabled_alternative_exists -ne $true })
        $highWithoutEnabled = @($highReportOnly | Where-Object { $_.enabled_alternative_exists -ne $true })
        $mediumWithoutEnabled = @($mediumReportOnly | Where-Object { $_.enabled_alternative_exists -ne $true })

        $importantWithEnabledAlternative = @($reportOnlyImportant | Where-Object { $_.enabled_alternative_exists -eq $true })

        $purposeSummary = @(
            $reportOnlyImportant |
                Group-Object purpose |
                ForEach-Object {
                    [PSCustomObject]@{
                        purpose = $_.Name
                        count   = $_.Count
                    }
                }
        )

        # ----------------------------------------------------
        # Findings
        # ----------------------------------------------------

        if ($reportOnlyPolicies.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No report-only Conditional Access policies detected" `
                -Detail "No Conditional Access policies were found in report-only mode."

            $recommendations += New-ZTVPRecommendation `
                -Title "Maintain Conditional Access governance" `
                -Detail "Continue using report-only mode only for controlled testing, then move validated protections to enabled state."
        }

        if ($criticalWithoutEnabled.Count -gt 0) {
            $affected = $criticalWithoutEnabled | ForEach-Object { "$($_.name) [$($_.purpose)]" }

            $findings += New-ZTVPFinding `
                -Title "Critical protections are only report-only" `
                -Detail ("Critical Conditional Access protections are report-only and no enabled equivalent was detected. Policies: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Enable critical Conditional Access protections" `
                -Detail "Review report-only impact and move critical protections such as MFA, admin protection, phishing-resistant authentication, or legacy authentication blocking to enabled state."
        }

        if ($highWithoutEnabled.Count -gt 0) {
            $affected = $highWithoutEnabled | ForEach-Object { "$($_.name) [$($_.purpose)]" }

            $findings += New-ZTVPFinding `
                -Title "High-value protections are only report-only" `
                -Detail ("High-value Conditional Access protections are report-only and no enabled equivalent was detected. Policies: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Prioritize high-value policy enforcement" `
                -Detail "Review and enable high-value report-only policies after validation, especially device trust, location blocking, risk response, and admin-focused controls."
        }

        if ($mediumWithoutEnabled.Count -gt 0) {
            $affected = $mediumWithoutEnabled | ForEach-Object { "$($_.name) [$($_.purpose)]" }

            $findings += New-ZTVPFinding `
                -Title "Medium-value protections are only report-only" `
                -Detail ("Some medium-value Conditional Access protections are report-only without an enabled equivalent. Policies: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review medium-value report-only policies" `
                -Detail "Validate whether session controls or app controls should be moved to enabled state or retired."
        }

        if ($importantWithEnabledAlternative.Count -gt 0) {
            $affected = $importantWithEnabledAlternative | Select-Object -First 15 | ForEach-Object { "$($_.name) [$($_.purpose)]" }

            $findings += New-ZTVPFinding `
                -Title "Report-only policies have enabled alternatives" `
                -Detail ("Some report-only policies appear to have enabled policies covering the same control purpose. These may be testing variants or duplicates. Sample: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review duplicate or testing report-only policies" `
                -Detail "Confirm whether report-only policies with enabled alternatives are intentional testing variants. Remove stale policies or document their purpose."
        }

        if ($reportOnlyImportant.Count -eq 0 -and $reportOnlyPolicies.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Report-only policies detected, but no critical dependency identified" `
                -Detail "Report-only Conditional Access policies exist, but the platform did not classify them as critical or high-value security dependencies."

            $recommendations += New-ZTVPRecommendation `
                -Title "Review report-only policy inventory" `
                -Detail "Review report-only policies and remove or document testing policies that are no longer needed."
        }

        if ($reportOnlyImportant.Count -eq 0 -and $reportOnlyPolicies.Count -eq 0) {
            # Already covered above; no extra action.
        }

        # ----------------------------------------------------
        # Result logic
        # ----------------------------------------------------

        $status = "PASS"
        $risk = "LOW"

        if ($criticalWithoutEnabled.Count -gt 0) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif ($highWithoutEnabled.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }
        elseif ($mediumWithoutEnabled.Count -gt 0 -or $importantWithEnabledAlternative.Count -gt 0 -or $reportOnlyPolicies.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }

        $currentState = @(
            "Conditional Access policies assessed: $($assessedPolicies.Count)."
            "Report-only policies: $($reportOnlyPolicies.Count)."
            "Important report-only policies: $($reportOnlyImportant.Count)."
            "Critical report-only dependencies without enabled equivalent: $($criticalWithoutEnabled.Count)."
            "High-value report-only dependencies without enabled equivalent: $($highWithoutEnabled.Count)."
            "Medium-value report-only dependencies without enabled equivalent: $($mediumWithoutEnabled.Count)."
            "Report-only policies with enabled alternatives: $($importantWithEnabledAlternative.Count)."
        ) -join " "

        $zeroTrustTarget = "Important Conditional Access protections should not depend on report-only policies. Critical controls such as MFA, admin access protection, phishing-resistant authentication, legacy authentication blocking, device trust, location blocking, and risk response should be enabled after validation."

        if ($status -eq "PASS") {
            $gapSummary = "No report-only policy dependency risk was detected."
            $executiveSummary = "Report-only policy dependency posture appears controlled. No important Conditional Access protection was found to depend only on report-only mode."
        }
        elseif ($status -eq "PARTIAL") {
            $gapSummary = "Report-only policy dependency posture requires review because some important protections are still in testing or duplicate enabled policies."
            $executiveSummary = "Report-only policy dependency posture is partially controlled. Some important Conditional Access policies remain report-only, but no critical unenforced dependency was confirmed."
        }
        else {
            $gapSummary = "Report-only policy dependency posture is not aligned because critical protections are present only in report-only mode without an enabled equivalent."
            $executiveSummary = "Critical report-only dependency detected. One or more critical Conditional Access protections exist only in report-only mode and are not enforcing protection."
        }

        return New-ZTVPResult `
            -ScenarioId "E3" `
            -ScenarioName "Report-Only Policy Dependency Review" `
            -Category "Access Enforcement" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary                                  = $executiveSummary
                conditional_access_policy_count                    = $assessedPolicies.Count
                report_only_policy_count                           = $reportOnlyPolicies.Count
                important_report_only_policy_count                 = $reportOnlyImportant.Count
                critical_report_only_policy_count                  = $criticalReportOnly.Count
                high_report_only_policy_count                      = $highReportOnly.Count
                medium_report_only_policy_count                    = $mediumReportOnly.Count
                critical_dependency_without_enabled_count          = $criticalWithoutEnabled.Count
                high_dependency_without_enabled_count              = $highWithoutEnabled.Count
                medium_dependency_without_enabled_count            = $mediumWithoutEnabled.Count
                report_only_with_enabled_alternative_count         = $importantWithEnabledAlternative.Count

                critical_dependency_without_enabled_policy_names   = @($criticalWithoutEnabled | ForEach-Object { $_.name })
                high_dependency_without_enabled_policy_names       = @($highWithoutEnabled | ForEach-Object { $_.name })
                medium_dependency_without_enabled_policy_names     = @($mediumWithoutEnabled | ForEach-Object { $_.name })
                report_only_with_enabled_alternative_policy_names  = @($importantWithEnabledAlternative | ForEach-Object { $_.name })

                purpose_summary                                    = $purposeSummary
                report_only_important_policy_details               = $reportOnlyImportant
                assessed_policies                                  = $assessedPolicies
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gapSummary
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "E3" `
            -ScenarioName "Report-Only Policy Dependency Review" `
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
                    -Detail "Review Graph connection, permissions, Conditional Access policy collection, and policy classification logic."
            ) `
            -Evidence $null `
            -CurrentState "The engine could not complete report-only policy dependency assessment." `
            -ZeroTrustTarget "Important Conditional Access protections should be enabled, not only report-only." `
            -GapSummary "The scenario could not be evaluated because execution failed."
    }
}

