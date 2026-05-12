Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Identity.SignIns -Force -ErrorAction SilentlyContinue

function Convert-ZTVPE5ToLowerArray {
    param($Value)

    $result = @()

    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $result += $item.ToString().ToLowerInvariant()
        }
    }

    return $result
}

function Get-ZTVPE5PolicyStateLabel {
    param([string]$State)

    switch ($State) {
        "enabled" { return "Enabled" }
        "enabledForReportingButNotEnforced" { return "Report-only" }
        "disabled" { return "Disabled" }
        default { return $State }
    }
}

function Test-ZTVPE5AuthenticationStrength {
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

function Test-ZTVPE5SessionControl {
    param($Policy)

    if ($null -eq $Policy -or $null -eq $Policy.SessionControls) {
        return $false
    }

    $sc = $Policy.SessionControls

    $props = @(
        "ApplicationEnforcedRestrictions",
        "CloudAppSecurity",
        "SignInFrequency",
        "PersistentBrowser",
        "DisableResilienceDefaults",
        "ContinuousAccessEvaluation"
    )

    foreach ($propName in $props) {
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

function Get-ZTVPE5PolicyEvidence {
    param($Policy)

    $name = ""
    if ($Policy.DisplayName) {
        $name = $Policy.DisplayName
    }

    $nameLower = $name.ToLowerInvariant()

    $state = ""
    if ($null -ne $Policy.State) {
        $state = $Policy.State.ToString()
    }

    $includeUsers = @()
    $includeGroups = @()
    $includeRoles = @()
    $includeApps = @()

    if ($Policy.Conditions -and $Policy.Conditions.Users) {
        $includeUsers = @(Convert-ZTVPE5ToLowerArray -Value $Policy.Conditions.Users.IncludeUsers)
        $includeGroups = @(Convert-ZTVPE5ToLowerArray -Value $Policy.Conditions.Users.IncludeGroups)
        $includeRoles = @(Convert-ZTVPE5ToLowerArray -Value $Policy.Conditions.Users.IncludeRoles)
    }

    if ($Policy.Conditions -and $Policy.Conditions.Applications) {
        $includeApps = @(Convert-ZTVPE5ToLowerArray -Value $Policy.Conditions.Applications.IncludeApplications)
    }

    $builtInControls = @()

    if ($Policy.GrantControls -and $Policy.GrantControls.BuiltInControls) {
        $builtInControls = @(Convert-ZTVPE5ToLowerArray -Value $Policy.GrantControls.BuiltInControls)
    }

    # Microsoft Admin Portals / Azure Management app used in Conditional Access admin protection.
    $adminPortalAppIds = @(
        "797f4846-ba00-4fd7-ba43-dac1f8f63013"
    )

    $targetsAdminRoles = [bool]($includeRoles.Count -gt 0)
    $targetsAdminPortal = [bool](@($includeApps | Where-Object { $_ -in $adminPortalAppIds }).Count -gt 0)

    $adminNameHint = [bool](
        $nameLower -match "admin" -or
        $nameLower -match "adm" -or
        $nameLower -match "privileged" -or
        $nameLower -match "paw" -or
        $nameLower -match "saw" -or
        $nameLower -match "portal"
    )

    $adminScopeCategory = "Not admin-scoped"
    $adminScopeReason = "No admin role, admin portal, or admin naming evidence detected."

    if ($targetsAdminRoles) {
        $adminScopeCategory = "Confirmed admin scope"
        $adminScopeReason = "Targets admin roles."
    }
    elseif ($targetsAdminPortal) {
        $adminScopeCategory = "Confirmed admin scope"
        $adminScopeReason = "Targets Microsoft Admin Portals / Azure Management."
    }
    elseif ($adminNameHint) {
        $adminScopeCategory = "Admin-name hint only"
        $adminScopeReason = "Policy name indicates admin/privileged/PAW/SAW intent, but role or admin portal targeting was not confirmed."
    }

    $adminRelevant = [bool]($adminScopeCategory -ne "Not admin-scoped")
    $confirmedAdminScope = [bool]($adminScopeCategory -eq "Confirmed admin scope")
    $adminNameOnly = [bool]($adminScopeCategory -eq "Admin-name hint only")

    $hasAuthStrength = Test-ZTVPE5AuthenticationStrength -GrantControls $Policy.GrantControls

    $nameLooksLikeMfa = [bool](
        $nameLower -match "mfa" -or
        $nameLower -match "duo" -or
        $nameLower -match "phish" -or
        $nameLower -match "fido" -or
        $nameLower -match "passkey" -or
        $nameLower -match "passwordless" -or
        $nameLower -match "strong"
    )

    $hasMfa = [bool](
        $builtInControls -contains "mfa" -or
        $hasAuthStrength -eq $true -or
        $nameLooksLikeMfa -eq $true
    )

    $hasPhishingResistant = [bool](
        $hasAuthStrength -eq $true -or
        $nameLower -match "phish" -or
        $nameLower -match "fido" -or
        $nameLower -match "passkey" -or
        $nameLower -match "passwordless" -or
        $nameLower -match "certificate" -or
        $nameLower -match "strong"
    )

    # Strict device trust. PAW/SAW alone is not counted unless the policy name/control indicates device enforcement.
    $hasDeviceTrust = [bool](
        $builtInControls -contains "compliantdevice" -or
        $builtInControls -contains "domainjoineddevice" -or
        $builtInControls -contains "hybridazureadjoineddevice" -or
        $builtInControls -contains "approvedapplication" -or
        $builtInControls -contains "compliantapplication" -or
        $nameLower -match "compliant" -or
        $nameLower -match "hybrid" -or
        $nameLower -match "trusteddevice" -or
        $nameLower -match "trusted device" -or
        $nameLower -match "manageddevice" -or
        $nameLower -match "managed device" -or
        $nameLower -match "nonpaw" -or
        $nameLower -match "non-paw" -or
        $nameLower -match "require-compliant" -or
        $nameLower -match "compliantorhybrid"
    )

    $hasBlock = [bool]($builtInControls -contains "block")

    $hasSession = [bool](
        (Test-ZTVPE5SessionControl -Policy $Policy) -or
        $nameLower -match "session" -or
        $nameLower -match "signinfrequency" -or
        $nameLower -match "sign-in frequency" -or
        $nameLower -match "persistentbrowser" -or
        $nameLower -match "persistent browser" -or
        $nameLower -match "browser" -or
        $nameLower -match "mdca" -or
        $nameLower -match "appcontrol" -or
        $nameLower -match "app control"
    )

    $includesAllUsers = [bool]($includeUsers -contains "all")
    $includesAllApps = [bool]($includeApps -contains "all")

    $isBroadWorkforceAuthPolicy = [bool](
        $includesAllUsers -eq $true -and
        $includesAllApps -eq $true -and
        $hasMfa -eq $true
    )

    $controls = @()

    if ($hasBlock) {
        $controls += "Block"
    }

    if ($hasPhishingResistant) {
        $controls += "Phishing-resistant/auth strength"
    }
    elseif ($hasMfa) {
        $controls += "MFA"
    }

    if ($hasDeviceTrust) {
        $controls += "Device trust"
    }

    if ($hasSession) {
        $controls += "Session"
    }

    if ($controls.Count -eq 0) {
        $controls += "Other"
    }

    return [PSCustomObject]@{
        name                         = $name
        state                        = $state
        state_label                  = Get-ZTVPE5PolicyStateLabel -State $state
        enabled                      = ($state -eq "enabled")
        report_only                  = ($state -eq "enabledForReportingButNotEnforced")
        disabled                     = ($state -eq "disabled")

        admin_relevant               = $adminRelevant
        confirmed_admin_scope        = $confirmedAdminScope
        admin_name_only              = $adminNameOnly
        admin_scope_category         = $adminScopeCategory
        admin_scope_reason           = $adminScopeReason
        targets_admin_roles          = $targetsAdminRoles
        targets_admin_portal         = $targetsAdminPortal
        admin_name_hint              = $adminNameHint

        includes_all_users           = $includesAllUsers
        includes_all_apps            = $includesAllApps
        include_roles_count          = $includeRoles.Count
        include_groups_count         = $includeGroups.Count
        include_users_count          = $includeUsers.Count
        include_apps_count           = $includeApps.Count

        has_mfa                      = $hasMfa
        has_auth_strength            = $hasAuthStrength
        has_phishing_resistant       = $hasPhishingResistant
        has_device_trust             = $hasDeviceTrust
        has_block                    = $hasBlock
        has_session_control          = $hasSession
        broad_workforce_auth_policy  = $isBroadWorkforceAuthPolicy
        control_summary              = ($controls -join " + ")
    }
}

function Invoke-ZTVP-E5 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== E5 - Admin Access Policy Presence Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        try {
            $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        }
        catch {
            return New-ZTVPResult `
                -ScenarioId "E5" `
                -ScenarioName "Admin Access Policy Presence Review" `
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
                        -Detail "Grant or consent permissions to read Conditional Access policies, then rerun E5."
                ) `
                -Evidence $null `
                -CurrentState "Conditional Access policies could not be collected." `
                -ZeroTrustTarget "Privileged access should have dedicated enabled Conditional Access protection." `
                -GapSummary "E5 could not be evaluated because Conditional Access policy evidence was unavailable."
        }

        $assessedPolicies = @()

        foreach ($policy in $policies) {
            if ($null -eq $policy) {
                continue
            }

            $assessedPolicies += Get-ZTVPE5PolicyEvidence -Policy $policy
        }

        $adminRelevantPolicies = @($assessedPolicies | Where-Object { $_.admin_relevant -eq $true })
        $confirmedAdminPolicies = @($assessedPolicies | Where-Object { $_.confirmed_admin_scope -eq $true })
        $adminNameOnlyPolicies = @($assessedPolicies | Where-Object { $_.admin_name_only -eq $true })

        $enabledConfirmedAdminPolicies = @($confirmedAdminPolicies | Where-Object { $_.enabled -eq $true })
        $reportOnlyConfirmedAdminPolicies = @($confirmedAdminPolicies | Where-Object { $_.report_only -eq $true })

        $enabledAdminNameOnlyPolicies = @($adminNameOnlyPolicies | Where-Object { $_.enabled -eq $true })
        $reportOnlyAdminNameOnlyPolicies = @($adminNameOnlyPolicies | Where-Object { $_.report_only -eq $true })

        $enabledConfirmedAdminAuthPolicies = @($enabledConfirmedAdminPolicies | Where-Object { $_.has_mfa -eq $true -or $_.has_auth_strength -eq $true })
        $reportOnlyConfirmedAdminAuthPolicies = @($reportOnlyConfirmedAdminPolicies | Where-Object { $_.has_mfa -eq $true -or $_.has_auth_strength -eq $true })

        $enabledNameOnlyAdminAuthPolicies = @($enabledAdminNameOnlyPolicies | Where-Object { $_.has_mfa -eq $true -or $_.has_auth_strength -eq $true })
        $reportOnlyNameOnlyAdminAuthPolicies = @($reportOnlyAdminNameOnlyPolicies | Where-Object { $_.has_mfa -eq $true -or $_.has_auth_strength -eq $true })

        $enabledConfirmedAdminPhishPolicies = @($enabledConfirmedAdminPolicies | Where-Object { $_.has_phishing_resistant -eq $true })
        $reportOnlyConfirmedAdminPhishPolicies = @($reportOnlyConfirmedAdminPolicies | Where-Object { $_.has_phishing_resistant -eq $true })

        $enabledNameOnlyAdminPhishPolicies = @($enabledAdminNameOnlyPolicies | Where-Object { $_.has_phishing_resistant -eq $true })
        $reportOnlyNameOnlyAdminPhishPolicies = @($reportOnlyAdminNameOnlyPolicies | Where-Object { $_.has_phishing_resistant -eq $true })

        $enabledConfirmedAdminDevicePolicies = @($enabledConfirmedAdminPolicies | Where-Object { $_.has_device_trust -eq $true })
        $reportOnlyConfirmedAdminDevicePolicies = @($reportOnlyConfirmedAdminPolicies | Where-Object { $_.has_device_trust -eq $true })

        $enabledNameOnlyAdminDevicePolicies = @($enabledAdminNameOnlyPolicies | Where-Object { $_.has_device_trust -eq $true })
        $reportOnlyNameOnlyAdminDevicePolicies = @($reportOnlyAdminNameOnlyPolicies | Where-Object { $_.has_device_trust -eq $true })

        $enabledAdminBlockPolicies = @($adminRelevantPolicies | Where-Object { $_.enabled -eq $true -and $_.has_block -eq $true })
        $reportOnlyAdminBlockPolicies = @($adminRelevantPolicies | Where-Object { $_.report_only -eq $true -and $_.has_block -eq $true })

        $enabledAdminSessionPolicies = @($adminRelevantPolicies | Where-Object { $_.enabled -eq $true -and $_.has_session_control -eq $true })
        $reportOnlyAdminSessionPolicies = @($adminRelevantPolicies | Where-Object { $_.report_only -eq $true -and $_.has_session_control -eq $true })

        $enabledBroadWorkforceAuthPolicies = @($assessedPolicies | Where-Object { $_.enabled -eq $true -and $_.broad_workforce_auth_policy -eq $true })
        $reportOnlyBroadWorkforceAuthPolicies = @($assessedPolicies | Where-Object { $_.report_only -eq $true -and $_.broad_workforce_auth_policy -eq $true })

        if ($assessedPolicies.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No Conditional Access policies detected" `
                -Detail "No Conditional Access policies were found."

            $recommendations += New-ZTVPRecommendation `
                -Title "Create Conditional Access baseline" `
                -Detail "Create Conditional Access policies for workforce and privileged access protection."
        }

        if ($confirmedAdminPolicies.Count -eq 0 -and $adminNameOnlyPolicies.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Admin-related policies detected by name only" `
                -Detail ("Policies appear admin-related by name, but E5 did not confirm admin role or Microsoft Admin Portal targeting. Policies: " + (($adminNameOnlyPolicies | Select-Object -First 10 | ForEach-Object { $_.name }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Confirm admin policy targeting" `
                -Detail "Validate that admin policies explicitly target privileged roles or Microsoft Admin Portals. Avoid relying only on policy naming."
        }
        elseif ($confirmedAdminPolicies.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No confirmed admin-scoped Conditional Access policies detected" `
                -Detail "No policy was confirmed to target admin roles or Microsoft Admin Portals."

            $recommendations += New-ZTVPRecommendation `
                -Title "Create confirmed admin-scoped policy" `
                -Detail "Create a Conditional Access policy targeting privileged roles or Microsoft Admin Portals and require MFA or authentication strength."
        }

        if ($enabledConfirmedAdminAuthPolicies.Count -eq 0) {
            if ($reportOnlyConfirmedAdminAuthPolicies.Count -gt 0) {
                $findings += New-ZTVPFinding `
                    -Title "Confirmed admin authentication policy is report-only" `
                    -Detail ("Confirmed admin authentication protection exists but is report-only. Policies: " + (($reportOnlyConfirmedAdminAuthPolicies | ForEach-Object { $_.name }) -join ", "))

                $recommendations += New-ZTVPRecommendation `
                    -Title "Enable confirmed admin authentication policy" `
                    -Detail "Validate report-only impact, then enable the admin MFA or authentication-strength policy."
            }
            elseif ($reportOnlyNameOnlyAdminAuthPolicies.Count -gt 0) {
                $findings += New-ZTVPFinding `
                    -Title "Admin authentication policies are report-only and scope is not confirmed" `
                    -Detail ("Admin-named authentication policies exist but are report-only and were not confirmed to target admin roles or admin portals. Policies: " + (($reportOnlyNameOnlyAdminAuthPolicies | ForEach-Object { $_.name }) -join ", "))

                $recommendations += New-ZTVPRecommendation `
                    -Title "Validate and enable admin authentication policy" `
                    -Detail "Confirm the policies target privileged roles or Microsoft Admin Portals, then move validated admin authentication protection to enabled state."
            }
            elseif ($enabledBroadWorkforceAuthPolicies.Count -gt 0) {
                $findings += New-ZTVPFinding `
                    -Title "Admin access may depend on broad workforce MFA" `
                    -Detail ("An enabled broad workforce MFA policy exists, but no enabled confirmed dedicated admin authentication policy was found. Broad policies: " + (($enabledBroadWorkforceAuthPolicies | ForEach-Object { $_.name }) -join ", "))

                $recommendations += New-ZTVPRecommendation `
                    -Title "Add dedicated admin authentication policy" `
                    -Detail "Broad workforce MFA is useful, but privileged access should also have dedicated admin-scoped protection."
            }
            else {
                $findings += New-ZTVPFinding `
                    -Title "No enabled confirmed admin MFA or authentication-strength policy detected" `
                    -Detail "E5 did not confirm an enabled policy targeting admin roles or Microsoft Admin Portals that requires MFA or authentication strength."

                $recommendations += New-ZTVPRecommendation `
                    -Title "Create enabled admin MFA or authentication-strength policy" `
                    -Detail "Create an enabled policy targeting privileged roles or Microsoft Admin Portals and require MFA or authentication strength."
            }
        }
        else {
            $findings += New-ZTVPFinding `
                -Title "Enabled confirmed admin authentication policy detected" `
                -Detail ("Enabled confirmed admin authentication policies were detected. Policies: " + (($enabledConfirmedAdminAuthPolicies | ForEach-Object { $_.name }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Maintain admin authentication protection" `
                -Detail "Continue validating exclusions through E2 and report-only dependencies through E3."
        }

        if ($enabledConfirmedAdminPhishPolicies.Count -eq 0) {
            if ($reportOnlyConfirmedAdminPhishPolicies.Count -gt 0 -or $reportOnlyNameOnlyAdminPhishPolicies.Count -gt 0) {
                $phishCandidates = @($reportOnlyConfirmedAdminPhishPolicies + $reportOnlyNameOnlyAdminPhishPolicies | Sort-Object name -Unique)

                $findings += New-ZTVPFinding `
                    -Title "Admin phishing-resistant authentication is not enforced" `
                    -Detail ("Phishing-resistant or authentication-strength admin policies exist, but they are not confirmed as enabled enforcement. Policies: " + (($phishCandidates | ForEach-Object { $_.name }) -join ", "))

                $recommendations += New-ZTVPRecommendation `
                    -Title "Move admin phishing-resistant authentication toward enforcement" `
                    -Detail "Privileged access should prefer authentication strength, FIDO2/passkeys, certificate-based authentication, or equivalent phishing-resistant methods."
            }
            else {
                $findings += New-ZTVPFinding `
                    -Title "Admin phishing-resistant authentication not confirmed" `
                    -Detail "No enabled confirmed phishing-resistant or authentication-strength policy was detected for admin access."

                $recommendations += New-ZTVPRecommendation `
                    -Title "Plan phishing-resistant admin authentication" `
                    -Detail "Add authentication-strength enforcement for privileged access where feasible."
            }
        }

        if ($enabledConfirmedAdminDevicePolicies.Count -eq 0) {
            if ($reportOnlyConfirmedAdminDevicePolicies.Count -gt 0 -or $reportOnlyNameOnlyAdminDevicePolicies.Count -gt 0) {
                $deviceCandidates = @($reportOnlyConfirmedAdminDevicePolicies + $reportOnlyNameOnlyAdminDevicePolicies | Sort-Object name -Unique)

                $findings += New-ZTVPFinding `
                    -Title "Admin device trust is not enforced" `
                    -Detail ("Admin device trust policies exist but are not confirmed as enabled enforcement. Policies: " + (($deviceCandidates | ForEach-Object { $_.name }) -join ", "))
            }
            else {
                $findings += New-ZTVPFinding `
                    -Title "Admin device trust policy not confirmed" `
                    -Detail "No enabled confirmed admin device trust policy was detected."
            }

            $recommendations += New-ZTVPRecommendation `
                -Title "Review device trust for admin access" `
                -Detail "Where feasible, require compliant, hybrid joined, managed, PAW, or SAW devices for privileged access."
        }

        if ($enabledAdminBlockPolicies.Count -eq 0 -and $reportOnlyAdminBlockPolicies.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Admin blocking controls are report-only" `
                -Detail ("Admin-related blocking controls exist but are report-only. Policies: " + (($reportOnlyAdminBlockPolicies | ForEach-Object { $_.name }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Validate admin blocking controls" `
                -Detail "Review and enable admin blocking controls where appropriate, such as blocking unsupported platforms, untrusted locations, or non-PAW devices."
        }

        $status = "PASS"
        $risk = "LOW"

        if ($assessedPolicies.Count -eq 0) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif ($enabledConfirmedAdminAuthPolicies.Count -gt 0 -and $enabledConfirmedAdminPhishPolicies.Count -gt 0) {
            if ($enabledConfirmedAdminDevicePolicies.Count -eq 0 -or $reportOnlyConfirmedAdminPolicies.Count -gt 0 -or $reportOnlyNameOnlyAdminPolicies.Count -gt 0) {
                $status = "PARTIAL"
                $risk = "HIGH"
            }
            else {
                $status = "PASS"
                $risk = "LOW"
            }
        }
        elseif ($enabledConfirmedAdminAuthPolicies.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }
        elseif ($enabledBroadWorkforceAuthPolicies.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }
        else {
            $status = "FAIL"
            $risk = "CRITICAL"
        }

        $currentState = @(
            "Conditional Access policies assessed: $($assessedPolicies.Count)."
            "Admin-relevant policies detected: $($adminRelevantPolicies.Count)."
            "Confirmed admin-scoped policies: $($confirmedAdminPolicies.Count)."
            "Admin-name-only policies requiring scope verification: $($adminNameOnlyPolicies.Count)."
            "Enabled confirmed admin authentication policies: $($enabledConfirmedAdminAuthPolicies.Count)."
            "Report-only confirmed admin authentication policies: $($reportOnlyConfirmedAdminAuthPolicies.Count)."
            "Enabled admin-name-only authentication policies: $($enabledNameOnlyAdminAuthPolicies.Count)."
            "Report-only admin-name-only authentication policies: $($reportOnlyNameOnlyAdminAuthPolicies.Count)."
            "Enabled confirmed admin phishing-resistant policies: $($enabledConfirmedAdminPhishPolicies.Count)."
            "Report-only admin phishing-resistant candidates: $(@($reportOnlyConfirmedAdminPhishPolicies + $reportOnlyNameOnlyAdminPhishPolicies).Count)."
            "Enabled confirmed admin device trust policies: $($enabledConfirmedAdminDevicePolicies.Count)."
            "Report-only admin device trust candidates: $(@($reportOnlyConfirmedAdminDevicePolicies + $reportOnlyNameOnlyAdminDevicePolicies).Count)."
            "Enabled admin blocking controls: $($enabledAdminBlockPolicies.Count)."
            "Report-only admin blocking controls: $($reportOnlyAdminBlockPolicies.Count)."
            "Enabled broad workforce MFA policies: $($enabledBroadWorkforceAuthPolicies.Count)."
        ) -join " "

        $zeroTrustTarget = "Privileged access should have confirmed dedicated Conditional Access protection. Admin roles or Microsoft Admin Portals should be protected by enabled policies requiring MFA or authentication strength, preferably phishing-resistant authentication, with device trust and blocking controls where appropriate."

        if ($status -eq "PASS") {
            $executiveSummary = "Admin access policy posture appears controlled. Enabled confirmed admin authentication and phishing-resistant or authentication-strength coverage were detected."
            $gapSummary = "Admin access policy presence appears aligned with the Zero Trust target."
        }
        elseif ($status -eq "PARTIAL") {
            $executiveSummary = "Admin access policy posture is partially controlled. Some admin protection exists, but confirmed dedicated enforcement, phishing-resistant authentication, device trust, or report-only dependencies require review."
            $gapSummary = "Admin access policy presence is partially aligned but requires hardening or scope verification."
        }
        else {
            $executiveSummary = "Critical admin access policy gap detected. Enabled confirmed admin MFA or authentication-strength protection was not found."
            $gapSummary = "Admin access policy presence is not aligned because enabled confirmed dedicated admin authentication protection was not found."
        }

        return New-ZTVPResult `
            -ScenarioId "E5" `
            -ScenarioName "Admin Access Policy Presence Review" `
            -Category "Access Enforcement" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary                                      = $executiveSummary

                conditional_access_policy_count                        = $assessedPolicies.Count
                admin_relevant_policy_count                            = $adminRelevantPolicies.Count
                confirmed_admin_policy_count                           = $confirmedAdminPolicies.Count
                admin_name_only_policy_count                           = $adminNameOnlyPolicies.Count

                enabled_confirmed_admin_policy_count                   = $enabledConfirmedAdminPolicies.Count
                report_only_confirmed_admin_policy_count               = $reportOnlyConfirmedAdminPolicies.Count
                enabled_admin_name_only_policy_count                   = $enabledAdminNameOnlyPolicies.Count
                report_only_admin_name_only_policy_count               = $reportOnlyAdminNameOnlyPolicies.Count

                enabled_confirmed_admin_auth_policy_count              = $enabledConfirmedAdminAuthPolicies.Count
                report_only_confirmed_admin_auth_policy_count          = $reportOnlyConfirmedAdminAuthPolicies.Count
                enabled_admin_name_only_auth_policy_count              = $enabledNameOnlyAdminAuthPolicies.Count
                report_only_admin_name_only_auth_policy_count          = $reportOnlyNameOnlyAdminAuthPolicies.Count

                enabled_confirmed_admin_phish_policy_count             = $enabledConfirmedAdminPhishPolicies.Count
                report_only_confirmed_admin_phish_policy_count         = $reportOnlyConfirmedAdminPhishPolicies.Count
                enabled_admin_name_only_phish_policy_count             = $enabledNameOnlyAdminPhishPolicies.Count
                report_only_admin_name_only_phish_policy_count         = $reportOnlyNameOnlyAdminPhishPolicies.Count

                enabled_confirmed_admin_device_policy_count            = $enabledConfirmedAdminDevicePolicies.Count
                report_only_confirmed_admin_device_policy_count        = $reportOnlyConfirmedAdminDevicePolicies.Count
                enabled_admin_name_only_device_policy_count            = $enabledNameOnlyAdminDevicePolicies.Count
                report_only_admin_name_only_device_policy_count        = $reportOnlyNameOnlyAdminDevicePolicies.Count

                enabled_admin_block_policy_count                       = $enabledAdminBlockPolicies.Count
                report_only_admin_block_policy_count                   = $reportOnlyAdminBlockPolicies.Count
                enabled_admin_session_policy_count                     = $enabledAdminSessionPolicies.Count
                report_only_admin_session_policy_count                 = $reportOnlyAdminSessionPolicies.Count

                enabled_broad_workforce_auth_policy_count              = $enabledBroadWorkforceAuthPolicies.Count
                report_only_broad_workforce_auth_policy_count          = $reportOnlyBroadWorkforceAuthPolicies.Count

                confirmed_admin_policies                               = $confirmedAdminPolicies
                admin_name_only_policies                               = $adminNameOnlyPolicies

                enabled_confirmed_admin_auth_policies                  = $enabledConfirmedAdminAuthPolicies
                report_only_confirmed_admin_auth_policies              = $reportOnlyConfirmedAdminAuthPolicies
                enabled_admin_name_only_auth_policies                  = $enabledNameOnlyAdminAuthPolicies
                report_only_admin_name_only_auth_policies              = $reportOnlyNameOnlyAdminAuthPolicies

                enabled_confirmed_admin_phish_policies                 = $enabledConfirmedAdminPhishPolicies
                report_only_confirmed_admin_phish_policies             = $reportOnlyConfirmedAdminPhishPolicies
                enabled_admin_name_only_phish_policies                 = $enabledNameOnlyAdminPhishPolicies
                report_only_admin_name_only_phish_policies             = $reportOnlyNameOnlyAdminPhishPolicies

                enabled_confirmed_admin_device_policies                = $enabledConfirmedAdminDevicePolicies
                report_only_confirmed_admin_device_policies            = $reportOnlyConfirmedAdminDevicePolicies
                enabled_admin_name_only_device_policies                = $enabledNameOnlyAdminDevicePolicies
                report_only_admin_name_only_device_policies            = $reportOnlyNameOnlyAdminDevicePolicies

                enabled_admin_block_policies                           = $enabledAdminBlockPolicies
                report_only_admin_block_policies                       = $reportOnlyAdminBlockPolicies

                enabled_broad_workforce_auth_policies                  = $enabledBroadWorkforceAuthPolicies
                report_only_broad_workforce_auth_policies              = $reportOnlyBroadWorkforceAuthPolicies

                admin_relevant_policy_details                          = $adminRelevantPolicies
                assessed_policies                                      = $assessedPolicies
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gapSummary
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "E5" `
            -ScenarioName "Admin Access Policy Presence Review" `
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
                    -Detail "Review Graph connection, Conditional Access collection, and E5 admin policy classification."
            ) `
            -Evidence $null `
            -CurrentState "E5 could not complete admin access policy assessment." `
            -ZeroTrustTarget "Privileged access should have dedicated enabled Conditional Access protection." `
            -GapSummary "E5 could not be evaluated because execution failed."
    }
}
