Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Identity.SignIns -Force -ErrorAction SilentlyContinue

function ConvertTo-ID1StringArray {
    param($Value)

    $items = @()

    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $items += $item.ToString()
        }
    }

    return $items
}

function ConvertTo-ID1LowerArray {
    param($Value)

    $items = @()

    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $items += $item.ToString().ToLowerInvariant()
        }
    }

    return $items
}

function Get-ID1StateLabel {
    param([string]$State)

    switch ($State) {
        "enabled" { return "Enabled" }
        "enabledForReportingButNotEnforced" { return "Report-only" }
        "disabled" { return "Disabled" }
        default { return $State }
    }
}

function Test-ID1AuthenticationStrength {
    param($GrantControls)

    if ($null -eq $GrantControls) {
        return $false
    }

    if ($null -eq $GrantControls.AuthenticationStrength) {
        return $false
    }

    $strength = $GrantControls.AuthenticationStrength

    if ($strength.PSObject.Properties["Id"] -and -not [string]::IsNullOrWhiteSpace($strength.Id)) {
        return $true
    }

    if ($strength.PSObject.Properties["DisplayName"] -and -not [string]::IsNullOrWhiteSpace($strength.DisplayName)) {
        return $true
    }

    return $false
}

function Get-ID1RiskPolicyEvidence {
    param($Policy)

    $name = ""
    if ($Policy.DisplayName) {
        $name = $Policy.DisplayName
    }

    $nameLower = $name.ToLowerInvariant()

    $state = ""
    if ($Policy.State) {
        $state = $Policy.State.ToString()
    }

    $userRiskLevels = @()
    $signInRiskLevels = @()

    if ($Policy.Conditions) {
        $userRiskLevels = @(ConvertTo-ID1LowerArray $Policy.Conditions.UserRiskLevels)
        $signInRiskLevels = @(ConvertTo-ID1LowerArray $Policy.Conditions.SignInRiskLevels)
    }

    $builtInControls = @()

    if ($Policy.GrantControls -and $Policy.GrantControls.BuiltInControls) {
        $builtInControls = @(ConvertTo-ID1LowerArray $Policy.GrantControls.BuiltInControls)
    }

    $hasAuthStrength = Test-ID1AuthenticationStrength -GrantControls $Policy.GrantControls

    $requiresMfa = [bool](
        $builtInControls -contains "mfa" -or
        $hasAuthStrength -eq $true
    )

    $requiresPasswordChange = [bool](
        $builtInControls -contains "passwordchange" -or
        $builtInControls -contains "passwordchangeandmfa"
    )

    $blocksAccess = [bool]($builtInControls -contains "block")

    $isUserRisk = [bool](
        $userRiskLevels.Count -gt 0 -or
        $nameLower -match "user risk" -or
        $nameLower -match "userrisk"
    )

    $isSignInRisk = [bool](
        $signInRiskLevels.Count -gt 0 -or
        $nameLower -match "sign-in risk" -or
        $nameLower -match "sign in risk" -or
        $nameLower -match "signinrisk"
    )

    $excludeUsers = @()
    $excludeGroups = @()
    $excludeRoles = @()

    if ($Policy.Conditions -and $Policy.Conditions.Users) {
        $excludeUsers  = @(ConvertTo-ID1StringArray $Policy.Conditions.Users.ExcludeUsers)
        $excludeGroups = @(ConvertTo-ID1StringArray $Policy.Conditions.Users.ExcludeGroups)
        $excludeRoles  = @(ConvertTo-ID1StringArray $Policy.Conditions.Users.ExcludeRoles)
    }

    $controlSummary = @()

    if ($blocksAccess) {
        $controlSummary += "Block"
    }

    if ($requiresPasswordChange) {
        $controlSummary += "Password change"
    }

    if ($requiresMfa) {
        if ($hasAuthStrength) {
            $controlSummary += "MFA/Auth strength"
        }
        else {
            $controlSummary += "MFA"
        }
    }

    if ($controlSummary.Count -eq 0) {
        $controlSummary += "No enforcing control detected"
    }

    $riskType = @()

    if ($isUserRisk) {
        $riskType += "User risk"
    }

    if ($isSignInRisk) {
        $riskType += "Sign-in risk"
    }

    if ($riskType.Count -eq 0) {
        $riskType += "Not risk-based"
    }

    [PSCustomObject]@{
        name                     = $name
        state                    = $state
        state_label              = Get-ID1StateLabel -State $state
        enabled                  = ($state -eq "enabled")
        report_only              = ($state -eq "enabledForReportingButNotEnforced")
        disabled                 = ($state -eq "disabled")

        risk_policy              = [bool]($isUserRisk -or $isSignInRisk)
        user_risk_policy         = $isUserRisk
        sign_in_risk_policy      = $isSignInRisk
        risk_type                = ($riskType -join " + ")

        user_risk_levels         = $userRiskLevels
        sign_in_risk_levels      = $signInRiskLevels

        requires_mfa             = $requiresMfa
        requires_password_change = $requiresPasswordChange
        blocks_access            = $blocksAccess
        has_auth_strength        = $hasAuthStrength
        control_summary          = ($controlSummary -join " + ")

        has_exclusions           = [bool]($excludeUsers.Count -gt 0 -or $excludeGroups.Count -gt 0 -or $excludeRoles.Count -gt 0)
        exclude_users_count      = $excludeUsers.Count
        exclude_groups_count     = $excludeGroups.Count
        exclude_roles_count      = $excludeRoles.Count
    }
}

function Invoke-ZTVP-ID1 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== ID1 - Risk-Based Conditional Access ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        try {
            $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        }
        catch {
            return New-ZTVPResult `
                -ScenarioId "ID1" `
                -ScenarioName "Risk-Based Conditional Access" `
                -Category "Identity Protection" `
                -Status "ERROR" `
                -Risk "CRITICAL" `
                -Findings @(
                    New-ZTVPFinding -Title "Conditional Access policies could not be collected" -Detail $_.Exception.Message
                ) `
                -Recommendations @(
                    New-ZTVPRecommendation -Title "Fix Conditional Access collection" -Detail "Confirm Microsoft Graph permissions allow reading Conditional Access policies."
                ) `
                -Evidence $null `
                -CurrentState "Conditional Access policy evidence was unavailable." `
                -ZeroTrustTarget "User risk and sign-in risk should be enforced through Conditional Access." `
                -GapSummary "ID1 could not be evaluated because Conditional Access evidence was unavailable."
        }

        $policyEvidence = @()

        foreach ($policy in $policies) {
            $policyEvidence += Get-ID1RiskPolicyEvidence -Policy $policy
        }

        $riskPolicies = @($policyEvidence | Where-Object { $_.risk_policy -eq $true })
        $enabledRiskPolicies = @($riskPolicies | Where-Object { $_.enabled -eq $true })
        $reportOnlyRiskPolicies = @($riskPolicies | Where-Object { $_.report_only -eq $true })
        $enabledRiskPoliciesWithExclusions = @($enabledRiskPolicies | Where-Object { $_.has_exclusions -eq $true })

        $enabledUserRiskPolicies = @(
            $riskPolicies |
            Where-Object {
                $_.enabled -eq $true -and
                $_.user_risk_policy -eq $true -and
                ($_.requires_password_change -eq $true -or $_.blocks_access -eq $true)
            }
        )

        $enabledSignInRiskPolicies = @(
            $riskPolicies |
            Where-Object {
                $_.enabled -eq $true -and
                $_.sign_in_risk_policy -eq $true -and
                ($_.requires_mfa -eq $true -or $_.blocks_access -eq $true)
            }
        )

        $reportOnlyUserRiskPolicies = @($riskPolicies | Where-Object { $_.report_only -eq $true -and $_.user_risk_policy -eq $true })
        $reportOnlySignInRiskPolicies = @($riskPolicies | Where-Object { $_.report_only -eq $true -and $_.sign_in_risk_policy -eq $true })

        if ($enabledUserRiskPolicies.Count -eq 0) {
            if ($reportOnlyUserRiskPolicies.Count -gt 0) {
                $findings += New-ZTVPFinding `
                    -Title "User risk protection is report-only" `
                    -Detail ("User risk protection exists but is not enforcing. Policies: " + (($reportOnlyUserRiskPolicies | ForEach-Object { $_.name }) -join ", "))
            }
            else {
                $findings += New-ZTVPFinding `
                    -Title "User risk protection is not enforced" `
                    -Detail "No enabled Conditional Access policy was found that targets user risk and requires password change or blocks access."
            }

            $recommendations += New-ZTVPRecommendation `
                -Title "Enable user risk protection" `
                -Detail "Create or enable a user risk Conditional Access policy. High user risk should require secure password change or block access."
        }

        if ($enabledSignInRiskPolicies.Count -eq 0) {
            if ($reportOnlySignInRiskPolicies.Count -gt 0) {
                $findings += New-ZTVPFinding `
                    -Title "Sign-in risk protection is report-only" `
                    -Detail ("Sign-in risk protection exists but is not enforcing. Policies: " + (($reportOnlySignInRiskPolicies | ForEach-Object { $_.name }) -join ", "))
            }
            else {
                $findings += New-ZTVPFinding `
                    -Title "Sign-in risk protection is not enforced" `
                    -Detail "No enabled Conditional Access policy was found that targets sign-in risk and requires MFA/authentication strength or blocks access."
            }

            $recommendations += New-ZTVPRecommendation `
                -Title "Enable sign-in risk protection" `
                -Detail "Create or enable a sign-in risk Conditional Access policy requiring MFA/authentication strength or blocking risky sign-ins."
        }

        if ($enabledRiskPoliciesWithExclusions.Count -gt 0) {
            $recommendations += New-ZTVPRecommendation `
                -Title "Review risk-policy exclusions in ID4" `
                -Detail ("ID1 confirms enforcement only. Exclusions do not fail ID1. Review excluded users, groups, and roles in ID4. Policies with exclusions: " + (($enabledRiskPoliciesWithExclusions | ForEach-Object { "$($_.name) [users=$($_.exclude_users_count), groups=$($_.exclude_groups_count), roles=$($_.exclude_roles_count)]" }) -join " | "))
        }

        $status = "PASS"
        $risk = "LOW"

        if ($enabledUserRiskPolicies.Count -eq 0 -or $enabledSignInRiskPolicies.Count -eq 0) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }

        $currentState = @(
            "Conditional Access policies assessed: $($policyEvidence.Count)."
            "Risk-based policies detected: $($riskPolicies.Count)."
            "Enabled risk policies: $($enabledRiskPolicies.Count)."
            "Enabled user risk protection policies: $($enabledUserRiskPolicies.Count)."
            "Enabled sign-in risk protection policies: $($enabledSignInRiskPolicies.Count)."
            "Report-only risk policies: $($reportOnlyRiskPolicies.Count)."
            "Enabled risk policies with exclusions: $($enabledRiskPoliciesWithExclusions.Count)."
        ) -join " "

        $zeroTrustTarget = "Risk-based Conditional Access should enforce user risk and sign-in risk. User risk should require secure password change or block access. Sign-in risk should require MFA/authentication strength or block access. Exclusions are reviewed separately in ID4."

        if ($status -eq "PASS") {
            if ($enabledRiskPoliciesWithExclusions.Count -gt 0) {
                $summary = "Risk-based Conditional Access is enforced. User risk and sign-in risk protections are enabled. Exclusions were detected and should be reviewed in ID4."
                $gap = "No risk-based Conditional Access enforcement gap was detected. Exclusions require separate validation in ID4."
            }
            else {
                $summary = "Risk-based Conditional Access is enforced. User risk and sign-in risk protections are enabled with no exclusions detected."
                $gap = "No risk-based Conditional Access enforcement gap was detected."
            }
        }
        else {
            $summary = "Risk-based Conditional Access enforcement gap detected. User risk or sign-in risk protection is not fully enforced."
            $gap = "Risk-based Conditional Access is not aligned because user risk or sign-in risk is not enforced."
        }

        return New-ZTVPResult `
            -ScenarioId "ID1" `
            -ScenarioName "Risk-Based Conditional Access" `
            -Category "Identity Protection" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary = $summary

                conditional_access_policy_count = $policyEvidence.Count
                risk_policy_count = $riskPolicies.Count
                enabled_risk_policy_count = $enabledRiskPolicies.Count
                report_only_risk_policy_count = $reportOnlyRiskPolicies.Count

                enabled_user_risk_policy_count = $enabledUserRiskPolicies.Count
                enabled_sign_in_risk_policy_count = $enabledSignInRiskPolicies.Count
                report_only_user_risk_policy_count = $reportOnlyUserRiskPolicies.Count
                report_only_sign_in_risk_policy_count = $reportOnlySignInRiskPolicies.Count

                enabled_risk_policy_with_exclusion_count = $enabledRiskPoliciesWithExclusions.Count

                risk_policies = $riskPolicies
                risk_policies_with_exclusions = $enabledRiskPoliciesWithExclusions
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gap
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "ID1" `
            -ScenarioName "Risk-Based Conditional Access" `
            -Category "Identity Protection" `
            -Status "ERROR" `
            -Risk "CRITICAL" `
            -Findings @(
                New-ZTVPFinding -Title "Execution error" -Detail $_.Exception.Message
            ) `
            -Recommendations @(
                New-ZTVPRecommendation -Title "Fix ID1 execution issue" -Detail "Review Graph permissions and Conditional Access visibility."
            ) `
            -Evidence $null `
            -CurrentState "ID1 could not complete the risk-based Conditional Access assessment." `
            -ZeroTrustTarget "Risk-based Conditional Access should enforce user risk and sign-in risk protection." `
            -GapSummary "ID1 could not be evaluated because execution failed."
    }
}
