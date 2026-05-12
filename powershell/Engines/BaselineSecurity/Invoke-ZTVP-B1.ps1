Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Identity.DirectoryManagement -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Identity.SignIns -Force -ErrorAction SilentlyContinue

function ConvertTo-B1StringArray {
    param($Value)

    $items = @()

    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $items += $item.ToString()
        }
    }

    return $items
}

function ConvertTo-B1LowerArray {
    param($Value)

    $items = @()

    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $items += $item.ToString().ToLowerInvariant()
        }
    }

    return $items
}

function Get-B1StateLabel {
    param([string]$State)

    switch ($State) {
        "enabled" { return "Enabled" }
        "enabledForReportingButNotEnforced" { return "Report-only" }
        "disabled" { return "Disabled" }
        default { return $State }
    }
}

function Test-B1AuthenticationStrength {
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

function Get-B1SecurityDefaultsEvidence {
    $result = [PSCustomObject]@{
        readable                  = $false
        organization_id           = ""
        organization_display_name = ""
        security_defaults_enabled = $null
        security_defaults_state   = "Unknown"
        raw_value                 = ""
        error                     = ""
    }

    try {
        $org = @(Get-MgOrganization -All -Property "id,displayName,securityDefaultsEnabled" -ErrorAction Stop | Select-Object -First 1)

        if ($org.Count -gt 0 -and $null -ne $org[0]) {
            $o = $org[0]
            $result.organization_id = $o.Id
            $result.organization_display_name = $o.DisplayName

            $raw = $null
            $hasValue = $false

            if ($o.PSObject.Properties["SecurityDefaultsEnabled"]) {
                $raw = $o.SecurityDefaultsEnabled
                $hasValue = $true
            }
            elseif ($o.AdditionalProperties -and $o.AdditionalProperties.ContainsKey("securityDefaultsEnabled")) {
                $raw = $o.AdditionalProperties["securityDefaultsEnabled"]
                $hasValue = $true
            }

            if ($hasValue) {
                $result.readable = $true
                $result.raw_value = $raw.ToString()

                if ($raw -eq $true -or $raw.ToString().ToLowerInvariant() -eq "true") {
                    $result.security_defaults_enabled = $true
                    $result.security_defaults_state = "Enabled"
                }
                else {
                    $result.security_defaults_enabled = $false
                    $result.security_defaults_state = "Disabled"
                }

                return $result
            }
        }

        $result.error = "securityDefaultsEnabled property was not returned by Get-MgOrganization."
    }
    catch {
        $result.error = $_.Exception.Message
    }

    try {
        if (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
            $response = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization?`$select=id,displayName,securityDefaultsEnabled" -ErrorAction Stop

            if ($response.value -and $response.value.Count -gt 0) {
                $o = $response.value[0]

                if ($o.id) {
                    $result.organization_id = $o.id.ToString()
                }

                if ($o.displayName) {
                    $result.organization_display_name = $o.displayName.ToString()
                }

                if ($null -ne $o.securityDefaultsEnabled) {
                    $result.readable = $true
                    $result.raw_value = $o.securityDefaultsEnabled.ToString()

                    if ($o.securityDefaultsEnabled -eq $true -or $o.securityDefaultsEnabled.ToString().ToLowerInvariant() -eq "true") {
                        $result.security_defaults_enabled = $true
                        $result.security_defaults_state = "Enabled"
                    }
                    else {
                        $result.security_defaults_enabled = $false
                        $result.security_defaults_state = "Disabled"
                    }

                    $result.error = ""
                    return $result
                }
            }
        }
    }
    catch {
        if ([string]::IsNullOrWhiteSpace($result.error)) {
            $result.error = $_.Exception.Message
        }
    }

    if ([string]::IsNullOrWhiteSpace($result.error)) {
        $result.error = "securityDefaultsEnabled property was not returned."
    }

    return $result
}

function Get-B1ConditionalAccessPolicyEvidence {
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

    $builtInControls = @()
    if ($Policy.GrantControls -and $Policy.GrantControls.BuiltInControls) {
        $builtInControls = @(ConvertTo-B1LowerArray $Policy.GrantControls.BuiltInControls)
    }

    $hasAuthStrength = Test-B1AuthenticationStrength -GrantControls $Policy.GrantControls

    $requiresMfa = [bool](
        $builtInControls -contains "mfa" -or
        $hasAuthStrength -eq $true
    )

    $blocksAccess = [bool]($builtInControls -contains "block")
    $requiresCompliantDevice = [bool]($builtInControls -contains "compliantdevice")
    $requiresHybridDevice = [bool]($builtInControls -contains "domainjoineddevice")
    $requiresDeviceTrust = [bool]($requiresCompliantDevice -or $requiresHybridDevice)

    $includeUsers = @()
    $excludeUsers = @()
    $includeGroups = @()
    $excludeGroups = @()
    $includeRoles = @()
    $excludeRoles = @()

    if ($Policy.Conditions -and $Policy.Conditions.Users) {
        $includeUsers  = @(ConvertTo-B1StringArray $Policy.Conditions.Users.IncludeUsers)
        $excludeUsers  = @(ConvertTo-B1StringArray $Policy.Conditions.Users.ExcludeUsers)
        $includeGroups = @(ConvertTo-B1StringArray $Policy.Conditions.Users.IncludeGroups)
        $excludeGroups = @(ConvertTo-B1StringArray $Policy.Conditions.Users.ExcludeGroups)
        $includeRoles  = @(ConvertTo-B1StringArray $Policy.Conditions.Users.IncludeRoles)
        $excludeRoles  = @(ConvertTo-B1StringArray $Policy.Conditions.Users.ExcludeRoles)
    }

    $includeApps = @()
    if ($Policy.Conditions -and $Policy.Conditions.Applications) {
        $includeApps = @(ConvertTo-B1StringArray $Policy.Conditions.Applications.IncludeApplications)
    }

    $clientAppTypes = @()
    if ($Policy.Conditions -and $Policy.Conditions.ClientAppTypes) {
        $clientAppTypes = @(ConvertTo-B1LowerArray $Policy.Conditions.ClientAppTypes)
    }

    $userRiskLevels = @()
    $signInRiskLevels = @()

    if ($Policy.Conditions) {
        $userRiskLevels = @(ConvertTo-B1LowerArray $Policy.Conditions.UserRiskLevels)
        $signInRiskLevels = @(ConvertTo-B1LowerArray $Policy.Conditions.SignInRiskLevels)
    }

    $targetsAllUsers = [bool](($includeUsers | ForEach-Object { $_.ToLowerInvariant() }) -contains "all")
    $targetsAllApps = [bool](($includeApps | ForEach-Object { $_.ToLowerInvariant() }) -contains "all")
    $targetsRoles = [bool]($includeRoles.Count -gt 0)

    $riskBased = [bool](
        $userRiskLevels.Count -gt 0 -or
        $signInRiskLevels.Count -gt 0 -or
        $nameLower -match "risk"
    )

    $legacyHint = [bool](
        $nameLower -match "legacy" -or
        $nameLower -match "basic auth" -or
        $nameLower -match "devicecode" -or
        $nameLower -match "device code" -or
        $clientAppTypes -contains "exchangeactivesync" -or
        $clientAppTypes -contains "other"
    )

    $baselineControl = [bool](
        $requiresMfa -or
        $hasAuthStrength -or
        $blocksAccess -or
        $requiresDeviceTrust -or
        $riskBased
    )

    $controlSummary = @()

    if ($blocksAccess) {
        $controlSummary += "Block"
    }

    if ($requiresMfa -or $hasAuthStrength) {
        if ($hasAuthStrength) {
            $controlSummary += "MFA/Auth strength"
        }
        else {
            $controlSummary += "MFA"
        }
    }

    if ($requiresDeviceTrust) {
        $controlSummary += "Device trust"
    }

    if ($riskBased) {
        $controlSummary += "Risk-based"
    }

    if ($controlSummary.Count -eq 0) {
        $controlSummary += "No baseline control detected"
    }

    return [PSCustomObject]@{
        policy_id              = $Policy.Id
        policy_name            = $name
        state                  = $state
        state_label            = Get-B1StateLabel -State $state
        enabled                = ($state -eq "enabled")
        report_only            = ($state -eq "enabledForReportingButNotEnforced")
        disabled               = ($state -eq "disabled")
        targets_all_users      = $targetsAllUsers
        targets_all_apps       = $targetsAllApps
        targets_roles          = $targetsRoles
        requires_mfa           = $requiresMfa
        has_auth_strength      = $hasAuthStrength
        blocks_access          = $blocksAccess
        requires_device_trust  = $requiresDeviceTrust
        risk_based             = $riskBased
        legacy_or_basic_hint   = $legacyHint
        baseline_control       = $baselineControl
        include_users_count    = $includeUsers.Count
        exclude_users_count    = $excludeUsers.Count
        include_groups_count   = $includeGroups.Count
        exclude_groups_count   = $excludeGroups.Count
        include_roles_count    = $includeRoles.Count
        exclude_roles_count    = $excludeRoles.Count
        control_summary        = ($controlSummary -join " + ")
    }
}

function Invoke-ZTVP-B1 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== B1 - Tenant Security Defaults and Baseline Control Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        $orgEvidence = Get-B1SecurityDefaultsEvidence

        try {
            $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
            $caReadable = $true
            $caError = ""
        }
        catch {
            $policies = @()
            $caReadable = $false
            $caError = $_.Exception.Message
        }

        $policyEvidence = @()

        foreach ($policy in $policies) {
            $policyEvidence += Get-B1ConditionalAccessPolicyEvidence -Policy $policy
        }

        $enabledPolicies = @($policyEvidence | Where-Object { $_.enabled -eq $true })
        $reportOnlyPolicies = @($policyEvidence | Where-Object { $_.report_only -eq $true })

        $enabledBaselinePolicies = @($enabledPolicies | Where-Object { $_.baseline_control -eq $true })
        $enabledAllUserBaselinePolicies = @($enabledBaselinePolicies | Where-Object { $_.targets_all_users -eq $true })
        $enabledMfaPolicies = @($enabledPolicies | Where-Object { $_.requires_mfa -eq $true -or $_.has_auth_strength -eq $true })
        $enabledBlockPolicies = @($enabledPolicies | Where-Object { $_.blocks_access -eq $true })
        $enabledRiskPolicies = @($enabledPolicies | Where-Object { $_.risk_based -eq $true })
        $enabledLegacyBlockPolicies = @($enabledPolicies | Where-Object { $_.blocks_access -eq $true -and $_.legacy_or_basic_hint -eq $true })
        $reportOnlyBaselinePolicies = @($reportOnlyPolicies | Where-Object { $_.baseline_control -eq $true })

        $customBaselineExists = [bool]($caReadable -eq $true -and $enabledBaselinePolicies.Count -gt 0)

        if ($orgEvidence.security_defaults_state -eq "Unknown") {
            $findings += New-ZTVPFinding `
                -Title "Security Defaults state is unknown" `
                -Detail "Graph did not return securityDefaultsEnabled. This does not prove Security Defaults are disabled. B1 evaluated the custom Conditional Access baseline instead."
        }

        if ($caReadable -eq $false) {
            $findings += New-ZTVPFinding `
                -Title "Conditional Access policies could not be collected" `
                -Detail $caError

            $recommendations += New-ZTVPRecommendation `
                -Title "Fix Conditional Access visibility" `
                -Detail "Confirm Microsoft Graph permissions allow reading Conditional Access policies."
        }

        if ($orgEvidence.security_defaults_state -eq "Disabled" -and $enabledPolicies.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No baseline protection model confirmed" `
                -Detail "Security Defaults are disabled and no enabled Conditional Access policies were found."

            $recommendations += New-ZTVPRecommendation `
                -Title "Enable a baseline protection model" `
                -Detail "Enable Security Defaults for a simple tenant, or implement a custom Conditional Access baseline for MFA, risky sign-ins, legacy authentication blocking, and administrative access."
        }

        if ($customBaselineExists) {
            $recommendations += New-ZTVPRecommendation `
                -Title "Validate the custom Conditional Access baseline through dedicated scenarios" `
                -Detail "B1 confirms that a custom Conditional Access baseline exists. Validate enforcement using A6 for workforce MFA, A1/A2 for admin MFA and phishing-resistant readiness, E1/E2/E3/E5 for CA state, exclusions, report-only dependency, and admin access policy presence, ID1/ID4 for risk-based protection and exclusions, and future Devices/Intune scenarios for compliant-device enforcement."
        }

        if ($reportOnlyBaselinePolicies.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Some baseline controls are report-only" `
                -Detail ("Report-only policies do not enforce protection yet. Policies: " + (($reportOnlyBaselinePolicies | Select-Object -First 20 | ForEach-Object { $_.policy_name }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Move report-only baseline policies through testing before enforcement" `
                -Detail "Test impact, confirm exclusions, validate sign-in behavior, then move approved baseline policies from report-only to enabled state."
        }

        if ($orgEvidence.security_defaults_state -eq "Unknown") {
            $recommendations += New-ZTVPRecommendation `
                -Title "Confirm Security Defaults state separately" `
                -Detail "Check Security Defaults in the Entra admin center or ensure Graph returns securityDefaultsEnabled. Do not treat Unknown as Disabled."
        }

        $status = "PASS"
        $risk = "LOW"

        if ($caReadable -eq $false -and $orgEvidence.security_defaults_state -ne "Enabled") {
            $status = "PARTIAL"
            $risk = "HIGH"
        }
        elseif ($orgEvidence.security_defaults_state -eq "Disabled" -and $enabledPolicies.Count -eq 0) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif ($customBaselineExists -eq $false -and $orgEvidence.security_defaults_state -ne "Enabled") {
            $status = "FAIL"
            $risk = "HIGH"
        }
        elseif ($reportOnlyBaselinePolicies.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }
        elseif ($orgEvidence.security_defaults_state -eq "Unknown") {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }

        $currentState = @(
            "Security Defaults state: $($orgEvidence.security_defaults_state)."
            "Conditional Access readable: $caReadable."
            "Conditional Access policies assessed: $($policyEvidence.Count)."
            "Enabled Conditional Access policies: $($enabledPolicies.Count)."
            "Enabled baseline Conditional Access policies: $($enabledBaselinePolicies.Count)."
            "Enabled all-user baseline policies: $($enabledAllUserBaselinePolicies.Count)."
            "Enabled MFA/authentication-strength policies: $($enabledMfaPolicies.Count)."
            "Enabled block policies: $($enabledBlockPolicies.Count)."
            "Enabled legacy/basic-auth block hints: $($enabledLegacyBlockPolicies.Count)."
            "Enabled risk-based policies: $($enabledRiskPolicies.Count)."
            "Report-only baseline policies: $($reportOnlyBaselinePolicies.Count)."
        ) -join " "

        $zeroTrustTarget = "The tenant should have a clear baseline protection model. Simple tenants may use Security Defaults. Mature tenants may use custom Conditional Access, but the baseline should be validated through dedicated MFA, Conditional Access, Identity Protection, privileged access, and device compliance scenarios."

        if ($status -eq "PASS") {
            if ($orgEvidence.security_defaults_state -eq "Enabled") {
                $summary = "Baseline protection is present because Security Defaults are enabled."
                $gap = "No baseline protection model gap was detected."
            }
            else {
                $summary = "Custom Conditional Access baseline protection is present and enabled."
                $gap = "No major baseline protection model gap was detected."
            }
        }
        elseif ($status -eq "PARTIAL") {
            if ($customBaselineExists) {
                $summary = "Custom Conditional Access baseline exists, but some baseline controls are still report-only or Security Defaults evidence is unknown. Validate coverage through the dedicated scenarios."
                $gap = "Baseline protection is partially aligned because some controls require validation or enforcement review."
            }
            else {
                $summary = "Baseline protection requires review because required evidence or enabled baseline controls were not fully confirmed."
                $gap = "Baseline protection is partially aligned and requires validation."
            }
        }
        else {
            $summary = "Baseline protection gap detected. Security Defaults or an adequate enabled Conditional Access baseline was not confirmed."
            $gap = "Baseline protection is not aligned because no adequate baseline protection model was confirmed."
        }

        $resultArgs = @{
            ScenarioId      = "B1"
            ScenarioName    = "Tenant Security Defaults and Baseline Control Review"
            Category        = "Baseline Security"
            Status          = $status
            Risk            = $risk
            Findings        = $findings
            Recommendations = $recommendations
            Evidence        = [PSCustomObject]@{
                executive_summary = $summary

                security_defaults_state = $orgEvidence.security_defaults_state
                security_defaults_readable = $orgEvidence.readable
                security_defaults_enabled = $orgEvidence.security_defaults_enabled
                organization_id = $orgEvidence.organization_id
                organization_display_name = $orgEvidence.organization_display_name
                security_defaults_error = $orgEvidence.error

                conditional_access_readable = $caReadable
                conditional_access_error = $caError
                conditional_access_policy_count = $policyEvidence.Count
                enabled_conditional_access_policy_count = $enabledPolicies.Count
                report_only_conditional_access_policy_count = $reportOnlyPolicies.Count

                enabled_baseline_policy_count = $enabledBaselinePolicies.Count
                enabled_all_user_baseline_policy_count = $enabledAllUserBaselinePolicies.Count
                enabled_mfa_policy_count = $enabledMfaPolicies.Count
                enabled_block_policy_count = $enabledBlockPolicies.Count
                enabled_legacy_block_policy_count = $enabledLegacyBlockPolicies.Count
                enabled_risk_policy_count = $enabledRiskPolicies.Count
                report_only_baseline_policy_count = $reportOnlyBaselinePolicies.Count

                custom_conditional_access_baseline_exists = $customBaselineExists

                conditional_access_policies = $policyEvidence
                enabled_baseline_policies = $enabledBaselinePolicies
                enabled_all_user_baseline_policies = $enabledAllUserBaselinePolicies
                report_only_baseline_policies = $reportOnlyBaselinePolicies
            }
            CurrentState    = $currentState
            ZeroTrustTarget = $zeroTrustTarget
            GapSummary      = $gap
        }

        return New-ZTVPResult @resultArgs
    }
    catch {
        $resultArgs = @{
            ScenarioId      = "B1"
            ScenarioName    = "Tenant Security Defaults and Baseline Control Review"
            Category        = "Baseline Security"
            Status          = "ERROR"
            Risk            = "CRITICAL"
            Findings        = @(New-ZTVPFinding -Title "Execution error" -Detail $_.Exception.Message)
            Recommendations = @(New-ZTVPRecommendation -Title "Fix B1 execution issue" -Detail "Review Microsoft Graph permissions for organization and Conditional Access evidence.")
            Evidence        = $null
            CurrentState    = "B1 could not complete baseline security assessment."
            ZeroTrustTarget = "The tenant should have either Security Defaults or an equivalent custom Conditional Access baseline."
            GapSummary      = "B1 could not be evaluated because execution failed."
        }

        return New-ZTVPResult @resultArgs
    }
}
