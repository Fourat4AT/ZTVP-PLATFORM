Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking

function Convert-ZTVPA5ToLowerArray {
    param($Value)

    $result = @()

    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $result += $item.ToString().ToLowerInvariant()
        }
    }

    return $result
}

function Test-ZTVPA5LegacyClientCoverage {
    param($ClientAppTypes)

    $apps = @(Convert-ZTVPA5ToLowerArray -Value $ClientAppTypes)

    if ($apps.Count -eq 0) {
        return $false
    }

    # A5 must only count policies explicitly targeting legacy authentication clients.
    # Do NOT treat "all" as legacy auth, because many unrelated block policies use "all".
    $legacyValues = @(
        "exchangeactivesync",
        "eassupported",
        "other"
    )

    foreach ($app in $apps) {
        if ($legacyValues -contains $app) {
            return $true
        }
    }

    return $false
}

function Test-ZTVPA5BlockGrantControl {
    param($GrantControls)

    if ($null -eq $GrantControls) {
        return $false
    }

    $builtInControls = @(Convert-ZTVPA5ToLowerArray -Value $GrantControls.BuiltInControls)

    return ($builtInControls -contains "block")
}

function Test-ZTVPA5PolicyTargetsBroadUsers {
    param($UsersCondition)

    if ($null -eq $UsersCondition) {
        return $false
    }

    $includeUsers = @(Convert-ZTVPA5ToLowerArray -Value $UsersCondition.IncludeUsers)

    # For legacy authentication blocking, the expected baseline is All users.
    # Groups or roles can be valid for testing, but they do not prove tenant-wide protection.
    return ($includeUsers -contains "all")
}

function Get-ZTVPA5ExclusionSummary {
    param($UsersCondition)

    if ($null -eq $UsersCondition) {
        return [PSCustomObject]@{
            has_exclusions        = $false
            excluded_users_count  = 0
            excluded_groups_count = 0
            excluded_roles_count  = 0
        }
    }

    $excludedUsers = @($UsersCondition.ExcludeUsers | Where-Object { $null -ne $_ })
    $excludedGroups = @($UsersCondition.ExcludeGroups | Where-Object { $null -ne $_ })
    $excludedRoles = @($UsersCondition.ExcludeRoles | Where-Object { $null -ne $_ })

    return [PSCustomObject]@{
        has_exclusions        = [bool]($excludedUsers.Count -gt 0 -or $excludedGroups.Count -gt 0 -or $excludedRoles.Count -gt 0)
        excluded_users_count  = $excludedUsers.Count
        excluded_groups_count = $excludedGroups.Count
        excluded_roles_count  = $excludedRoles.Count
    }
}

function Test-ZTVPA5LegacySignIn {
    param($SignIn)

    if ($null -eq $SignIn) {
        return $false
    }

    $client = ""
    $app = ""

    if ($null -ne $SignIn.ClientAppUsed) {
        $client = $SignIn.ClientAppUsed.ToString().ToLowerInvariant()
    }

    if ($null -ne $SignIn.AppDisplayName) {
        $app = $SignIn.AppDisplayName.ToString().ToLowerInvariant()
    }

    $legacyPatterns = @(
        "other clients",
        "exchange activesync",
        "imap",
        "pop",
        "smtp",
        "mapi",
        "ews",
        "autodiscover",
        "legacy"
    )

    foreach ($pattern in $legacyPatterns) {
        if ($client -like "*$pattern*" -or $app -like "*$pattern*") {
            return $true
        }
    }

    return $false
}

function Invoke-ZTVP-A5 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== A5 - Legacy Authentication Bypass Exposure ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        $caPolicies = @()

        try {
            $caPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        }
        catch {
            return New-ZTVPResult `
                -ScenarioId "A5" `
                -ScenarioName "Legacy Authentication Bypass Exposure" `
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
                -ZeroTrustTarget "Legacy authentication should be blocked by enforced Conditional Access controls." `
                -GapSummary "The scenario could not be evaluated because Conditional Access evidence was unavailable."
        }

        $assessedPolicies = @()

        foreach ($policy in $caPolicies) {
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

            $clientAppTypes = @()
            if ($policy.Conditions -and $policy.Conditions.ClientAppTypes) {
                $clientAppTypes = @($policy.Conditions.ClientAppTypes | Where-Object { $null -ne $_ })
            }

            $coversLegacyClients = Test-ZTVPA5LegacyClientCoverage -ClientAppTypes $clientAppTypes
            $blocksAccess = Test-ZTVPA5BlockGrantControl -GrantControls $policy.GrantControls

            $targetsBroadUsers = $false
            $exclusionSummary = Get-ZTVPA5ExclusionSummary -UsersCondition $null

            if ($policy.Conditions -and $policy.Conditions.Users) {
                $targetsBroadUsers = Test-ZTVPA5PolicyTargetsBroadUsers -UsersCondition $policy.Conditions.Users
                $exclusionSummary = Get-ZTVPA5ExclusionSummary -UsersCondition $policy.Conditions.Users
            }

            $isLegacyBlockPolicy = ($coversLegacyClients -and $blocksAccess)

            $assessedPolicies += [PSCustomObject]@{
                name                         = $policy.DisplayName
                state                        = $state
                enabled                      = $isEnabled
                report_only                  = $isReportOnly
                disabled                     = $isDisabled
                client_app_types              = $clientAppTypes
                covers_legacy_clients         = $coversLegacyClients
                blocks_access                 = $blocksAccess
                targets_broad_users           = $targetsBroadUsers
                includes_all_users            = $targetsBroadUsers
                is_legacy_block_policy        = $isLegacyBlockPolicy
                has_exclusions                = $exclusionSummary.has_exclusions
                excluded_users_count          = $exclusionSummary.excluded_users_count
                excluded_groups_count         = $exclusionSummary.excluded_groups_count
                excluded_roles_count          = $exclusionSummary.excluded_roles_count
            }
        }

        $legacyBlockPolicies = @($assessedPolicies | Where-Object { $_.is_legacy_block_policy -eq $true })
        $enabledLegacyBlockPolicies = @($legacyBlockPolicies | Where-Object { $_.enabled -eq $true })
        $reportOnlyLegacyBlockPolicies = @($legacyBlockPolicies | Where-Object { $_.report_only -eq $true })
        $disabledLegacyBlockPolicies = @($legacyBlockPolicies | Where-Object { $_.disabled -eq $true })
        $enabledBroadLegacyBlockPolicies = @($enabledLegacyBlockPolicies | Where-Object { $_.targets_broad_users -eq $true })
        $enabledLegacyBlockPoliciesWithExclusions = @($enabledLegacyBlockPolicies | Where-Object { $_.has_exclusions -eq $true })

        $signinLogChecked = $false
        $signinLogError = $null
        $legacySignIns = @()

        try {
            $startDate = (Get-Date).ToUniversalTime().AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
            $filter = "createdDateTime ge $startDate"

            $signIns = @(Get-MgAuditLogSignIn -Filter $filter -Top 200 -ErrorAction Stop)
            $signinLogChecked = $true

            foreach ($signIn in $signIns) {
                if (Test-ZTVPA5LegacySignIn -SignIn $signIn) {
                    $legacySignIns += [PSCustomObject]@{
                        createdDateTime   = $signIn.CreatedDateTime
                        userPrincipalName = $signIn.UserPrincipalName
                        appDisplayName    = $signIn.AppDisplayName
                        clientAppUsed     = $signIn.ClientAppUsed
                        status            = if ($signIn.Status) { $signIn.Status.ErrorCode } else { $null }
                    }
                }
            }
        }
        catch {
            $signinLogChecked = $false
            $signinLogError = $_.Exception.Message
        }

        if ($legacyBlockPolicies.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No legacy authentication block policy detected" `
                -Detail "No Conditional Access policy was detected that both targets legacy client applications and blocks access."

            $recommendations += New-ZTVPRecommendation `
                -Title "Create a legacy authentication block policy" `
                -Detail "Create a Conditional Access policy that targets legacy client applications such as Exchange ActiveSync and other legacy clients, then blocks access."
        }

        if ($enabledLegacyBlockPolicies.Count -eq 0 -and $legacyBlockPolicies.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Legacy authentication block policy is not enforced" `
                -Detail "Legacy authentication block policies were found, but none are enabled. Policies in report-only or disabled mode do not enforce protection."

            $recommendations += New-ZTVPRecommendation `
                -Title "Move legacy authentication blocking to enforcement" `
                -Detail "Review report-only results and enable the legacy authentication block policy after validating impact."
        }

        if ($reportOnlyLegacyBlockPolicies.Count -gt 0) {
            $affected = $reportOnlyLegacyBlockPolicies | ForEach-Object { $_.name }

            $findings += New-ZTVPFinding `
                -Title "Legacy authentication block policy is in report-only mode" `
                -Detail ("Report-only mode does not block legacy authentication. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review report-only policies" `
                -Detail "Analyze report-only impact and move the legacy authentication block policy to enabled mode when validated."
        }

        if ($disabledLegacyBlockPolicies.Count -gt 0) {
            $affected = $disabledLegacyBlockPolicies | ForEach-Object { $_.name }

            $findings += New-ZTVPFinding `
                -Title "Legacy authentication block policy is disabled" `
                -Detail ("Disabled policies do not enforce protection. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Enable or remove disabled legacy block policies" `
                -Detail "Enable the required policy after testing or remove stale disabled policies to avoid false confidence."
        }

        if ($enabledLegacyBlockPolicies.Count -gt 0 -and $enabledBroadLegacyBlockPolicies.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "Enabled legacy authentication block policy does not include All users" `
                -Detail "At least one enabled legacy authentication block policy exists, but no enabled explicit legacy authentication block policy includes All users."

            $recommendations += New-ZTVPRecommendation `
                -Title "Apply legacy authentication blocking to All users" `
                -Detail "Configure the legacy authentication block policy to include All users. Keep only documented emergency or operational exclusions if required."
        }

        if ($enabledLegacyBlockPoliciesWithExclusions.Count -gt 0) {
            $affected = $enabledLegacyBlockPoliciesWithExclusions | ForEach-Object {
                "$($_.name) [users=$($_.excluded_users_count), groups=$($_.excluded_groups_count), roles=$($_.excluded_roles_count)]"
            }

            $findings += New-ZTVPFinding `
                -Title "Legacy authentication block policy has exclusions" `
                -Detail ("Enabled legacy authentication block policies contain exclusions. Affected policies: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review legacy authentication exclusions" `
                -Detail "Keep exclusions minimal, documented, and monitored. Avoid excluding normal users or broad groups."
        }

        if ($signinLogChecked -and $legacySignIns.Count -gt 0) {
            $affected = $legacySignIns | Select-Object -First 20 | ForEach-Object {
                "$($_.userPrincipalName) [$($_.clientAppUsed)]"
            }

            $findings += New-ZTVPFinding `
                -Title "Recent legacy authentication sign-ins detected" `
                -Detail ("Legacy authentication activity was detected in recent sign-in logs. Sample: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Investigate legacy authentication usage" `
                -Detail "Identify applications, users, or service accounts still relying on legacy authentication and migrate them to modern authentication."
        }

        if (-not $signinLogChecked) {
            $findings += New-ZTVPFinding `
                -Title "Legacy authentication sign-in evidence unavailable" `
                -Detail ("Sign-in logs could not be collected, so the platform could not confirm whether legacy authentication was recently used. Error: " + $signinLogError)

            $recommendations += New-ZTVPRecommendation `
                -Title "Enable sign-in evidence collection" `
                -Detail "Grant or consent the required Graph permissions for sign-in log collection so real legacy authentication usage can be validated."
        }

        $status = "PASS"
        $risk = "LOW"

        if (
            $legacyBlockPolicies.Count -eq 0 -or
            $enabledLegacyBlockPolicies.Count -eq 0 -or
            ($signinLogChecked -and $legacySignIns.Count -gt 0)
        ) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif (
            $enabledBroadLegacyBlockPolicies.Count -eq 0 -or
            $enabledLegacyBlockPoliciesWithExclusions.Count -gt 0 -or
            $reportOnlyLegacyBlockPolicies.Count -gt 0 -or
            $disabledLegacyBlockPolicies.Count -gt 0 -or
            -not $signinLogChecked
        ) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }

        $currentState = @(
            "Conditional Access policies assessed: $($assessedPolicies.Count)."
            "Explicit legacy-auth block policies detected: $($legacyBlockPolicies.Count)."
            "Enabled explicit legacy-auth block policies: $($enabledLegacyBlockPolicies.Count)."
            "Report-only explicit legacy-auth block policies: $($reportOnlyLegacyBlockPolicies.Count)."
            "Disabled explicit legacy-auth block policies: $($disabledLegacyBlockPolicies.Count)."
            "Enabled All-users explicit legacy-auth block policies: $($enabledBroadLegacyBlockPolicies.Count)."
            "Enabled explicit legacy-auth block policies with exclusions: $($enabledLegacyBlockPoliciesWithExclusions.Count)."
            "Sign-in log checked: $signinLogChecked."
            "Recent legacy sign-ins detected: $($legacySignIns.Count)."
        ) -join " "

        $zeroTrustTarget = "Legacy authentication should be blocked by an enabled Conditional Access policy that explicitly targets legacy client applications, includes All users, and blocks access. Report-only or disabled policies should not be treated as enforcement. Exclusions should be minimal, documented, justified, and monitored."

        if ($status -eq "PASS") {
            $gapSummary = "Legacy authentication blocking appears aligned with the Zero Trust target."
            $executiveSummary = "Legacy authentication exposure is controlled. An enabled block policy exists and no recent legacy sign-in activity was detected from available evidence."
        }
        elseif ($status -eq "PARTIAL") {
            $gapSummary = "Legacy authentication blocking is partially aligned, but enforcement scope, exclusions, policy state, or sign-in evidence requires improvement."
            $executiveSummary = "Legacy authentication exposure is partially controlled. A blocking policy may exist, but report-only mode, disabled policy state, exclusions, narrow targeting, or missing sign-in evidence reduce confidence."
        }
        else {
            $gapSummary = "Legacy authentication exposure is not aligned with the target because enforcement is missing or recent legacy usage was detected."
            $executiveSummary = "Legacy authentication exposure is critical. Legacy authentication may bypass MFA and modern access controls because no effective enforced blocking policy was confirmed or legacy usage was observed."
        }

        return New-ZTVPResult `
            -ScenarioId "A5" `
            -ScenarioName "Legacy Authentication Bypass Exposure" `
            -Category "Authentication Security" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary                        = $executiveSummary
                conditional_access_policy_count          = $assessedPolicies.Count
                legacy_block_policy_count                = $legacyBlockPolicies.Count
                enabled_legacy_block_policy_count        = $enabledLegacyBlockPolicies.Count
                report_only_legacy_block_policy_count    = $reportOnlyLegacyBlockPolicies.Count
                disabled_legacy_block_policy_count       = $disabledLegacyBlockPolicies.Count
                enabled_broad_legacy_block_policy_count  = $enabledBroadLegacyBlockPolicies.Count
                legacy_block_policy_with_exclusion_count = $enabledLegacyBlockPoliciesWithExclusions.Count
                signin_log_checked                       = $signinLogChecked
                recent_legacy_signin_count               = $legacySignIns.Count
                signin_log_error                         = $signinLogError
                legacy_block_policy_names                = @($legacyBlockPolicies | ForEach-Object { $_.name })
                enabled_legacy_block_policy_names        = @($enabledLegacyBlockPolicies | ForEach-Object { $_.name })
                report_only_legacy_block_policy_names    = @($reportOnlyLegacyBlockPolicies | ForEach-Object { $_.name })
                disabled_legacy_block_policy_names       = @($disabledLegacyBlockPolicies | ForEach-Object { $_.name })
                legacy_block_policy_with_exclusion_names = @($enabledLegacyBlockPoliciesWithExclusions | ForEach-Object { $_.name })
                assessed_policies                        = $assessedPolicies
                legacy_signins                           = $legacySignIns
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gapSummary
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "A5" `
            -ScenarioName "Legacy Authentication Bypass Exposure" `
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
                    -Detail "Review Graph connection, permissions, Conditional Access policy collection, and sign-in log collection."
            ) `
            -Evidence $null `
            -CurrentState "The engine could not complete legacy authentication exposure assessment." `
            -ZeroTrustTarget "Legacy authentication should be blocked by enabled Conditional Access controls." `
            -GapSummary "The scenario could not be evaluated because execution failed."
    }
}


