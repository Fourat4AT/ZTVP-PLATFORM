Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Users.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.ConditionalAccess.psm1" -Force -DisableNameChecking

function Test-ZTVPEmergencyAccountName {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    return ($Value -match '(?i)emergency|break.?glass|breakglass')
}

function Get-ZTVPMethodBreakdown {
    param(
        [Parameter(Mandatory = $true)]
        [array]$AdminUsers
    )

    $allMethods = @()

    foreach ($u in $AdminUsers) {
        if ($u.mfa_methods) {
            $allMethods += $u.mfa_methods
        }
    }

    $labels = @(
        "microsoft_authenticator",
        "windows_hello",
        "fido2",
        "software_oath",
        "phone",
        "email",
        "temporary_access_pass"
    )

    $result = [ordered]@{}
    foreach ($label in $labels) {
        $result[$label] = @($allMethods | Where-Object { $_ -eq $label }).Count
    }

    return [PSCustomObject]$result
}

function Invoke-ZTVP-A1 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== A1 - Advanced MFA Enforcement ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $adminUsers = @(Get-ZTVPPrivilegedAccounts)
        $caPolicies = @(Get-ZTVPConditionalAccessPolicies)

        $findings = @()
        $recommendations = @()

        $enabledAdminPolicies = @(
            $caPolicies | Where-Object {
                $_.enabled -eq $true -and $_.covers_admins -eq $true
            }
        )

        $policiesWithExclusions = @(
            $enabledAdminPolicies | Where-Object {
                $_.allows_exclusions -eq $true
            }
        )

        $adminCaMissing = ($enabledAdminPolicies.Count -eq 0)
        $hasPolicyExclusions = ($policiesWithExclusions.Count -gt 0)

        $unknownMfaUsers = @($adminUsers | Where-Object { -not $_.mfa_known })
        $noMfaUsers      = @($adminUsers | Where-Object { $_.mfa_known -eq $true -and $_.mfa_enabled -eq $false })
        $weakMfaUsers    = @($adminUsers | Where-Object { $_.mfa_known -eq $true -and $_.weak_mfa -eq $true })
        $excludedAdminUsers = @($adminUsers | Where-Object { $_.excluded_from_ca -eq $true })

        $enabledAdminPolicyNames = @($enabledAdminPolicies | Select-Object -ExpandProperty name)
        $exclusionPolicyNames    = @($policiesWithExclusions | Select-Object -ExpandProperty name)

        $emergencyNamedAdmins = @(
            $adminUsers | Where-Object {
                (Test-ZTVPEmergencyAccountName -Value $_.userPrincipalName) -or
                (Test-ZTVPEmergencyAccountName -Value $_.displayName)
            }
        )

        $justifiedExclusionLikely = $false
        $riskyExclusionLikely = $false

        if ($hasPolicyExclusions) {
            if ($emergencyNamedAdmins.Count -gt 0) {
                $justifiedExclusionLikely = $true
            }
            else {
                $riskyExclusionLikely = $true
            }
        }

        if ($adminCaMissing) {
            $findings += New-ZTVPFinding -Title "Coverage gap" -Detail "No enabled Conditional Access policy was identified as covering privileged accounts."
            $recommendations += New-ZTVPRecommendation -Title "Create admin CA policy" -Detail "Add or enable a Conditional Access policy that explicitly protects privileged accounts."
        }

        if ($justifiedExclusionLikely) {
            $detailText = "An enabled policy covers admins and allows exclusions that likely correspond to emergency access accounts."
            if ($exclusionPolicyNames.Count -gt 0) {
                $detailText += " Policies: " + ($exclusionPolicyNames -join ", ")
            }
            $findings += New-ZTVPFinding -Title "Emergency-access exclusions likely present" -Detail $detailText
            $recommendations += New-ZTVPRecommendation -Title "Govern emergency exclusions" -Detail "Keep break-glass exclusions minimal, document them, protect the emergency accounts separately, and monitor their use."
        }
        elseif ($riskyExclusionLikely) {
            $detailText = "An enabled policy covers admins, but exclusions are allowed and do not appear justified."
            if ($exclusionPolicyNames.Count -gt 0) {
                $detailText += " Policies: " + ($exclusionPolicyNames -join ", ")
            }
            $findings += New-ZTVPFinding -Title "Risky admin-policy exclusions" -Detail $detailText
            $recommendations += New-ZTVPRecommendation -Title "Remove unnecessary exclusions" -Detail "Restrict exclusions to tightly controlled emergency accounts only."
        }

        if ($excludedAdminUsers.Count -gt 0) {
            $findings += New-ZTVPFinding -Title "Privileged account excluded from CA" -Detail "At least one privileged account appears explicitly excluded from Conditional Access."
            $recommendations += New-ZTVPRecommendation -Title "Review excluded privileged accounts" -Detail "Keep exclusions only for justified emergency access accounts and monitor them closely."
        }

        if ($noMfaUsers.Count -gt 0) {
            $affected = $noMfaUsers | ForEach-Object { $_.userPrincipalName }
            $detail = "At least one privileged account is not registered for MFA."
            if ($affected.Count -gt 0) {
                $detail += " Affected accounts: " + ($affected -join ", ")
            }

            $findings += New-ZTVPFinding -Title "MFA missing" -Detail $detail
            $recommendations += New-ZTVPRecommendation -Title "Register MFA for all privileged accounts" -Detail "Ensure every privileged user is MFA-registered."
        }

        if ($weakMfaUsers.Count -gt 0) {
            $affected = $weakMfaUsers | ForEach-Object { "$($_.userPrincipalName) [" + ($_.mfa_methods -join ", ") + "]" }
            $detail = "At least one privileged account appears to rely on weaker MFA methods."
            if ($affected.Count -gt 0) {
                $detail += " Affected accounts: " + ($affected -join " | ")
            }

            $findings += New-ZTVPFinding -Title "Weak MFA posture" -Detail $detail
            $recommendations += New-ZTVPRecommendation -Title "Adopt stronger MFA methods" -Detail "Prefer Microsoft Authenticator, FIDO2, or Windows Hello for privileged users."
        }

        if ($unknownMfaUsers.Count -gt 0) {
            $exampleErrors = @(
                $unknownMfaUsers |
                Select-Object -First 3 |
                ForEach-Object {
                    if ([string]::IsNullOrWhiteSpace($_.mfa_error)) {
                        "$($_.userPrincipalName): Unknown MFA lookup error"
                    }
                    else {
                        "$($_.userPrincipalName): $($_.mfa_error)"
                    }
                }
            )

            $detail = "The engine could not confirm MFA state for all privileged accounts."
            if ($exampleErrors.Count -gt 0) {
                $detail += " Examples: " + ($exampleErrors -join " | ")
            }

            $findings += New-ZTVPFinding -Title "MFA state not fully collected" -Detail $detail
            $recommendations += New-ZTVPRecommendation -Title "Complete MFA evidence collection" -Detail "Review the MFA collection errors and verify Graph access for all privileged accounts."
        }

        if ($adminCaMissing -or $riskyExclusionLikely -or $noMfaUsers.Count -gt 0) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif ($justifiedExclusionLikely -or $weakMfaUsers.Count -gt 0 -or $unknownMfaUsers.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }
        else {
            $status = "PASS"
            $risk = "LOW"
        }

        $currentState = @(
            if ($enabledAdminPolicies.Count -gt 0) { "At least one enabled Conditional Access policy covers privileged accounts." } else { "No enabled Conditional Access policy was confirmed as covering privileged accounts." }
            if ($justifiedExclusionLikely) { "Exclusions likely correspond to emergency access accounts." }
            elseif ($riskyExclusionLikely) { "Exclusions appear risky." }
            else { "No risky exclusions were inferred." }
            if ($unknownMfaUsers.Count -gt 0) { "MFA state is not fully known for all privileged accounts." }
            elseif ($weakMfaUsers.Count -gt 0) { "Weak MFA usage was detected." }
            elseif ($noMfaUsers.Count -gt 0) { "At least one privileged account appears without MFA." }
            else { "No explicit weak or missing MFA was identified from collected MFA evidence." }
        ) -join " "

        $zeroTrustTarget = "All privileged identities should be protected by strong MFA and Conditional Access, with minimal and justified exclusions only for tightly controlled emergency access accounts."

        if ($adminCaMissing) {
            $gapSummary = "The tenant is not aligned with the Zero Trust target because privileged identities are not fully covered by an enabled Conditional Access policy."
        }
        elseif ($riskyExclusionLikely) {
            $gapSummary = "The tenant is not aligned with the Zero Trust target because risky admin-policy exclusions appear to exist."
        }
        elseif ($justifiedExclusionLikely -or $weakMfaUsers.Count -gt 0 -or $noMfaUsers.Count -gt 0 -or $unknownMfaUsers.Count -gt 0) {
            $gapSummary = "The tenant is partially aligned with the Zero Trust target because exclusions and/or MFA posture still need stronger assurance."
        }
        else {
            $gapSummary = "The tenant appears aligned with the Zero Trust target for this scenario."
        }

        $methodBreakdown = Get-ZTVPMethodBreakdown -AdminUsers $adminUsers

        $executiveSummary = if ($status -eq "FAIL") {
            "Privileged access protection is not sufficient. Although an admin-covering Conditional Access policy exists, privileged accounts remain exposed because at least one admin account is not MFA-registered."
        }
        elseif ($status -eq "PARTIAL") {
            "Privileged access protection is partially aligned with Zero Trust. Core controls exist, but exclusions and/or MFA quality gaps still reduce assurance."
        }
        else {
            "Privileged access protection appears aligned with the Zero Trust objective for this scenario."
        }

        return New-ZTVPResult `
            -ScenarioId "A1" `
            -ScenarioName "Advanced MFA Enforcement" `
            -Category "Authentication Security" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                admin_users                = $adminUsers
                conditional_access         = $caPolicies
                enabled_admin_policy_names = $enabledAdminPolicyNames
                exclusion_policy_names     = $exclusionPolicyNames
                unknown_mfa_user_count     = $unknownMfaUsers.Count
                no_mfa_user_count          = $noMfaUsers.Count
                weak_mfa_user_count        = $weakMfaUsers.Count
                justified_exclusion_likely = $justifiedExclusionLikely
                risky_exclusion_likely     = $riskyExclusionLikely
                no_mfa_users               = @($noMfaUsers | ForEach-Object { $_.userPrincipalName })
                weak_mfa_users             = @($weakMfaUsers | ForEach-Object { $_.userPrincipalName })
                strong_mfa_users           = @($adminUsers | Where-Object { $_.mfa_known -eq $true -and $_.mfa_enabled -eq $true -and $_.weak_mfa -eq $false } | ForEach-Object { $_.userPrincipalName })
                mfa_method_breakdown       = $methodBreakdown
                executive_summary          = $executiveSummary
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gapSummary
    }
    catch {
        return [PSCustomObject]@{
            scenario_id       = "A1"
            scenario_name     = "Advanced MFA Enforcement"
            category          = "Authentication Security"
            status            = "ERROR"
            risk              = "CRITICAL"
            findings          = @(
                [PSCustomObject]@{
                    title  = "Execution error"
                    detail = $_.Exception.Message
                }
            )
            recommendations   = @(
                [PSCustomObject]@{
                    title  = "Fix execution issue"
                    detail = "Review script loading, Graph connection, permissions, and scenario logic."
                }
            )
            evidence          = $null
            current_state     = "The engine could not complete evidence collection."
            zero_trust_target = "All privileged identities should be protected by strong MFA and Conditional Access."
            gap_summary       = "The scenario could not be evaluated because execution failed."
            timestamp         = (Get-Date).ToString("s")
        }
    }
}
