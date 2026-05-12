Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Users.psm1" -Force -DisableNameChecking

function Test-ZTVPA2EmergencyAccountName {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    return ($Value -match '(?i)emergency|break.?glass|breakglass')
}

function Get-ZTVPA2MethodClassification {
    param(
        [array]$Methods
    )

    $normalizedMethods = @()

    foreach ($method in @($Methods)) {
        if (-not [string]::IsNullOrWhiteSpace($method)) {
            $normalizedMethods += $method.ToString().Trim().ToLowerInvariant()
        }
    }

    $phishingResistantMethods = @(
        "fido2",
        "passkey",
        "passkeys",
        "windows_hello",
        "windows_hello_for_business",
        "certificate",
        "certificate_based",
        "certificate_based_authentication",
        "platform_credential",
        "macos_platform_credential",
        "microsoft_authenticator_passwordless"
    )

    $strongButNotConfirmedPhishingResistantMethods = @(
        "microsoft_authenticator",
        "temporary_access_pass"
    )

    $weakOrPhishableMethods = @(
        "phone",
        "sms",
        "voice",
        "email",
        "software_oath",
        "oath"
    )

    $hasPhishingResistant = $false
    $hasStrongButNotConfirmed = $false
    $hasWeakOrPhishable = $false

    foreach ($method in $normalizedMethods) {
        if ($phishingResistantMethods -contains $method) {
            $hasPhishingResistant = $true
        }

        if ($strongButNotConfirmedPhishingResistantMethods -contains $method) {
            $hasStrongButNotConfirmed = $true
        }

        if ($weakOrPhishableMethods -contains $method) {
            $hasWeakOrPhishable = $true
        }
    }

    $readiness = "Missing"

    if ($hasPhishingResistant) {
        $readiness = "PhishingResistant"
    }
    elseif ($hasStrongButNotConfirmed) {
        $readiness = "StrongButNotPhishingResistantConfirmed"
    }
    elseif ($hasWeakOrPhishable) {
        $readiness = "WeakOrPhishableOnly"
    }

    return [PSCustomObject]@{
        methods                       = $normalizedMethods
        has_phishing_resistant_method = $hasPhishingResistant
        has_strong_unconfirmed_method = $hasStrongButNotConfirmed
        has_weak_or_phishable_method  = $hasWeakOrPhishable
        readiness                     = $readiness
    }
}

function Invoke-ZTVP-A2 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== A2 - Phishing-Resistant Authentication Readiness ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $adminUsers = @(Get-ZTVPPrivilegedAccounts)

        $findings = @()
        $recommendations = @()
        $assessedUsers = @()

        foreach ($user in $adminUsers) {
            $classification = Get-ZTVPA2MethodClassification -Methods $user.mfa_methods

            $isEmergency = (
                (Test-ZTVPA2EmergencyAccountName -Value $user.userPrincipalName) -or
                (Test-ZTVPA2EmergencyAccountName -Value $user.displayName)
            )

            $assessedUsers += [PSCustomObject]@{
                userPrincipalName             = $user.userPrincipalName
                displayName                   = $user.displayName
                role                          = $user.role
                is_emergency_account          = $isEmergency
                mfa_known                     = $user.mfa_known
                mfa_enabled                   = $user.mfa_enabled
                mfa_methods                   = $classification.methods
                readiness                     = $classification.readiness
                has_phishing_resistant_method = $classification.has_phishing_resistant_method
                has_strong_unconfirmed_method = $classification.has_strong_unconfirmed_method
                has_weak_or_phishable_method  = $classification.has_weak_or_phishable_method
                mfa_error                     = $user.mfa_error
            }
        }

        $unknownUsers = @(
            $assessedUsers | Where-Object {
                $_.mfa_known -ne $true
            }
        )

        $missingUsers = @(
            $assessedUsers | Where-Object {
                $_.mfa_known -eq $true -and (
                    $_.mfa_enabled -ne $true -or
                    $_.readiness -eq "Missing"
                )
            }
        )

        $phishingResistantUsers = @(
            $assessedUsers | Where-Object {
                $_.readiness -eq "PhishingResistant"
            }
        )

        $strongButNotConfirmedUsers = @(
            $assessedUsers | Where-Object {
                $_.readiness -eq "StrongButNotPhishingResistantConfirmed"
            }
        )

        $weakOnlyUsers = @(
            $assessedUsers | Where-Object {
                $_.readiness -eq "WeakOrPhishableOnly"
            }
        )

        $emergencyWithoutPhishingResistant = @(
            $assessedUsers | Where-Object {
                $_.is_emergency_account -eq $true -and
                $_.readiness -ne "PhishingResistant"
            }
        )

        if ($adminUsers.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No privileged users collected" `
                -Detail "The scenario did not collect any privileged users. This may indicate a collection or permissions issue."

            $recommendations += New-ZTVPRecommendation `
                -Title "Validate privileged account collection" `
                -Detail "Confirm Microsoft Graph permissions and directory role collection before relying on this result."
        }

        if ($unknownUsers.Count -gt 0) {
            $affected = $unknownUsers | ForEach-Object {
                if ([string]::IsNullOrWhiteSpace($_.mfa_error)) {
                    "$($_.userPrincipalName): MFA state unknown"
                }
                else {
                    "$($_.userPrincipalName): $($_.mfa_error)"
                }
            }

            $findings += New-ZTVPFinding `
                -Title "MFA evidence incomplete" `
                -Detail ("The platform could not confirm MFA method state for some privileged users. Affected users: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Complete authentication method evidence" `
                -Detail "Review Graph permissions and MFA collection errors so privileged authentication readiness can be fully assessed."
        }

        if ($missingUsers.Count -gt 0) {
            $affected = $missingUsers | ForEach-Object { $_.userPrincipalName }

            $findings += New-ZTVPFinding `
                -Title "Privileged users missing MFA" `
                -Detail ("Some privileged users have no confirmed MFA registration. Affected users: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Register strong authentication for privileged users" `
                -Detail "Require every privileged account to register at least one strong authentication method, preferably phishing-resistant."
        }

        if ($weakOnlyUsers.Count -gt 0) {
            $affected = $weakOnlyUsers | ForEach-Object {
                "$($_.userPrincipalName) [" + ($_.mfa_methods -join ", ") + "]"
            }

            $findings += New-ZTVPFinding `
                -Title "Privileged users rely only on weak or phishable methods" `
                -Detail ("Some privileged users appear to rely only on methods such as SMS, voice, email, or software OATH. Affected users: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Move privileged users away from weak MFA" `
                -Detail "Prioritize FIDO2/passkeys, Windows Hello for Business, or certificate-based authentication for privileged users."
        }

        if ($strongButNotConfirmedUsers.Count -gt 0) {
            $affected = $strongButNotConfirmedUsers | ForEach-Object {
                "$($_.userPrincipalName) [" + ($_.mfa_methods -join ", ") + "]"
            }

            $findings += New-ZTVPFinding `
                -Title "Strong MFA exists but phishing-resistant readiness is not confirmed" `
                -Detail ("Some privileged users have strong MFA registered, but no confirmed phishing-resistant method was detected from the collected evidence. Affected users: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Adopt phishing-resistant authentication for privileged accounts" `
                -Detail "Move privileged users to phishing-resistant methods such as FIDO2/passkeys, Windows Hello for Business, or certificate-based authentication."
        }

        if ($emergencyWithoutPhishingResistant.Count -gt 0) {
            $affected = $emergencyWithoutPhishingResistant | ForEach-Object {
                "$($_.userPrincipalName) [$($_.readiness)]"
            }

            $findings += New-ZTVPFinding `
                -Title "Emergency accounts are not phishing-resistant ready" `
                -Detail ("Emergency or break-glass privileged accounts were detected without confirmed phishing-resistant authentication readiness. Affected accounts: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Strengthen emergency account authentication design" `
                -Detail "Validate emergency account authentication strategy, compensating controls, monitoring, and cloud-only design."
        }

        $totalPrivilegedUsers = $assessedUsers.Count
        $phishingResistantCount = $phishingResistantUsers.Count
        $strongButUnconfirmedCount = $strongButNotConfirmedUsers.Count
        $weakOnlyCount = $weakOnlyUsers.Count
        $missingCount = $missingUsers.Count
        $unknownCount = $unknownUsers.Count

        if ($totalPrivilegedUsers -eq 0 -or $unknownCount -gt 0 -or $missingCount -gt 0 -or $weakOnlyCount -gt 0) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif ($strongButUnconfirmedCount -gt 0 -or $emergencyWithoutPhishingResistant.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }
        else {
            $status = "PASS"
            $risk = "LOW"
        }

        $currentState = @(
            "Privileged users assessed: $totalPrivilegedUsers."
            "Users with confirmed phishing-resistant methods: $phishingResistantCount."
            "Users with strong MFA but no confirmed phishing-resistant method: $strongButUnconfirmedCount."
            "Users relying only on weak or phishable methods: $weakOnlyCount."
            "Users missing MFA: $missingCount."
            "Users with unknown MFA evidence: $unknownCount."
        ) -join " "

        $zeroTrustTarget = "Privileged users should be ready for phishing-resistant authentication using methods such as FIDO2/passkeys, Windows Hello for Business, or certificate-based authentication. Strong but phishable or unconfirmed methods should not be the long-term target for privileged access."

        if ($status -eq "PASS") {
            $gapSummary = "Privileged accounts appear aligned with the phishing-resistant authentication readiness target."
            $executiveSummary = "Privileged authentication readiness is strong. All assessed privileged users have confirmed phishing-resistant authentication methods."
        }
        elseif ($status -eq "PARTIAL") {
            $gapSummary = "Privileged accounts are partially aligned. Strong MFA exists for some users, but phishing-resistant authentication is not fully confirmed across all privileged accounts."
            $executiveSummary = "Privileged authentication readiness is partially aligned. Some privileged users still need migration to confirmed phishing-resistant authentication."
        }
        else {
            $gapSummary = "Privileged accounts are not aligned with the phishing-resistant authentication readiness target because missing MFA, weak methods, or incomplete evidence were detected."
            $executiveSummary = "Privileged authentication readiness is insufficient. At least one privileged account is missing MFA, relies only on weak/phishable methods, or could not be fully assessed."
        }

        return New-ZTVPResult `
            -ScenarioId "A2" `
            -ScenarioName "Phishing-Resistant Authentication Readiness" `
            -Category "Authentication Security" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary                          = $executiveSummary
                privileged_users_assessed                  = $totalPrivilegedUsers
                phishing_resistant_user_count              = $phishingResistantCount
                strong_but_not_confirmed_user_count        = $strongButUnconfirmedCount
                weak_or_phishable_only_user_count          = $weakOnlyCount
                missing_mfa_user_count                     = $missingCount
                unknown_mfa_user_count                     = $unknownCount
                emergency_without_phishing_resistant_count = $emergencyWithoutPhishingResistant.Count
                phishing_resistant_users                   = @($phishingResistantUsers | ForEach-Object { $_.userPrincipalName })
                strong_but_not_confirmed_users             = @($strongButNotConfirmedUsers | ForEach-Object { $_.userPrincipalName })
                weak_or_phishable_only_users               = @($weakOnlyUsers | ForEach-Object { $_.userPrincipalName })
                missing_mfa_users                          = @($missingUsers | ForEach-Object { $_.userPrincipalName })
                unknown_mfa_users                          = @($unknownUsers | ForEach-Object { $_.userPrincipalName })
                emergency_without_phishing_resistant_users = @($emergencyWithoutPhishingResistant | ForEach-Object { $_.userPrincipalName })
                assessed_users                             = $assessedUsers
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gapSummary
    }
    catch {
        return [PSCustomObject]@{
            scenario_id       = "A2"
            scenario_name     = "Phishing-Resistant Authentication Readiness"
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
                    detail = "Review script loading, Graph connection, permissions, and privileged user MFA collection."
                }
            )
            evidence          = $null
            current_state     = "The engine could not complete phishing-resistant authentication readiness assessment."
            zero_trust_target = "Privileged users should be ready for phishing-resistant authentication."
            gap_summary       = "The scenario could not be evaluated because execution failed."
            timestamp         = (Get-Date).ToString("s")
        }
    }
}


