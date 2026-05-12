Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Users.psm1" -Force -DisableNameChecking

function Get-ZTVPA3UserMfaState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    $methodLabels = @()
    $mfaKnown = $true
    $mfaError = $null

    try {
        $methods = @(Get-MgUserAuthenticationMethod -UserId $UserPrincipalName -ErrorAction Stop)

        foreach ($method in $methods) {
            $odataType = $null

            if ($method.AdditionalProperties -and $method.AdditionalProperties.ContainsKey("@odata.type")) {
                $odataType = $method.AdditionalProperties["@odata.type"]
            }

            if ([string]::IsNullOrWhiteSpace($odataType)) {
                continue
            }

            switch -Regex ($odataType) {
                "passwordAuthenticationMethod" {
                    # Password is not MFA.
                    continue
                }

                "microsoftAuthenticatorAuthenticationMethod" {
                    $methodLabels += "microsoft_authenticator"
                    continue
                }

                "fido2AuthenticationMethod" {
                    $methodLabels += "fido2"
                    continue
                }

                "windowsHelloForBusinessAuthenticationMethod" {
                    $methodLabels += "windows_hello"
                    continue
                }

                "temporaryAccessPassAuthenticationMethod" {
                    $methodLabels += "temporary_access_pass"
                    continue
                }

                "phoneAuthenticationMethod" {
                    $methodLabels += "phone"
                    continue
                }

                "emailAuthenticationMethod" {
                    $methodLabels += "email"
                    continue
                }

                "softwareOathAuthenticationMethod" {
                    $methodLabels += "software_oath"
                    continue
                }

                default {
                    $methodLabels += ($odataType -replace "#microsoft.graph.", "" -replace "AuthenticationMethod", "")
                    continue
                }
            }
        }

        $methodLabels = @($methodLabels | Sort-Object -Unique)

        $strongMethods = @(
            "microsoft_authenticator",
            "fido2",
            "windows_hello",
            "temporary_access_pass"
        )

        $weakMethods = @(
            "phone",
            "email",
            "software_oath"
        )

        $hasMfa = ($methodLabels.Count -gt 0)

        $hasWeakMethod = $false
        foreach ($label in $methodLabels) {
            if ($weakMethods -contains $label) {
                $hasWeakMethod = $true
            }
        }

        $hasStrongMethod = $false
        foreach ($label in $methodLabels) {
            if ($strongMethods -contains $label) {
                $hasStrongMethod = $true
            }
        }

        return [PSCustomObject]@{
            mfa_enabled = [bool]$hasMfa
            mfa_methods = $methodLabels
            mfa_known   = [bool]$mfaKnown
            weak_mfa    = [bool]($hasWeakMethod -and -not $hasStrongMethod)
            mfa_error   = $mfaError
        }
    }
    catch {
        return [PSCustomObject]@{
            mfa_enabled = $false
            mfa_methods = @()
            mfa_known   = $false
            weak_mfa    = $false
            mfa_error   = $_.Exception.Message
        }
    }
}

function Invoke-ZTVP-A3 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== A3 - Workforce MFA Registration Coverage ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        # Privileged users are excluded because A1/A2 already assess them.
        $privilegedUsers = @(Get-ZTVPPrivilegedAccounts)
        $privilegedLookup = @{}

        foreach ($admin in $privilegedUsers) {
            if (-not [string]::IsNullOrWhiteSpace($admin.userPrincipalName)) {
                $privilegedLookup[$admin.userPrincipalName.ToLowerInvariant()] = $true
            }
        }

        $allUsers = @(Get-MgUser -All -Property "id,displayName,userPrincipalName,accountEnabled,userType")

        $enabledMemberUsers = @(
            $allUsers | Where-Object {
                $_.AccountEnabled -eq $true -and
                $_.UserType -eq "Member" -and
                -not [string]::IsNullOrWhiteSpace($_.UserPrincipalName)
            }
        )

        $standardUsers = @(
            $enabledMemberUsers | Where-Object {
                -not $privilegedLookup.ContainsKey($_.UserPrincipalName.ToLowerInvariant())
            }
        )

        $assessedUsers = @()

        foreach ($user in $standardUsers) {
            $mfa = Get-ZTVPA3UserMfaState -UserPrincipalName $user.UserPrincipalName

            $assessedUsers += [PSCustomObject]@{
                userPrincipalName = $user.UserPrincipalName
                displayName       = $user.DisplayName
                accountEnabled    = $user.AccountEnabled
                userType          = $user.UserType
                mfa_known         = $mfa.mfa_known
                mfa_enabled       = $mfa.mfa_enabled
                mfa_methods       = $mfa.mfa_methods
                weak_mfa          = $mfa.weak_mfa
                mfa_error         = $mfa.mfa_error
            }
        }

        $unknownUsers = @(
            $assessedUsers | Where-Object {
                $_.mfa_known -ne $true
            }
        )

        $missingMfaUsers = @(
            $assessedUsers | Where-Object {
                $_.mfa_known -eq $true -and $_.mfa_enabled -ne $true
            }
        )

        $registeredUsers = @(
            $assessedUsers | Where-Object {
                $_.mfa_known -eq $true -and $_.mfa_enabled -eq $true
            }
        )

        $weakMfaUsers = @(
            $assessedUsers | Where-Object {
                $_.mfa_known -eq $true -and $_.mfa_enabled -eq $true -and $_.weak_mfa -eq $true
            }
        )

        $totalAssessed = $assessedUsers.Count
        $registeredCount = $registeredUsers.Count
        $missingCount = $missingMfaUsers.Count
        $unknownCount = $unknownUsers.Count
        $weakCount = $weakMfaUsers.Count

        $coveragePercent = 0
        if ($totalAssessed -gt 0) {
            $coveragePercent = [math]::Round(($registeredCount / $totalAssessed) * 100, 2)
        }

        if ($totalAssessed -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No standard users assessed" `
                -Detail "The scenario did not find enabled standard users after excluding privileged accounts."

            $recommendations += New-ZTVPRecommendation `
                -Title "Validate user collection" `
                -Detail "Confirm Microsoft Graph permissions and tenant user inventory."
        }

        if ($missingCount -gt 0) {
            $affected = $missingMfaUsers | ForEach-Object { $_.userPrincipalName }

            $findings += New-ZTVPFinding `
                -Title "Enabled standard users missing MFA registration" `
                -Detail ("Some enabled standard users do not have confirmed MFA registration. Affected users: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Complete workforce MFA registration" `
                -Detail "Require all enabled member users to register MFA methods before enforcing stronger access controls."
        }

        if ($weakCount -gt 0) {
            $affected = $weakMfaUsers | ForEach-Object {
                "$($_.userPrincipalName) [" + ($_.mfa_methods -join ", ") + "]"
            }

            $findings += New-ZTVPFinding `
                -Title "Standard users using weak MFA methods only" `
                -Detail ("Some standard users have MFA but rely only on weak methods. Affected users: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Reduce weak MFA usage" `
                -Detail "Move users from SMS, voice, email, or software OATH toward stronger Microsoft Authenticator, FIDO2/passkeys, Windows Hello, or certificate-based methods."
        }

        if ($unknownCount -gt 0) {
            $affected = $unknownUsers | ForEach-Object {
                if ([string]::IsNullOrWhiteSpace($_.mfa_error)) {
                    "$($_.userPrincipalName): MFA state unknown"
                }
                else {
                    "$($_.userPrincipalName): $($_.mfa_error)"
                }
            }

            $findings += New-ZTVPFinding `
                -Title "MFA evidence incomplete for some standard users" `
                -Detail ("MFA method state could not be confirmed for some enabled users. Affected users: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Fix MFA evidence collection" `
                -Detail "Review Microsoft Graph permissions and authentication method collection errors."
        }

        if ($totalAssessed -eq 0 -or $unknownCount -gt 0) {
            $status = "FAIL"
            $risk = "HIGH"
        }
        elseif ($coveragePercent -eq 100 -and $weakCount -eq 0) {
            $status = "PASS"
            $risk = "LOW"
        }
        elseif ($coveragePercent -ge 90) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }
        else {
            $status = "FAIL"
            $risk = "HIGH"
        }

        $currentState = @(
            "Enabled standard users assessed: $totalAssessed."
            "MFA registered users: $registeredCount."
            "MFA coverage: $coveragePercent%."
            "Users missing MFA: $missingCount."
            "Users using weak MFA only: $weakCount."
            "Users with unknown MFA evidence: $unknownCount."
            "Privileged users excluded from this scenario because they are assessed by A1/A2: $($privilegedUsers.Count)."
        ) -join " "

        $zeroTrustTarget = "All enabled standard users should have MFA registered before broad enforcement. Weak MFA-only users should be moved to stronger authentication methods."

        if ($status -eq "PASS") {
            $gapSummary = "Workforce MFA registration coverage is aligned with the target."
            $executiveSummary = "Workforce MFA registration coverage is strong. All assessed enabled standard users have MFA registered and no weak-only MFA usage was detected."
        }
        elseif ($status -eq "PARTIAL") {
            $gapSummary = "Workforce MFA registration coverage is close to the target but still has gaps."
            $executiveSummary = "Workforce MFA registration coverage is partially aligned. Most enabled standard users have MFA registered, but remaining users or weak methods require remediation."
        }
        else {
            $gapSummary = "Workforce MFA registration coverage is not aligned with the target because missing MFA, weak-only methods, or incomplete evidence were detected."
            $executiveSummary = "Workforce MFA registration coverage is insufficient. Some enabled standard users are not fully ready for secure access enforcement."
        }

        return New-ZTVPResult `
            -ScenarioId "A3" `
            -ScenarioName "Workforce MFA Registration Coverage" `
            -Category "Authentication Security" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary             = $executiveSummary
                total_enabled_member_users    = $enabledMemberUsers.Count
                privileged_users_excluded     = $privilegedUsers.Count
                standard_users_assessed       = $totalAssessed
                mfa_registered_user_count     = $registeredCount
                missing_mfa_user_count        = $missingCount
                weak_mfa_user_count           = $weakCount
                unknown_mfa_user_count        = $unknownCount
                mfa_coverage_percent          = $coveragePercent
                mfa_registered_users          = @($registeredUsers | ForEach-Object { $_.userPrincipalName })
                missing_mfa_users             = @($missingMfaUsers | ForEach-Object { $_.userPrincipalName })
                weak_mfa_users                = @($weakMfaUsers | ForEach-Object { $_.userPrincipalName })
                unknown_mfa_users             = @($unknownUsers | ForEach-Object { $_.userPrincipalName })
                assessed_users                = $assessedUsers
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gapSummary
    }
    catch {
        return [PSCustomObject]@{
            scenario_id       = "A3"
            scenario_name     = "Workforce MFA Registration Coverage"
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
                    detail = "Review Microsoft Graph permissions, user collection, and MFA method collection."
                }
            )
            evidence          = $null
            current_state     = "The engine could not complete workforce MFA registration assessment."
            zero_trust_target = "All enabled standard users should have MFA registered."
            gap_summary       = "The scenario could not be evaluated because execution failed."
            timestamp         = (Get-Date).ToString("s")
        }
    }
}
