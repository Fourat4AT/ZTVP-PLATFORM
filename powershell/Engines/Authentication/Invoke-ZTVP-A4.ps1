Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking

function Test-ZTVPA4EmergencyName {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    return ($Value -match '(?i)emergency|break.?glass|breakglass|recovery|tenant.?recovery|emergency.?access')
}

function Get-ZTVPA4UserMfaState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId
    )

    $methodLabels = @()

    try {
        $methods = @(Get-MgUserAuthenticationMethod -UserId $UserId -ErrorAction Stop)

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

        $phishingResistantMethods = @(
            "fido2",
            "windows_hello",
            "certificate",
            "certificate_based",
            "certificate_based_authentication",
            "passkey",
            "passkeys"
        )

        $strongButNotConfirmedMethods = @(
            "microsoft_authenticator",
            "temporary_access_pass"
        )

        $weakOrPhishableMethods = @(
            "phone",
            "email",
            "software_oath",
            "sms",
            "voice",
            "oath"
        )

        $hasPhishingResistant = $false
        $hasStrongUnconfirmed = $false
        $hasWeak = $false

        foreach ($label in $methodLabels) {
            if ($phishingResistantMethods -contains $label) {
                $hasPhishingResistant = $true
            }

            if ($strongButNotConfirmedMethods -contains $label) {
                $hasStrongUnconfirmed = $true
            }

            if ($weakOrPhishableMethods -contains $label) {
                $hasWeak = $true
            }
        }

        $readiness = "Missing"

        if ($hasPhishingResistant) {
            $readiness = "PhishingResistant"
        }
        elseif ($hasStrongUnconfirmed) {
            $readiness = "StrongButNotPhishingResistantConfirmed"
        }
        elseif ($hasWeak) {
            $readiness = "WeakOrPhishableOnly"
        }

        return [PSCustomObject]@{
            mfa_known                      = $true
            mfa_enabled                    = [bool]($methodLabels.Count -gt 0)
            mfa_methods                    = $methodLabels
            readiness                      = $readiness
            has_phishing_resistant_method  = $hasPhishingResistant
            has_strong_unconfirmed_method  = $hasStrongUnconfirmed
            has_weak_or_phishable_method   = $hasWeak
            mfa_error                      = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            mfa_known                      = $false
            mfa_enabled                    = $false
            mfa_methods                    = @()
            readiness                      = "Unknown"
            has_phishing_resistant_method  = $false
            has_strong_unconfirmed_method  = $false
            has_weak_or_phishable_method   = $false
            mfa_error                      = $_.Exception.Message
        }
    }
}

function Get-ZTVPA4UserById {
    param([string]$UserId)

    try {
        return Get-MgUser -UserId $UserId -Property "id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled" -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Invoke-ZTVP-A4 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== A4 - Break-Glass Account Authentication Hygiene ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        # ----------------------------------------------------
        # Collect users
        # ----------------------------------------------------
        $allUsers = @(Get-MgUser -All -Property "id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled")

        # ----------------------------------------------------
        # Discover emergency users by naming pattern
        # ----------------------------------------------------
        $emergencyUserMap = @{}

        foreach ($user in $allUsers) {
            $isEmergencyByName = (
                (Test-ZTVPA4EmergencyName -Value $user.UserPrincipalName) -or
                (Test-ZTVPA4EmergencyName -Value $user.DisplayName)
            )

            if ($isEmergencyByName) {
                $emergencyUserMap[$user.Id] = [PSCustomObject]@{
                    user                  = $user
                    detected_by_name      = $true
                    detected_by_group     = $false
                    emergency_groups      = @()
                }
            }
        }

        # ----------------------------------------------------
        # Discover emergency groups and members
        # ----------------------------------------------------
        $emergencyGroups = @()
        $emergencyGroupErrors = @()

        try {
            $allGroups = @(Get-MgGroup -All -Property "id,displayName,description,securityEnabled,onPremisesSyncEnabled")

            $emergencyGroups = @(
                $allGroups | Where-Object {
                    (Test-ZTVPA4EmergencyName -Value $_.DisplayName) -or
                    (Test-ZTVPA4EmergencyName -Value $_.Description)
                }
            )

            foreach ($group in $emergencyGroups) {
                $members = @()

                try {
                    $members = @(Get-MgGroupMember -GroupId $group.Id -All -ErrorAction Stop)
                }
                catch {
                    $emergencyGroupErrors += "$($group.DisplayName): $($_.Exception.Message)"
                    continue
                }

                foreach ($member in $members) {
                    $memberType = ""

                    if ($member.AdditionalProperties -and $member.AdditionalProperties.ContainsKey("@odata.type")) {
                        $memberType = $member.AdditionalProperties["@odata.type"]
                    }

                    if ($memberType -notmatch "user") {
                        continue
                    }

                    $memberUser = Get-ZTVPA4UserById -UserId $member.Id

                    if ($null -eq $memberUser) {
                        continue
                    }

                    if (-not $emergencyUserMap.ContainsKey($memberUser.Id)) {
                        $emergencyUserMap[$memberUser.Id] = [PSCustomObject]@{
                            user                  = $memberUser
                            detected_by_name      = $false
                            detected_by_group     = $true
                            emergency_groups      = @($group.DisplayName)
                        }
                    }
                    else {
                        $existing = $emergencyUserMap[$memberUser.Id]
                        $existing.detected_by_group = $true
                        $existing.emergency_groups = @($existing.emergency_groups + $group.DisplayName | Sort-Object -Unique)
                    }
                }
            }
        }
        catch {
            $emergencyGroupErrors += $_.Exception.Message
        }

        # ----------------------------------------------------
        # Collect privileged roles
        # ----------------------------------------------------
        $targetRoles = @(
            "Global Administrator",
            "Privileged Role Administrator",
            "Security Administrator",
            "Conditional Access Administrator",
            "Authentication Administrator",
            "User Administrator"
        )

        $roleMap = @{}

        try {
            $roles = @(Get-MgDirectoryRole -All)
            $matchedRoles = @($roles | Where-Object { $_.DisplayName -in $targetRoles })

            foreach ($role in $matchedRoles) {
                $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All)

                foreach ($member in $members) {
                    $upn = $null

                    if ($member.AdditionalProperties -and $member.AdditionalProperties.ContainsKey("userPrincipalName")) {
                        $upn = $member.AdditionalProperties["userPrincipalName"]
                    }

                    if (-not [string]::IsNullOrWhiteSpace($member.Id)) {
                        if (-not $roleMap.ContainsKey($member.Id)) {
                            $roleMap[$member.Id] = @()
                        }

                        $roleMap[$member.Id] = @($roleMap[$member.Id] + $role.DisplayName | Sort-Object -Unique)
                    }

                    if (-not [string]::IsNullOrWhiteSpace($upn)) {
                        $key = $upn.ToLowerInvariant()

                        if (-not $roleMap.ContainsKey($key)) {
                            $roleMap[$key] = @()
                        }

                        $roleMap[$key] = @($roleMap[$key] + $role.DisplayName | Sort-Object -Unique)
                    }
                }
            }
        }
        catch {
            $findings += New-ZTVPFinding `
                -Title "Privileged role evidence incomplete" `
                -Detail ("The platform could not fully collect privileged role assignments. Error: " + $_.Exception.Message)

            $recommendations += New-ZTVPRecommendation `
                -Title "Validate role collection permissions" `
                -Detail "Confirm Microsoft Graph permissions for directory role and role member collection."
        }

        # ----------------------------------------------------
        # Collect Conditional Access exclusions
        # ----------------------------------------------------
        $caPolicies = @()
        $caCollectionError = $null

        try {
            $caPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        }
        catch {
            $caCollectionError = $_.Exception.Message
        }

        # ----------------------------------------------------
        # Assess emergency accounts
        # ----------------------------------------------------
        $assessedUsers = @()

        foreach ($entry in $emergencyUserMap.Values) {
            $user = $entry.user

            $roles = @()

            if ($roleMap.ContainsKey($user.Id)) {
                $roles += $roleMap[$user.Id]
            }

            if (-not [string]::IsNullOrWhiteSpace($user.UserPrincipalName)) {
                $upnKey = $user.UserPrincipalName.ToLowerInvariant()

                if ($roleMap.ContainsKey($upnKey)) {
                    $roles += $roleMap[$upnKey]
                }
            }

            $roles = @($roles | Sort-Object -Unique)

            $mfa = Get-ZTVPA4UserMfaState -UserId $user.Id

            $isSynced = $false
            if ($null -ne $user.OnPremisesSyncEnabled) {
                $isSynced = [bool]$user.OnPremisesSyncEnabled
            }

            $isCloudOnly = -not $isSynced

            $caExcluded = $false
            $caExclusionPolicyNames = @()

            foreach ($policy in $caPolicies) {
                try {
                    $usersCondition = $policy.Conditions.Users

                    $excludeUsers = @($usersCondition.ExcludeUsers)
                    $excludeGroups = @($usersCondition.ExcludeGroups)

                    if ($excludeUsers -contains $user.Id -or $excludeUsers -contains $user.UserPrincipalName) {
                        $caExcluded = $true
                        $caExclusionPolicyNames += $policy.DisplayName
                    }

                    foreach ($groupName in @($entry.emergency_groups)) {
                        $matchedGroup = $emergencyGroups | Where-Object { $_.DisplayName -eq $groupName } | Select-Object -First 1

                        if ($matchedGroup -and ($excludeGroups -contains $matchedGroup.Id)) {
                            $caExcluded = $true
                            $caExclusionPolicyNames += $policy.DisplayName
                        }
                    }
                }
                catch {
                    continue
                }
            }

            $assessedUsers += [PSCustomObject]@{
                userPrincipalName              = $user.UserPrincipalName
                displayName                    = $user.DisplayName
                accountEnabled                 = $user.AccountEnabled
                userType                       = $user.UserType
                detected_by_name               = $entry.detected_by_name
                detected_by_group              = $entry.detected_by_group
                emergency_groups               = @($entry.emergency_groups)
                on_premises_sync_enabled       = $isSynced
                cloud_only                     = $isCloudOnly
                role                           = ($roles -join ", ")
                roles                          = $roles
                is_global_admin                = ($roles -contains "Global Administrator")
                is_privileged                  = ($roles.Count -gt 0)
                mfa_known                      = $mfa.mfa_known
                mfa_enabled                    = $mfa.mfa_enabled
                mfa_methods                    = $mfa.mfa_methods
                readiness                      = $mfa.readiness
                has_phishing_resistant_method  = $mfa.has_phishing_resistant_method
                has_strong_unconfirmed_method  = $mfa.has_strong_unconfirmed_method
                has_weak_or_phishable_method   = $mfa.has_weak_or_phishable_method
                mfa_error                      = $mfa.mfa_error
                excluded_from_ca               = $caExcluded
                ca_exclusion_policy_names      = @($caExclusionPolicyNames | Sort-Object -Unique)
            }
        }

        $emergencyAccounts = @($assessedUsers)
        $activeEmergencyAccounts = @($assessedUsers | Where-Object { $_.accountEnabled -eq $true })
        $disabledEmergencyAccounts = @($assessedUsers | Where-Object { $_.accountEnabled -ne $true })
        $syncedEmergencyAccounts = @($assessedUsers | Where-Object { $_.on_premises_sync_enabled -eq $true })
        $cloudOnlyEmergencyAccounts = @($assessedUsers | Where-Object { $_.cloud_only -eq $true })
        $globalAdminEmergencyAccounts = @($assessedUsers | Where-Object { $_.is_global_admin -eq $true })
        $missingMfaUsers = @($assessedUsers | Where-Object { $_.mfa_known -eq $true -and $_.mfa_enabled -ne $true })
        $unknownMfaUsers = @($assessedUsers | Where-Object { $_.mfa_known -ne $true })
        $weakOnlyUsers = @($assessedUsers | Where-Object { $_.readiness -eq "WeakOrPhishableOnly" })
        $phishingResistantUsers = @($assessedUsers | Where-Object { $_.readiness -eq "PhishingResistant" })
        $strongButNotConfirmedUsers = @($assessedUsers | Where-Object { $_.readiness -eq "StrongButNotPhishingResistantConfirmed" })
        $notPhishingReadyUsers = @($assessedUsers | Where-Object { $_.readiness -ne "PhishingResistant" })
        $caExcludedUsers = @($assessedUsers | Where-Object { $_.excluded_from_ca -eq $true })
        $caExcludedAndWeakUsers = @($assessedUsers | Where-Object {
            $_.excluded_from_ca -eq $true -and
            ($_.readiness -eq "Missing" -or $_.readiness -eq "WeakOrPhishableOnly" -or $_.readiness -eq "Unknown")
        })

        $unexpectedGroupMembers = @(
            $assessedUsers | Where-Object {
                $_.detected_by_group -eq $true -and $_.detected_by_name -ne $true
            }
        )

        # ----------------------------------------------------
        # Findings
        # ----------------------------------------------------

        if ($emergencyAccounts.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No emergency access accounts detected" `
                -Detail "No emergency or break-glass accounts were detected by naming pattern or emergency group membership."

            $recommendations += New-ZTVPRecommendation `
                -Title "Define emergency access accounts" `
                -Detail "Create and document at least two dedicated cloud-only emergency access accounts for tenant recovery."
        }

        if ($activeEmergencyAccounts.Count -eq 1) {
            $findings += New-ZTVPFinding `
                -Title "Only one active emergency access account detected" `
                -Detail "Only one active emergency account was detected. This creates a single point of failure for tenant recovery."

            $recommendations += New-ZTVPRecommendation `
                -Title "Maintain at least two emergency accounts" `
                -Detail "Use at least two dedicated emergency access accounts so one account failure does not block recovery."
        }

        if ($activeEmergencyAccounts.Count -gt 4) {
            $findings += New-ZTVPFinding `
                -Title "Too many active emergency access accounts" `
                -Detail "More than four active emergency accounts were detected. Too many emergency accounts can create unnecessary privileged backdoors."

            $recommendations += New-ZTVPRecommendation `
                -Title "Limit emergency account count" `
                -Detail "Review whether all emergency accounts are required. Keep the number low, controlled, and documented."
        }

        if ($syncedEmergencyAccounts.Count -gt 0) {
            $affected = $syncedEmergencyAccounts | ForEach-Object { $_.userPrincipalName }

            $findings += New-ZTVPFinding `
                -Title "Emergency accounts are synchronized from on-premises" `
                -Detail ("Emergency accounts should be cloud-only. Synced accounts detected: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Use cloud-only emergency accounts" `
                -Detail "Emergency access accounts should not depend on on-premises Active Directory, federation, or directory synchronization."
        }

        if ($globalAdminEmergencyAccounts.Count -eq 0 -and $emergencyAccounts.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "No emergency account has Global Administrator role" `
                -Detail "Emergency accounts were detected, but none appear to have Global Administrator role. They may not be sufficient for tenant recovery."

            $recommendations += New-ZTVPRecommendation `
                -Title "Validate emergency account recovery privilege" `
                -Detail "Ensure emergency accounts have enough privilege to recover the tenant while avoiding unnecessary extra roles."
        }

        if ($missingMfaUsers.Count -gt 0) {
            $affected = $missingMfaUsers | ForEach-Object { $_.userPrincipalName }

            $findings += New-ZTVPFinding `
                -Title "Emergency accounts missing MFA" `
                -Detail ("Some emergency accounts have no confirmed MFA registration. Affected accounts: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Strengthen emergency account authentication" `
                -Detail "Review the emergency account authentication design. If MFA is intentionally not used, compensating controls, secure credential storage, and monitoring must be documented."
        }

        if ($weakOnlyUsers.Count -gt 0) {
            $affected = $weakOnlyUsers | ForEach-Object {
                "$($_.userPrincipalName) [" + ($_.mfa_methods -join ", ") + "]"
            }

            $findings += New-ZTVPFinding `
                -Title "Emergency accounts rely only on weak or phishable methods" `
                -Detail ("Some emergency accounts rely only on weak or phishable methods. Affected accounts: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Move emergency accounts to stronger authentication" `
                -Detail "Use phishing-resistant or carefully controlled strong authentication for emergency access accounts where possible."
        }

        if ($notPhishingReadyUsers.Count -gt 0) {
            $affected = $notPhishingReadyUsers | ForEach-Object {
                "$($_.userPrincipalName) [$($_.readiness)]"
            }

            $findings += New-ZTVPFinding `
                -Title "Emergency accounts are not fully phishing-resistant ready" `
                -Detail ("Some emergency accounts do not have confirmed phishing-resistant authentication readiness. Affected accounts: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Plan phishing-resistant emergency access" `
                -Detail "Prefer FIDO2/passkeys, Windows Hello for Business, or certificate-based authentication where operationally possible."
        }

        if ($caExcludedUsers.Count -gt 0) {
            $affected = $caExcludedUsers | ForEach-Object {
                "$($_.userPrincipalName) [" + ($_.ca_exclusion_policy_names -join ", ") + "]"
            }

            $findings += New-ZTVPFinding `
                -Title "Emergency accounts are excluded from Conditional Access" `
                -Detail ("Emergency account CA exclusion was detected. This can be valid for recovery, but must be controlled and monitored. Affected accounts: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Control emergency Conditional Access exclusions" `
                -Detail "Document why emergency accounts are excluded from Conditional Access and ensure any use triggers urgent alerting."
        }

        if ($caExcludedAndWeakUsers.Count -gt 0) {
            $affected = $caExcludedAndWeakUsers | ForEach-Object { $_.userPrincipalName }

            $findings += New-ZTVPFinding `
                -Title "Critical emergency backdoor risk" `
                -Detail ("Some emergency accounts are excluded from Conditional Access and are missing or weakly protected. Affected accounts: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Remediate emergency backdoor risk" `
                -Detail "Do not allow weak or missing authentication on emergency accounts that bypass Conditional Access unless formally documented with strong compensating controls."
        }

        if ($unexpectedGroupMembers.Count -gt 0) {
            $affected = $unexpectedGroupMembers | ForEach-Object {
                "$($_.userPrincipalName) via group(s): " + ($_.emergency_groups -join ", ")
            }

            $findings += New-ZTVPFinding `
                -Title "Emergency group contains users not named as emergency accounts" `
                -Detail ("An emergency or break-glass group contains users whose account names do not clearly indicate emergency purpose. Affected members: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review emergency group membership" `
                -Detail "Emergency groups should contain only documented emergency accounts. Remove normal users or rename/document accounts clearly."
        }

        if ($emergencyGroupErrors.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Emergency group evidence incomplete" `
                -Detail ("Some emergency groups could not be fully inspected. Errors: " + ($emergencyGroupErrors -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Validate group read permissions" `
                -Detail "Review Microsoft Graph permissions for group and group membership collection."
        }

        if ($caCollectionError) {
            $findings += New-ZTVPFinding `
                -Title "Conditional Access exclusion evidence incomplete" `
                -Detail ("Conditional Access policies could not be collected. Error: " + $caCollectionError)

            $recommendations += New-ZTVPRecommendation `
                -Title "Validate Conditional Access permissions" `
                -Detail "Grant or consent the required Microsoft Graph permissions to read Conditional Access policies."
        }

        # ----------------------------------------------------
        # Status and risk
        # ----------------------------------------------------

        $status = "PASS"
        $risk = "LOW"

        if (
            $emergencyAccounts.Count -eq 0 -or
            $activeEmergencyAccounts.Count -eq 0 -or
            $globalAdminEmergencyAccounts.Count -eq 0 -or
            $syncedEmergencyAccounts.Count -gt 0 -or
            $missingMfaUsers.Count -gt 0 -or
            $caExcludedAndWeakUsers.Count -gt 0
        ) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif (
            $activeEmergencyAccounts.Count -lt 2 -or
            $activeEmergencyAccounts.Count -gt 4 -or
            $notPhishingReadyUsers.Count -gt 0 -or
            $unexpectedGroupMembers.Count -gt 0 -or
            $caExcludedUsers.Count -gt 0 -or
            $unknownMfaUsers.Count -gt 0
        ) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }

        $currentState = @(
            "Emergency accounts detected: $($emergencyAccounts.Count)."
            "Active emergency accounts: $($activeEmergencyAccounts.Count)."
            "Emergency groups detected: $($emergencyGroups.Count)."
            "Cloud-only emergency accounts: $($cloudOnlyEmergencyAccounts.Count)."
            "Synced emergency accounts: $($syncedEmergencyAccounts.Count)."
            "Emergency accounts with Global Administrator: $($globalAdminEmergencyAccounts.Count)."
            "Missing MFA: $($missingMfaUsers.Count)."
            "Confirmed phishing-resistant: $($phishingResistantUsers.Count)."
            "CA-excluded emergency accounts: $($caExcludedUsers.Count)."
            "Unexpected emergency group members: $($unexpectedGroupMembers.Count)."
        ) -join " "

        $zeroTrustTarget = "Emergency access accounts should be dedicated, cloud-only, limited in number, privileged enough for recovery, strongly authenticated, excluded from Conditional Access only when intentional, and monitored for any usage."

        if ($status -eq "PASS") {
            $gapSummary = "Emergency access account hygiene appears aligned with the Zero Trust target."
            $executiveSummary = "Break-glass account hygiene is strong. Emergency accounts are present, controlled, cloud-only, and do not show major authentication or access-control gaps."
        }
        elseif ($status -eq "PARTIAL") {
            $gapSummary = "Emergency access account hygiene is partially aligned, but one or more design or monitoring weaknesses require review."
            $executiveSummary = "Break-glass account hygiene is partially aligned. Emergency access exists, but improvements are needed around phishing-resistant readiness, group membership, CA exclusions, or account count."
        }
        else {
            $gapSummary = "Emergency access account hygiene is not aligned with the target because critical recovery or privileged backdoor risks were detected."
            $executiveSummary = "Break-glass account hygiene is insufficient. Emergency accounts may be missing, synced, weakly protected, improperly privileged, or exposed through Conditional Access exclusions."
        }

        return New-ZTVPResult `
            -ScenarioId "A4" `
            -ScenarioName "Break-Glass Account Authentication Hygiene" `
            -Category "Authentication Security" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary                         = $executiveSummary
                emergency_account_count                   = $emergencyAccounts.Count
                active_emergency_account_count            = $activeEmergencyAccounts.Count
                disabled_emergency_account_count          = $disabledEmergencyAccounts.Count
                emergency_group_count                     = $emergencyGroups.Count
                cloud_only_emergency_account_count        = $cloudOnlyEmergencyAccounts.Count
                synced_emergency_account_count            = $syncedEmergencyAccounts.Count
                global_admin_emergency_account_count      = $globalAdminEmergencyAccounts.Count
                phishing_resistant_user_count             = $phishingResistantUsers.Count
                strong_but_not_confirmed_user_count       = $strongButNotConfirmedUsers.Count
                missing_mfa_user_count                    = $missingMfaUsers.Count
                weak_or_phishable_only_user_count         = $weakOnlyUsers.Count
                unknown_mfa_user_count                    = $unknownMfaUsers.Count
                ca_excluded_emergency_account_count       = $caExcludedUsers.Count
                critical_backdoor_risk_count              = $caExcludedAndWeakUsers.Count
                unexpected_emergency_group_member_count   = $unexpectedGroupMembers.Count

                emergency_accounts                        = @($emergencyAccounts | ForEach-Object { $_.userPrincipalName })
                phishing_resistant_users                  = @($phishingResistantUsers | ForEach-Object { $_.userPrincipalName })
                strong_but_not_confirmed_users            = @($strongButNotConfirmedUsers | ForEach-Object { $_.userPrincipalName })
                missing_mfa_users                         = @($missingMfaUsers | ForEach-Object { $_.userPrincipalName })
                weak_or_phishable_only_users              = @($weakOnlyUsers | ForEach-Object { $_.userPrincipalName })
                unknown_mfa_users                         = @($unknownMfaUsers | ForEach-Object { $_.userPrincipalName })
                emergency_without_phishing_resistant_users = @($notPhishingReadyUsers | ForEach-Object { $_.userPrincipalName })
                synced_emergency_accounts                 = @($syncedEmergencyAccounts | ForEach-Object { $_.userPrincipalName })
                ca_excluded_emergency_accounts            = @($caExcludedUsers | ForEach-Object { $_.userPrincipalName })
                critical_backdoor_risk_accounts           = @($caExcludedAndWeakUsers | ForEach-Object { $_.userPrincipalName })
                unexpected_emergency_group_members        = @($unexpectedGroupMembers | ForEach-Object { $_.userPrincipalName })

                emergency_groups                          = @($emergencyGroups | ForEach-Object { $_.DisplayName })
                assessed_users                            = $assessedUsers
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gapSummary
    }
    catch {
        return [PSCustomObject]@{
            scenario_id       = "A4"
            scenario_name     = "Break-Glass Account Authentication Hygiene"
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
                    detail = "Review Graph connection, permissions, user collection, group collection, role assignments, authentication methods, and Conditional Access access."
                }
            )
            evidence          = $null
            current_state     = "The engine could not complete break-glass account hygiene assessment."
            zero_trust_target = "Emergency access accounts should be dedicated, cloud-only, strongly controlled, and monitored."
            gap_summary       = "The scenario could not be evaluated because execution failed."
            timestamp         = (Get-Date).ToString("s")
        }
    }
}
