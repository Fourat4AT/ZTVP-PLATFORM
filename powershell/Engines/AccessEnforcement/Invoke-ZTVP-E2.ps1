Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking

function Convert-ZTVPE2ToLowerArray {
    param($Value)

    $result = @()

    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $result += $item.ToString().ToLowerInvariant()
        }
    }

    return $result
}

function Test-ZTVPE2EmergencyName {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    $v = $Value.ToLowerInvariant()

    return (
        $v -match "emergency" -or
        $v -match "breakglass" -or
        $v -match "break-glass" -or
        $v -match "break_glass" -or
        $v -match "glass" -or
        $v -match "recovery"
    )
}

function Get-ZTVPE2PolicyStateLabel {
    param([string]$State)

    switch ($State) {
        "enabled" { return "Enabled" }
        "enabledForReportingButNotEnforced" { return "Report-only" }
        "disabled" { return "Disabled" }
        default { return $State }
    }
}

function Get-ZTVPE2GroupMembers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    if (Get-Command Get-MgGroupTransitiveMember -ErrorAction SilentlyContinue) {
        return @(Get-MgGroupTransitiveMember -GroupId $GroupId -All -ErrorAction Stop)
    }

    return @(Get-MgGroupMember -GroupId $GroupId -All -ErrorAction Stop)
}

function Invoke-ZTVP-E2 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== E2 - Admin Conditional Access Exclusion Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        # ----------------------------------------------------
        # Collect privileged roles and members
        # ----------------------------------------------------

        $targetRoles = @(
            "Global Administrator",
            "Privileged Role Administrator",
            "Security Administrator",
            "Conditional Access Administrator",
            "Authentication Administrator",
            "User Administrator",
            "Helpdesk Administrator",
            "Exchange Administrator",
            "SharePoint Administrator",
            "Intune Administrator",
            "Application Administrator",
            "Cloud Application Administrator",
            "Global Reader"
        )

        $adminById = @{}
        $roleTemplateMap = @{}
        $roleIdMap = @{}
        $roleNameMap = @{}

        try {
            $roles = @(Get-MgDirectoryRole -All -ErrorAction Stop)
            $matchedRoles = @($roles | Where-Object { $_.DisplayName -in $targetRoles })

            foreach ($role in $matchedRoles) {
                if (-not [string]::IsNullOrWhiteSpace($role.Id)) {
                    $roleIdMap[$role.Id.ToLowerInvariant()] = $role.DisplayName
                }

                if (-not [string]::IsNullOrWhiteSpace($role.RoleTemplateId)) {
                    $roleTemplateMap[$role.RoleTemplateId.ToLowerInvariant()] = $role.DisplayName
                }

                if (-not [string]::IsNullOrWhiteSpace($role.DisplayName)) {
                    $roleNameMap[$role.DisplayName.ToLowerInvariant()] = $role.DisplayName
                }

                $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop)

                foreach ($member in $members) {
                    if ([string]::IsNullOrWhiteSpace($member.Id)) {
                        continue
                    }

                    $upn = $null
                    $displayName = $null

                    if ($member.AdditionalProperties -and $member.AdditionalProperties.ContainsKey("userPrincipalName")) {
                        $upn = $member.AdditionalProperties["userPrincipalName"]
                    }

                    if ($member.AdditionalProperties -and $member.AdditionalProperties.ContainsKey("displayName")) {
                        $displayName = $member.AdditionalProperties["displayName"]
                    }

                    $idKey = $member.Id.ToLowerInvariant()

                    if (-not $adminById.ContainsKey($idKey)) {
                        $adminById[$idKey] = [PSCustomObject]@{
                            id                = $member.Id
                            userPrincipalName = $upn
                            displayName       = $displayName
                            roles             = @()
                        }
                    }

                    $adminById[$idKey].roles = @($adminById[$idKey].roles + $role.DisplayName | Sort-Object -Unique)
                }
            }
        }
        catch {
            return New-ZTVPResult `
                -ScenarioId "E2" `
                -ScenarioName "Admin Conditional Access Exclusion Review" `
                -Category "Access Enforcement" `
                -Status "ERROR" `
                -Risk "CRITICAL" `
                -Findings @(
                    New-ZTVPFinding `
                        -Title "Privileged role evidence unavailable" `
                        -Detail $_.Exception.Message
                ) `
                -Recommendations @(
                    New-ZTVPRecommendation `
                        -Title "Fix privileged role collection" `
                        -Detail "Grant or consent permissions to read directory roles and role members, then rerun E2."
                ) `
                -Evidence $null `
                -CurrentState "Privileged role assignments could not be collected." `
                -ZeroTrustTarget "Privileged users, privileged roles, and admin-containing groups should not be excluded from Conditional Access unless formally approved and monitored." `
                -GapSummary "The scenario could not be evaluated because privileged role evidence was unavailable."
        }

        $adminUsers = @($adminById.Values)

        # ----------------------------------------------------
        # Collect Conditional Access policies
        # ----------------------------------------------------

        try {
            $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        }
        catch {
            return New-ZTVPResult `
                -ScenarioId "E2" `
                -ScenarioName "Admin Conditional Access Exclusion Review" `
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
                        -Detail "Grant or consent permissions to read Conditional Access policies, then rerun E2."
                ) `
                -Evidence $null `
                -CurrentState "Conditional Access policies could not be collected." `
                -ZeroTrustTarget "Privileged users, privileged roles, and admin-containing groups should not be excluded from Conditional Access unless formally approved and monitored." `
                -GapSummary "The scenario could not be evaluated because Conditional Access evidence was unavailable."
        }

        # ----------------------------------------------------
        # Analyze CA exclusions
        # ----------------------------------------------------

        $assessedPolicies = @()
        $riskyPolicies = @()
        $normalRiskyPolicies = @()
        $emergencyRiskyPolicies = @()
        $unresolvedGroups = @()

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

            $usersCondition = $null

            if ($policy.Conditions -and $policy.Conditions.Users) {
                $usersCondition = $policy.Conditions.Users
            }

            $excludeUsers = @()
            $excludeGroups = @()
            $excludeRoles = @()

            if ($null -ne $usersCondition) {
                $excludeUsers = @(Convert-ZTVPE2ToLowerArray -Value $usersCondition.ExcludeUsers)
                $excludeGroups = @(Convert-ZTVPE2ToLowerArray -Value $usersCondition.ExcludeGroups)
                $excludeRoles = @(Convert-ZTVPE2ToLowerArray -Value $usersCondition.ExcludeRoles)
            }

            $normalExcludedAdminUsers = @()
            $emergencyExcludedAdminUsers = @()
            $normalExcludedAdminGroups = @()
            $emergencyExcludedAdminGroups = @()
            $excludedAdminRoles = @()
            $excludedGroupAdminMembers = @()

            foreach ($excludedUser in $excludeUsers) {
                if ($adminById.ContainsKey($excludedUser)) {
                    $admin = $adminById[$excludedUser]

                    $label = $admin.userPrincipalName
                    if ([string]::IsNullOrWhiteSpace($label)) {
                        $label = $admin.displayName
                    }
                    if ([string]::IsNullOrWhiteSpace($label)) {
                        $label = $admin.id
                    }

                    if ((Test-ZTVPE2EmergencyName -Value $label) -or (Test-ZTVPE2EmergencyName -Value $admin.displayName)) {
                        $emergencyExcludedAdminUsers += $label
                    }
                    else {
                        $normalExcludedAdminUsers += $label
                    }
                }
            }

            foreach ($excludedRole in $excludeRoles) {
                if ($roleTemplateMap.ContainsKey($excludedRole)) {
                    $excludedAdminRoles += $roleTemplateMap[$excludedRole]
                }
                elseif ($roleIdMap.ContainsKey($excludedRole)) {
                    $excludedAdminRoles += $roleIdMap[$excludedRole]
                }
                elseif ($roleNameMap.ContainsKey($excludedRole)) {
                    $excludedAdminRoles += $roleNameMap[$excludedRole]
                }
            }

            foreach ($excludedGroup in $excludeGroups) {
                $groupName = $excludedGroup
                $groupIsEmergency = $false

                try {
                    $group = Get-MgGroup -GroupId $excludedGroup -Property "id,displayName" -ErrorAction Stop

                    if ($group -and $group.DisplayName) {
                        $groupName = $group.DisplayName
                    }

                    $groupIsEmergency = (Test-ZTVPE2EmergencyName -Value $groupName)

                    $members = @(Get-ZTVPE2GroupMembers -GroupId $excludedGroup)

                    foreach ($member in $members) {
                        if ([string]::IsNullOrWhiteSpace($member.Id)) {
                            continue
                        }

                        $memberKey = $member.Id.ToLowerInvariant()

                        if ($adminById.ContainsKey($memberKey)) {
                            $admin = $adminById[$memberKey]

                            $label = $admin.userPrincipalName
                            if ([string]::IsNullOrWhiteSpace($label)) {
                                $label = $admin.displayName
                            }
                            if ([string]::IsNullOrWhiteSpace($label)) {
                                $label = $admin.id
                            }

                            $excludedGroupAdminMembers += [PSCustomObject]@{
                                groupId            = $excludedGroup
                                groupName          = $groupName
                                groupIsEmergency  = $groupIsEmergency
                                admin              = $label
                                displayName        = $admin.displayName
                                roles              = $admin.roles
                            }
                        }
                    }
                }
                catch {
                    $unresolvedGroups += [PSCustomObject]@{
                        policyName = $policy.DisplayName
                        groupId    = $excludedGroup
                        error      = $_.Exception.Message
                    }
                }

                $matching = @($excludedGroupAdminMembers | Where-Object { $_.groupId -eq $excludedGroup })

                if ($matching.Count -gt 0) {
                    if ($groupIsEmergency) {
                        $emergencyExcludedAdminGroups += $groupName
                    }
                    else {
                        $normalExcludedAdminGroups += $groupName
                    }
                }
            }

            $normalExcludedAdminUsers = @($normalExcludedAdminUsers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
            $emergencyExcludedAdminUsers = @($emergencyExcludedAdminUsers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
            $normalExcludedAdminGroups = @($normalExcludedAdminGroups | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
            $emergencyExcludedAdminGroups = @($emergencyExcludedAdminGroups | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
            $excludedAdminRoles = @($excludedAdminRoles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

            $hasExclusions = [bool]($excludeUsers.Count -gt 0 -or $excludeGroups.Count -gt 0 -or $excludeRoles.Count -gt 0)

            $hasNormalPrivilegedExclusion = [bool](
                $normalExcludedAdminUsers.Count -gt 0 -or
                $normalExcludedAdminGroups.Count -gt 0 -or
                $excludedAdminRoles.Count -gt 0
            )

            $hasEmergencyPrivilegedExclusion = [bool](
                $emergencyExcludedAdminUsers.Count -gt 0 -or
                $emergencyExcludedAdminGroups.Count -gt 0
            )

            $hasPrivilegedExclusion = [bool]($hasNormalPrivilegedExclusion -or $hasEmergencyPrivilegedExclusion)

            $allExcludedAdminUsers = @($normalExcludedAdminUsers + $emergencyExcludedAdminUsers | Sort-Object -Unique)
            $allExcludedAdminGroups = @($normalExcludedAdminGroups + $emergencyExcludedAdminGroups | Sort-Object -Unique)

            $policyEvidence = [PSCustomObject]@{
                name                                 = $policy.DisplayName
                state                                = $state
                state_label                          = Get-ZTVPE2PolicyStateLabel -State $state
                enabled                              = $enabled
                report_only                          = $reportOnly
                disabled                             = $disabled

                has_exclusions                       = $hasExclusions
                excluded_users_count                 = $excludeUsers.Count
                excluded_groups_count                = $excludeGroups.Count
                excluded_roles_count                 = $excludeRoles.Count

                has_privileged_exclusion             = $hasPrivilegedExclusion
                has_normal_privileged_exclusion      = $hasNormalPrivilegedExclusion
                has_emergency_privileged_exclusion   = $hasEmergencyPrivilegedExclusion

                excluded_admin_users                 = $allExcludedAdminUsers
                excluded_admin_groups                = $allExcludedAdminGroups
                excluded_admin_roles                 = $excludedAdminRoles

                normal_excluded_admin_users          = $normalExcludedAdminUsers
                emergency_excluded_admin_users       = $emergencyExcludedAdminUsers
                normal_excluded_admin_groups         = $normalExcludedAdminGroups
                emergency_excluded_admin_groups      = $emergencyExcludedAdminGroups

                excluded_group_admin_members         = $excludedGroupAdminMembers
            }

            $assessedPolicies += $policyEvidence

            if ($hasPrivilegedExclusion) {
                $riskyPolicies += $policyEvidence
            }

            if ($hasNormalPrivilegedExclusion) {
                $normalRiskyPolicies += $policyEvidence
            }

            if ($hasEmergencyPrivilegedExclusion) {
                $emergencyRiskyPolicies += $policyEvidence
            }
        }

        $policiesWithExclusions = @($assessedPolicies | Where-Object { $_.has_exclusions -eq $true })

        $enabledNormalRiskyPolicies = @($normalRiskyPolicies | Where-Object { $_.enabled -eq $true })
        $reportOnlyNormalRiskyPolicies = @($normalRiskyPolicies | Where-Object { $_.report_only -eq $true })
        $disabledNormalRiskyPolicies = @($normalRiskyPolicies | Where-Object { $_.disabled -eq $true })

        $enabledEmergencyRiskyPolicies = @($emergencyRiskyPolicies | Where-Object { $_.enabled -eq $true })
        $reportOnlyEmergencyRiskyPolicies = @($emergencyRiskyPolicies | Where-Object { $_.report_only -eq $true })
        $disabledEmergencyRiskyPolicies = @($emergencyRiskyPolicies | Where-Object { $_.disabled -eq $true })

        $enabledRiskyPolicies = @($riskyPolicies | Where-Object { $_.enabled -eq $true })
        $reportOnlyRiskyPolicies = @($riskyPolicies | Where-Object { $_.report_only -eq $true })
        $disabledRiskyPolicies = @($riskyPolicies | Where-Object { $_.disabled -eq $true })

        $normalDirectAdminUserExclusions = @($normalRiskyPolicies | ForEach-Object { $_.normal_excluded_admin_users } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        $emergencyDirectAdminUserExclusions = @($emergencyRiskyPolicies | ForEach-Object { $_.emergency_excluded_admin_users } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

        $adminRoleExclusions = @($normalRiskyPolicies | ForEach-Object { $_.excluded_admin_roles } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

        $normalAdminGroupExclusions = @($normalRiskyPolicies | ForEach-Object { $_.normal_excluded_admin_groups } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        $emergencyAdminGroupExclusions = @($emergencyRiskyPolicies | ForEach-Object { $_.emergency_excluded_admin_groups } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

        $allDirectAdminUserExclusions = @($normalDirectAdminUserExclusions + $emergencyDirectAdminUserExclusions | Sort-Object -Unique)
        $allAdminGroupExclusions = @($normalAdminGroupExclusions + $emergencyAdminGroupExclusions | Sort-Object -Unique)

        # ----------------------------------------------------
        # Findings
        # ----------------------------------------------------

        if ($policies.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No Conditional Access policies detected" `
                -Detail "No Conditional Access policies were found, so privileged exclusions could not be assessed."

            $recommendations += New-ZTVPRecommendation `
                -Title "Create Conditional Access baseline" `
                -Detail "Create baseline Conditional Access policies for privileged access, MFA, legacy authentication blocking, and session protection."
        }

        if ($adminUsers.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No privileged users collected" `
                -Detail "No users were collected from monitored privileged roles. This may indicate missing role activation, no assigned admins, or insufficient Graph permissions."

            $recommendations += New-ZTVPRecommendation `
                -Title "Validate privileged role evidence" `
                -Detail "Confirm directory roles are activated and the account can read role memberships."
        }

        if ($enabledNormalRiskyPolicies.Count -gt 0) {
            $affected = $enabledNormalRiskyPolicies | ForEach-Object { $_.name }

            $findings += New-ZTVPFinding `
                -Title "Enabled policies exclude normal privileged access" `
                -Detail ("Enabled Conditional Access policies exclude normal privileged users, privileged roles, or non-emergency groups containing privileged users. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Remove normal privileged Conditional Access exclusions" `
                -Detail "Remove unnecessary normal privileged exclusions or formally document, approve, and monitor them as exceptions."
        }

        if ($enabledEmergencyRiskyPolicies.Count -gt 0) {
            $affected = $enabledEmergencyRiskyPolicies | ForEach-Object { $_.name }

            $findings += New-ZTVPFinding `
                -Title "Enabled policies exclude emergency or break-glass privileged access" `
                -Detail ("Enabled policies exclude emergency/break-glass accounts or groups containing privileged users. This may be expected, but it must be limited, documented, and validated by the break-glass scenario. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Validate emergency Conditional Access exclusions" `
                -Detail "Confirm emergency exclusions are limited to approved break-glass accounts/groups, reviewed in A4, monitored, and not used for normal administration."
        }

        if ($reportOnlyNormalRiskyPolicies.Count -gt 0 -or $reportOnlyEmergencyRiskyPolicies.Count -gt 0) {
            $affected = @($reportOnlyRiskyPolicies | ForEach-Object { $_.name } | Sort-Object -Unique)

            $findings += New-ZTVPFinding `
                -Title "Report-only policies contain privileged exclusions" `
                -Detail ("Report-only policies contain privileged exclusions. These exclusions may become risky if the policies are enabled without review. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review privileged exclusions before enforcement" `
                -Detail "Before enabling report-only policies, validate whether privileged users, roles, emergency groups, or admin-containing groups are excluded."
        }

        if ($disabledNormalRiskyPolicies.Count -gt 0 -or $disabledEmergencyRiskyPolicies.Count -gt 0) {
            $affected = @($disabledRiskyPolicies | ForEach-Object { $_.name } | Sort-Object -Unique)

            $findings += New-ZTVPFinding `
                -Title "Disabled policies contain privileged exclusions" `
                -Detail ("Disabled policies contain privileged exclusions. This may represent stale or unmanaged policy design. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Clean up stale privileged exclusions" `
                -Detail "Remove stale disabled policies or document why privileged exclusions exist before re-enabling them."
        }

        if ($unresolvedGroups.Count -gt 0) {
            $affected = $unresolvedGroups | Select-Object -First 10 | ForEach-Object { "$($_.policyName) [$($_.groupId)]" }

            $findings += New-ZTVPFinding `
                -Title "Some excluded groups could not be inspected" `
                -Detail ("Some excluded groups could not be resolved or expanded, so privileged membership could not be confirmed. Sample: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Validate excluded group visibility" `
                -Detail "Grant or consent permissions to read groups and group memberships, then rerun E2."
        }

        if ($riskyPolicies.Count -eq 0 -and $policies.Count -gt 0 -and $adminUsers.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "No privileged Conditional Access exclusions detected" `
                -Detail "No Conditional Access exclusions were found that directly excluded privileged users, privileged roles, emergency groups, or groups containing privileged users."

            $recommendations += New-ZTVPRecommendation `
                -Title "Continue periodic privileged exclusion review" `
                -Detail "Re-run this validation regularly because Conditional Access exclusions can change over time."
        }

        # ----------------------------------------------------
        # Result logic
        # ----------------------------------------------------

        $status = "PASS"
        $risk = "LOW"

        if ($policies.Count -eq 0 -or $adminUsers.Count -eq 0) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif ($enabledNormalRiskyPolicies.Count -gt 0) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif (
            $enabledEmergencyRiskyPolicies.Count -gt 0 -or
            $reportOnlyRiskyPolicies.Count -gt 0 -or
            $disabledRiskyPolicies.Count -gt 0 -or
            $unresolvedGroups.Count -gt 0
        ) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }

        $currentState = @(
            "Conditional Access policies assessed: $($assessedPolicies.Count)."
            "Policies with any exclusions: $($policiesWithExclusions.Count)."
            "Privileged users assessed: $($adminUsers.Count)."
            "Policies with privileged exclusions: $($riskyPolicies.Count)."
            "Enabled normal privileged exclusion policies: $($enabledNormalRiskyPolicies.Count)."
            "Enabled emergency privileged exclusion policies: $($enabledEmergencyRiskyPolicies.Count)."
            "Report-only privileged exclusion policies: $($reportOnlyRiskyPolicies.Count)."
            "Disabled privileged exclusion policies: $($disabledRiskyPolicies.Count)."
            "Normal direct privileged user exclusions: $($normalDirectAdminUserExclusions.Count)."
            "Emergency direct privileged user exclusions: $($emergencyDirectAdminUserExclusions.Count)."
            "Privileged role exclusions: $($adminRoleExclusions.Count)."
            "Normal admin-containing group exclusions: $($normalAdminGroupExclusions.Count)."
            "Emergency admin-containing group exclusions: $($emergencyAdminGroupExclusions.Count)."
            "Unresolved excluded groups: $($unresolvedGroups.Count)."
        ) -join " "

        $zeroTrustTarget = "Normal privileged users, privileged roles, and non-emergency groups containing privileged users should not be excluded from Conditional Access. Emergency/break-glass exclusions may exist only when formally approved, limited, monitored, and validated by break-glass hygiene controls."

        if ($status -eq "PASS") {
            $gapSummary = "No privileged Conditional Access exclusion risk was detected."
            $executiveSummary = "Privileged Conditional Access exclusion posture appears controlled. The platform did not detect normal privileged or emergency privileged exclusions requiring action."
        }
        elseif ($status -eq "PARTIAL") {
            $gapSummary = "Privileged Conditional Access exclusion posture requires review. Emergency/break-glass exclusions, report-only exclusions, disabled policy exclusions, or unresolved group evidence reduce confidence."
            $executiveSummary = "Privileged Conditional Access exclusion posture is partially controlled. No active normal privileged bypass was confirmed, but emergency/break-glass exclusions or non-enforced policy exclusions require review."
        }
        else {
            $gapSummary = "Privileged Conditional Access exclusion posture is not aligned because normal privileged users, privileged roles, or non-emergency admin-containing groups are excluded from active policy enforcement."
            $executiveSummary = "Critical privileged access bypass risk detected. One or more enabled Conditional Access policies exclude normal privileged users, privileged roles, or non-emergency groups containing privileged users."
        }

        return New-ZTVPResult `
            -ScenarioId "E2" `
            -ScenarioName "Admin Conditional Access Exclusion Review" `
            -Category "Access Enforcement" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary                                = $executiveSummary
                conditional_access_policy_count                  = $assessedPolicies.Count
                policy_with_exclusion_count                      = $policiesWithExclusions.Count
                privileged_user_count                            = $adminUsers.Count

                privileged_exclusion_policy_count                = $riskyPolicies.Count
                enabled_privileged_exclusion_policy_count        = $enabledRiskyPolicies.Count
                report_only_privileged_exclusion_policy_count    = $reportOnlyRiskyPolicies.Count
                disabled_privileged_exclusion_policy_count       = $disabledRiskyPolicies.Count

                enabled_normal_privileged_exclusion_policy_count = $enabledNormalRiskyPolicies.Count
                enabled_emergency_privileged_exclusion_policy_count = $enabledEmergencyRiskyPolicies.Count

                normal_direct_privileged_user_exclusion_count    = $normalDirectAdminUserExclusions.Count
                emergency_direct_privileged_user_exclusion_count = $emergencyDirectAdminUserExclusions.Count
                direct_privileged_user_exclusion_count           = $allDirectAdminUserExclusions.Count

                privileged_role_exclusion_count                  = $adminRoleExclusions.Count

                normal_admin_group_exclusion_count               = $normalAdminGroupExclusions.Count
                emergency_admin_group_exclusion_count            = $emergencyAdminGroupExclusions.Count
                admin_group_exclusion_count                      = $allAdminGroupExclusions.Count

                unresolved_excluded_group_count                  = $unresolvedGroups.Count

                enabled_privileged_exclusion_policy_names        = @($enabledRiskyPolicies | ForEach-Object { $_.name })
                enabled_normal_privileged_exclusion_policy_names = @($enabledNormalRiskyPolicies | ForEach-Object { $_.name })
                enabled_emergency_privileged_exclusion_policy_names = @($enabledEmergencyRiskyPolicies | ForEach-Object { $_.name })
                report_only_privileged_exclusion_policy_names    = @($reportOnlyRiskyPolicies | ForEach-Object { $_.name })
                disabled_privileged_exclusion_policy_names       = @($disabledRiskyPolicies | ForEach-Object { $_.name })

                direct_privileged_user_exclusions                = $allDirectAdminUserExclusions
                normal_direct_privileged_user_exclusions         = $normalDirectAdminUserExclusions
                emergency_direct_privileged_user_exclusions      = $emergencyDirectAdminUserExclusions

                privileged_role_exclusions                       = $adminRoleExclusions

                admin_group_exclusions                           = $allAdminGroupExclusions
                normal_admin_group_exclusions                    = $normalAdminGroupExclusions
                emergency_admin_group_exclusions                 = $emergencyAdminGroupExclusions

                privileged_users                                 = $adminUsers
                risky_policy_details                             = $riskyPolicies
                normal_risky_policy_details                      = $normalRiskyPolicies
                emergency_risky_policy_details                   = $emergencyRiskyPolicies
                unresolved_excluded_groups                       = $unresolvedGroups
                assessed_policies                                = $assessedPolicies
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gapSummary
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "E2" `
            -ScenarioName "Admin Conditional Access Exclusion Review" `
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
                    -Detail "Review Graph connection, permissions, Conditional Access policy collection, role membership collection, and group membership visibility."
            ) `
            -Evidence $null `
            -CurrentState "The engine could not complete privileged Conditional Access exclusion assessment." `
            -ZeroTrustTarget "Privileged users should not be excluded from Conditional Access policies unless formally approved and monitored." `
            -GapSummary "The scenario could not be evaluated because execution failed."
    }
}
