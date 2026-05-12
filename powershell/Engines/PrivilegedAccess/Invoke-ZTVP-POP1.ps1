Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking

function Invoke-ZTVP-POP1 {
    [CmdletBinding()]
    param(
        [int]$StaleDays = 90
    )

    Write-Host ""
    Write-Host "=== POP1 - Privileged AD Group Membership Review ===" -ForegroundColor Cyan

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "POP1" `
            -ScenarioName "Privileged AD Group Membership Review" `
            -Category "Privileged Access" `
            -Status "ERROR" `
            -Risk "CRITICAL" `
            -Findings @(New-ZTVPFinding -Title "Active Directory module unavailable" -Detail "Run this scenario from the domain controller or a domain-joined admin machine with RSAT Active Directory tools installed.") `
            -Recommendations @(New-ZTVPRecommendation -Title "Run POP1 from an AD-connected machine" -Detail "Use the lab domain controller or install RSAT Active Directory tools on a domain-joined admin workstation.") `
            -Evidence $null `
            -CurrentState "Active Directory could not be queried." `
            -ZeroTrustTarget "Privileged AD groups should be minimal, documented, and reviewed." `
            -GapSummary "POP1 could not run because the ActiveDirectory module was unavailable."
    }

    try {
        $domain = Get-ADDomain -ErrorAction Stop
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "POP1" `
            -ScenarioName "Privileged AD Group Membership Review" `
            -Category "Privileged Access" `
            -Status "ERROR" `
            -Risk "CRITICAL" `
            -Findings @(New-ZTVPFinding -Title "AD domain unavailable" -Detail "This machine could not query the AD domain.") `
            -Recommendations @(New-ZTVPRecommendation -Title "Run from a domain-joined machine" -Detail "Run POP1 from the lab domain controller or a domain-joined admin workstation.") `
            -Evidence $null `
            -CurrentState "AD domain evidence was unavailable." `
            -ZeroTrustTarget "Privileged AD groups should be reviewed from a machine that can query AD." `
            -GapSummary "POP1 could not run because the AD domain could not be reached."
    }

    $findings = @()
    $recommendations = @()

    $privilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Server Operators",
        "Backup Operators",
        "Print Operators",
        "Group Policy Creator Owners",
        "DnsAdmins"
    )

    $operatorGroups = @(
        "Account Operators",
        "Server Operators",
        "Backup Operators",
        "Print Operators",
        "Group Policy Creator Owners",
        "DnsAdmins"
    )

    $groupEvidence = @()
    $userEvidence = @()
    $nestedGroupEvidence = @()
    $missingGroups = @()

    foreach ($groupName in $privilegedGroups) {
        try {
            $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
        }
        catch {
            $missingGroups += [PSCustomObject]@{
                Group = $groupName
                Error = $_.Exception.Message
            }
            continue
        }

        $directMembers = @(Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction SilentlyContinue)
        $recursiveMembers = @(Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -ErrorAction SilentlyContinue)

        $directUsers = @($directMembers | Where-Object { $_.objectClass -eq "user" })
        $directGroups = @($directMembers | Where-Object { $_.objectClass -eq "group" })
        $recursiveUsers = @($recursiveMembers | Where-Object { $_.objectClass -eq "user" })

        foreach ($nestedGroup in $directGroups) {
            $nestedGroupEvidence += [PSCustomObject]@{
                PrivilegedGroup = $groupName
                NestedGroup     = $nestedGroup.Name
                SamAccountName  = $nestedGroup.SamAccountName
            }
        }

        foreach ($member in $recursiveUsers) {
            try {
                $user = Get-ADUser `
                    -Identity $member.DistinguishedName `
                    -Properties Enabled,LastLogonDate,PasswordNeverExpires,ServicePrincipalName,UserPrincipalName `
                    -ErrorAction Stop

                $isDirect = $false

                foreach ($directUser in $directUsers) {
                    if ($directUser.DistinguishedName -eq $member.DistinguishedName) {
                        $isDirect = $true
                        break
                    }
                }

                $membershipType = "Nested"
                if ($isDirect) {
                    $membershipType = "Direct"
                }

                $lastLogonAgeDays = $null
                if ($user.LastLogonDate) {
                    $lastLogonAgeDays = [int]((Get-Date) - $user.LastLogonDate).TotalDays
                }

                $serviceLike = $false
                $samLower = $user.SamAccountName.ToLowerInvariant()
                $nameLower = $user.Name.ToLowerInvariant()

                if (
                    $samLower -match '(^svc|svc_|svc-|service|backup|sql|app|sync|adfs|iis)' -or
                    $nameLower -match '(^svc|svc_|svc-|service|backup|sql|app|sync|adfs|iis)' -or
                    ($user.ServicePrincipalName -and @($user.ServicePrincipalName).Count -gt 0)
                ) {
                    $serviceLike = $true
                }

                $userEvidence += [PSCustomObject]@{
                    PrivilegedGroup       = $groupName
                    MembershipType        = $membershipType
                    Name                  = $user.Name
                    SamAccountName        = $user.SamAccountName
                    UserPrincipalName     = $user.UserPrincipalName
                    Enabled               = [bool]$user.Enabled
                    LastLogonDate         = $user.LastLogonDate
                    LastLogonAgeDays      = $lastLogonAgeDays
                    PasswordNeverExpires  = [bool]$user.PasswordNeverExpires
                    ServiceLike           = [bool]$serviceLike
                    DistinguishedName     = $user.DistinguishedName
                }
            }
            catch {}
        }

        $groupEvidence += [PSCustomObject]@{
            GroupName           = $groupName
            DirectMemberCount   = $directMembers.Count
            DirectUserCount     = $directUsers.Count
            DirectGroupCount    = $directGroups.Count
            RecursiveUserCount  = @($recursiveUsers | Select-Object -ExpandProperty DistinguishedName -Unique).Count
            OperatorGroup       = [bool]($operatorGroups -contains $groupName)
        }
    }

    $userEvidence = @($userEvidence | Sort-Object PrivilegedGroup, SamAccountName, MembershipType -Unique)

    $disabledPrivilegedUsers = @($userEvidence | Where-Object { $_.Enabled -eq $false })
    $serviceLikePrivilegedUsers = @($userEvidence | Where-Object { $_.Enabled -eq $true -and $_.ServiceLike -eq $true })
    $stalePrivilegedUsers = @($userEvidence | Where-Object { $_.Enabled -eq $true -and $_.LastLogonAgeDays -ne $null -and $_.LastLogonAgeDays -ge $StaleDays })
    $passwordNeverExpiresUsers = @($userEvidence | Where-Object { $_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $true })
    $populatedOperatorGroups = @($groupEvidence | Where-Object { $_.OperatorGroup -eq $true -and $_.RecursiveUserCount -gt 0 })
    $emergencyUsers = @($userEvidence | Where-Object { $_.SamAccountName -match "(?i)emergency|breakglass|break-glass" -or $_.Name -match "(?i)emergency|breakglass|break-glass" })

    if ($nestedGroupEvidence.Count -gt 0) {
        $findings += New-ZTVPFinding -Title "Nested privileged groups detected" -Detail "$($nestedGroupEvidence.Count) nested group relationship(s) were found inside privileged AD groups."
    }

    if ($disabledPrivilegedUsers.Count -gt 0) {
        $findings += New-ZTVPFinding -Title "Disabled privileged accounts detected" -Detail "$($disabledPrivilegedUsers.Count) disabled account(s) still have privileged AD group membership."
    }

    if ($serviceLikePrivilegedUsers.Count -gt 0) {
        $findings += New-ZTVPFinding -Title "Service-like privileged accounts detected" -Detail "$($serviceLikePrivilegedUsers.Count) service-like account(s) have privileged AD group membership."
    }

    if ($populatedOperatorGroups.Count -gt 0) {
        $findings += New-ZTVPFinding -Title "Sensitive operator groups are populated" -Detail "$($populatedOperatorGroups.Count) sensitive operator group(s) have members."
    }

    if ($stalePrivilegedUsers.Count -gt 0) {
        $findings += New-ZTVPFinding -Title "Stale privileged users detected" -Detail "$($stalePrivilegedUsers.Count) privileged user(s) have not signed in for at least $StaleDays days."
    }

    $recommendations += New-ZTVPRecommendation -Title "Review privileged AD group membership" -Detail "Keep Domain Admins, Enterprise Admins, Schema Admins, Administrators, and operator groups minimal and documented."
    $recommendations += New-ZTVPRecommendation -Title "Review nested privileged groups" -Detail "Nested groups grant AD privilege indirectly. Confirm each nested group has a clear owner and business reason."
    $recommendations += New-ZTVPRecommendation -Title "Remove disabled or stale privileged users" -Detail "Disabled and stale users should not remain in privileged AD groups."
    $recommendations += New-ZTVPRecommendation -Title "Review service-like privileged accounts" -Detail "Service-like accounts should not be privileged unless explicitly required and controlled."

    if ($emergencyUsers.Count -gt 0) {
        $recommendations += New-ZTVPRecommendation -Title "Document emergency privileged accounts" -Detail "$($emergencyUsers.Count) emergency-style privileged account(s) were detected. Confirm they are monitored and not used daily."
    }

    $status = "PASS"
    $risk = "LOW"

    if ($disabledPrivilegedUsers.Count -gt 0 -or $serviceLikePrivilegedUsers.Count -gt 0) {
        $status = "FAIL"
        $risk = "HIGH"
    }
    elseif ($nestedGroupEvidence.Count -gt 0 -or $populatedOperatorGroups.Count -gt 0 -or $stalePrivilegedUsers.Count -gt 0) {
        $status = "PARTIAL"
        $risk = "HIGH"
    }

    if ($status -eq "PASS") {
        $summary = "Privileged AD group membership appears controlled. No nested, disabled, stale, service-like, or operator group issue was detected."
        $gap = "No major privileged AD group membership gap was detected."
    }
    elseif ($status -eq "PARTIAL") {
        $summary = "Privileged AD group membership needs review. Nested privileged groups, populated operator groups, or stale privileged users were detected."
        $gap = "Privileged AD access is partially aligned but requires review."
    }
    else {
        $summary = "Privileged AD group membership has high-risk exposure. Disabled or service-like accounts were found in privileged groups."
        $gap = "Privileged AD access is not aligned because high-risk privileged membership was detected."
    }

    $overview = @(
        "Domain: $($domain.DNSRoot)"
        "Privileged groups assessed: $($groupEvidence.Count)"
        "Privileged users found: $($userEvidence.Count)"
        "Nested privileged groups: $($nestedGroupEvidence.Count)"
        "Disabled privileged users: $($disabledPrivilegedUsers.Count)"
        "Service-like privileged users: $($serviceLikePrivilegedUsers.Count)"
        "Stale privileged users: $($stalePrivilegedUsers.Count)"
        "PasswordNeverExpires privileged users: $($passwordNeverExpiresUsers.Count)"
        "Populated operator groups: $($populatedOperatorGroups.Count)"
    ) -join "; "

    return New-ZTVPResult `
        -ScenarioId "POP1" `
        -ScenarioName "Privileged AD Group Membership Review" `
        -Category "Privileged Access" `
        -Status $status `
        -Risk $risk `
        -Findings $findings `
        -Recommendations $recommendations `
        -Evidence ([PSCustomObject]@{
            executive_summary = $summary
            privileged_access_overview = $overview
            domain_dns_root = $domain.DNSRoot
            privileged_group_count = $groupEvidence.Count
            privileged_user_count = $userEvidence.Count
            nested_privileged_group_count = $nestedGroupEvidence.Count
            disabled_privileged_user_count = $disabledPrivilegedUsers.Count
            service_like_privileged_user_count = $serviceLikePrivilegedUsers.Count
            stale_privileged_user_count = $stalePrivilegedUsers.Count
            password_never_expires_privileged_user_count = $passwordNeverExpiresUsers.Count
            populated_operator_group_count = $populatedOperatorGroups.Count
            emergency_privileged_user_count = $emergencyUsers.Count
            privileged_group_summaries = $groupEvidence
            privileged_users = $userEvidence
            nested_privileged_groups = $nestedGroupEvidence
            disabled_privileged_users = $disabledPrivilegedUsers
            service_like_privileged_users = $serviceLikePrivilegedUsers
            stale_privileged_users = $stalePrivilegedUsers
            password_never_expires_privileged_users = $passwordNeverExpiresUsers
            populated_operator_groups = $populatedOperatorGroups
            emergency_privileged_users = $emergencyUsers
            missing_groups = $missingGroups
        }) `
        -CurrentState $overview `
        -ZeroTrustTarget "Privileged AD group membership should be minimal, documented, and free of disabled, stale, unnecessary nested, or service-like privileged accounts." `
        -GapSummary $gap
}
