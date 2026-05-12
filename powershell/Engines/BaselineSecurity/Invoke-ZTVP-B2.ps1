Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Authentication -Force -ErrorAction SilentlyContinue

function Get-B2ObjectValue {
    param(
        $Object,
        [string[]]$Names
    )

    if ($null -eq $Object) {
        return $null
    }

    foreach ($name in $Names) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($name)) {
                return $Object[$name]
            }
        }

        if ($Object.PSObject.Properties[$name]) {
            return $Object.$name
        }

        if ($Object.PSObject.Properties["AdditionalProperties"] -and $Object.AdditionalProperties) {
            if ($Object.AdditionalProperties.ContainsKey($name)) {
                return $Object.AdditionalProperties[$name]
            }
        }
    }

    return $null
}

function ConvertTo-B2Bool {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -eq $true) {
        return $true
    }

    if ($Value -eq $false) {
        return $false
    }

    $text = $Value.ToString().ToLowerInvariant()

    if ($text -eq "true") {
        return $true
    }

    if ($text -eq "false") {
        return $false
    }

    return $null
}

function ConvertTo-B2Text {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return $Value.ToString()
}

function ConvertTo-B2ReadableState {
    param($Value)

    if ($null -eq $Value) {
        return "Unknown"
    }

    if ($Value -eq $true) {
        return "Allowed"
    }

    if ($Value -eq $false) {
        return "Restricted"
    }

    if ([string]::IsNullOrWhiteSpace($Value.ToString())) {
        return "Unknown"
    }

    return $Value.ToString()
}

function ConvertTo-B2InviteMeaning {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return "Unknown"
    }

    switch ($Value) {
        "none" { return "Restricted" }
        "adminsAndGuestInviters" { return "Limited to admins and Guest Inviters" }
        "adminsGuestInvitersAndAllMembers" { return "Admins, Guest Inviters, and members can invite" }
        "everyone" { return "Everyone can invite guests" }
        default { return $Value }
    }
}

function New-B2SettingEvidence {
    param(
        [string]$Setting,
        $Value,
        [string]$State,
        [string]$Severity,
        [string]$ScenarioOwner,
        [string]$Interpretation
    )

    [PSCustomObject]@{
        setting        = $Setting
        value          = $Value
        state          = $State
        severity       = $Severity
        scenario_owner = $ScenarioOwner
        interpretation = $Interpretation
    }
}

function Get-B2AuthorizationPolicyEvidence {
    try {
        $policy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -ErrorAction Stop

        return [PSCustomObject]@{
            readable = $true
            error    = ""
            policy   = $policy
        }
    }
    catch {
        return [PSCustomObject]@{
            readable = $false
            error    = $_.Exception.Message
            policy   = $null
        }
    }
}

function Invoke-ZTVP-B2 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== B2 - Default User Permissions and App Registration Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        $authz = Get-B2AuthorizationPolicyEvidence

        if ($authz.readable -eq $false) {
            $resultArgs = @{
                ScenarioId      = "B2"
                ScenarioName    = "Default User Permissions and App Registration Review"
                Category        = "Baseline Security"
                Status          = "ERROR"
                Risk            = "CRITICAL"
                Findings        = @(New-ZTVPFinding -Title "Authorization policy could not be read" -Detail $authz.error)
                Recommendations = @(New-ZTVPRecommendation -Title "Fix authorization policy visibility" -Detail "Confirm Microsoft Graph permissions allow reading /policies/authorizationPolicy.")
                Evidence        = $null
                CurrentState    = "Default user permission evidence was unavailable."
                ZeroTrustTarget = "Default user permissions should be restricted so normal users cannot create risky identity objects without governance."
                GapSummary      = "B2 could not be evaluated because authorization policy evidence was unavailable."
            }

            return New-ZTVPResult @resultArgs
        }

        $policy = $authz.policy
        $defaultPerms = Get-B2ObjectValue -Object $policy -Names @("defaultUserRolePermissions", "DefaultUserRolePermissions")

        $allowedToCreateApps = ConvertTo-B2Bool (Get-B2ObjectValue -Object $defaultPerms -Names @("allowedToCreateApps", "AllowedToCreateApps"))
        $allowedToCreateSecurityGroups = ConvertTo-B2Bool (Get-B2ObjectValue -Object $defaultPerms -Names @("allowedToCreateSecurityGroups", "AllowedToCreateSecurityGroups"))
        $allowedToCreateTenants = ConvertTo-B2Bool (Get-B2ObjectValue -Object $defaultPerms -Names @("allowedToCreateTenants", "AllowedToCreateTenants"))
        $allowedToReadOtherUsers = ConvertTo-B2Bool (Get-B2ObjectValue -Object $defaultPerms -Names @("allowedToReadOtherUsers", "AllowedToReadOtherUsers"))

        $permissionGrantPoliciesAssigned = @(Get-B2ObjectValue -Object $defaultPerms -Names @("permissionGrantPoliciesAssigned", "PermissionGrantPoliciesAssigned"))

        $allowInvitesFrom = ConvertTo-B2Text (Get-B2ObjectValue -Object $policy -Names @("allowInvitesFrom", "AllowInvitesFrom"))
        $allowedToSignUpEmailBasedSubscriptions = ConvertTo-B2Bool (Get-B2ObjectValue -Object $policy -Names @("allowedToSignUpEmailBasedSubscriptions", "AllowedToSignUpEmailBasedSubscriptions"))
        $allowedToUseSSPR = ConvertTo-B2Bool (Get-B2ObjectValue -Object $policy -Names @("allowedToUseSSPR", "AllowedToUseSSPR"))
        $allowEmailVerifiedUsersToJoinOrganization = ConvertTo-B2Bool (Get-B2ObjectValue -Object $policy -Names @("allowEmailVerifiedUsersToJoinOrganization", "AllowEmailVerifiedUsersToJoinOrganization"))

        $inviteMeaning = ConvertTo-B2InviteMeaning $allowInvitesFrom

        $settings = @()

        $settings += New-B2SettingEvidence -Setting "Users can register applications" -Value $allowedToCreateApps -State (ConvertTo-B2ReadableState $allowedToCreateApps) -Severity $(if ($allowedToCreateApps -eq $true) { "High" } else { "Low" }) -ScenarioOwner "B2" -Interpretation $(if ($allowedToCreateApps -eq $true) { "Normal users can create app registrations. This should usually be restricted or request-based." } else { "Normal users cannot freely create app registrations." })

        $settings += New-B2SettingEvidence -Setting "Users can create security groups" -Value $allowedToCreateSecurityGroups -State (ConvertTo-B2ReadableState $allowedToCreateSecurityGroups) -Severity $(if ($allowedToCreateSecurityGroups -eq $true) { "High" } else { "Low" }) -ScenarioOwner "B2" -Interpretation $(if ($allowedToCreateSecurityGroups -eq $true) { "Normal users can create security groups. This can weaken group governance." } else { "Normal users cannot freely create security groups." })

        $settings += New-B2SettingEvidence -Setting "Users can create tenants" -Value $allowedToCreateTenants -State (ConvertTo-B2ReadableState $allowedToCreateTenants) -Severity $(if ($allowedToCreateTenants -eq $true) { "High" } else { "Low" }) -ScenarioOwner "B2" -Interpretation $(if ($allowedToCreateTenants -eq $true) { "Normal users can create new tenants. This should usually be restricted." } else { "Normal users cannot create new tenants." })

        $settings += New-B2SettingEvidence -Setting "Guest invitation setting" -Value $allowInvitesFrom -State $inviteMeaning -Severity $(if ($allowInvitesFrom -eq "everyone" -or $allowInvitesFrom -eq "adminsGuestInvitersAndAllMembers") { "Medium" } else { "Low" }) -ScenarioOwner "B2" -Interpretation $(if ($allowInvitesFrom -eq "everyone" -or $allowInvitesFrom -eq "adminsGuestInvitersAndAllMembers") { "Guest invitations are broadly available and should be reviewed." } else { "Guest invitations are limited and not broadly open." })

        $settings += New-B2SettingEvidence -Setting "Email-verified users can join organization" -Value $allowEmailVerifiedUsersToJoinOrganization -State (ConvertTo-B2ReadableState $allowEmailVerifiedUsersToJoinOrganization) -Severity $(if ($allowEmailVerifiedUsersToJoinOrganization -eq $true) { "Medium" } else { "Low" }) -ScenarioOwner "B2" -Interpretation $(if ($allowEmailVerifiedUsersToJoinOrganization -eq $true) { "Email-verified users can join the organization. This should be disabled or justified." } else { "Email-verified users cannot freely join the organization." })

        $settings += New-B2SettingEvidence -Setting "Email-based subscription sign-up" -Value $allowedToSignUpEmailBasedSubscriptions -State (ConvertTo-B2ReadableState $allowedToSignUpEmailBasedSubscriptions) -Severity $(if ($allowedToSignUpEmailBasedSubscriptions -eq $true) { "Medium" } else { "Low" }) -ScenarioOwner "B2" -Interpretation $(if ($allowedToSignUpEmailBasedSubscriptions -eq $true) { "Users can sign up for email-based subscriptions. Review whether this is needed." } else { "Email-based subscription sign-up is restricted." })

        $settings += New-B2SettingEvidence -Setting "Users can read other users" -Value $allowedToReadOtherUsers -State (ConvertTo-B2ReadableState $allowedToReadOtherUsers) -Severity "Informational" -ScenarioOwner "B2" -Interpretation "Directory read visibility is common, but it is recorded for identity exposure context."

        $settings += New-B2SettingEvidence -Setting "Users can use SSPR" -Value $allowedToUseSSPR -State (ConvertTo-B2ReadableState $allowedToUseSSPR) -Severity "Informational" -ScenarioOwner "B4" -Interpretation "SSPR is recorded here for context. Detailed password and SSPR posture belongs in B4."

        $highRiskItems = @($settings | Where-Object { $_.severity -eq "High" })
        $mediumRiskItems = @($settings | Where-Object { $_.severity -eq "Medium" })
        $controlledItems = @($settings | Where-Object { $_.severity -eq "Low" })
        $infoItems = @($settings | Where-Object { $_.severity -eq "Informational" })

        if ($allowedToCreateApps -eq $true) {
            $findings += New-ZTVPFinding -Title "Users can register applications" -Detail "Normal users are allowed to create app registrations. This can increase OAuth/app registration risk unless governed."
            $recommendations += New-ZTVPRecommendation -Title "Restrict app registration creation" -Detail "Disable unrestricted user app registration creation and use an approved request process for application registration."
        }

        if ($allowedToCreateSecurityGroups -eq $true) {
            $findings += New-ZTVPFinding -Title "Users can create security groups" -Detail "Normal users are allowed to create security groups. This can weaken group governance and access review discipline."
            $recommendations += New-ZTVPRecommendation -Title "Restrict security group creation" -Detail "Limit security group creation to admins or approved group owners with governance."
        }

        if ($allowedToCreateTenants -eq $true) {
            $findings += New-ZTVPFinding -Title "Users can create new tenants" -Detail "Normal users are allowed to create new tenants. This is usually not needed for a controlled enterprise tenant."
            $recommendations += New-ZTVPRecommendation -Title "Restrict tenant creation" -Detail "Disable unrestricted tenant creation unless there is a documented business requirement."
        }

        if ($allowInvitesFrom -eq "everyone" -or $allowInvitesFrom -eq "adminsGuestInvitersAndAllMembers") {
            $findings += New-ZTVPFinding -Title "Guest invitations are broadly available" -Detail "Guest invitation setting is: $allowInvitesFrom."
            $recommendations += New-ZTVPRecommendation -Title "Restrict guest invitations" -Detail "Restrict guest invitations to admins, Guest Inviter role, or approved business processes."
        }

        if ($allowEmailVerifiedUsersToJoinOrganization -eq $true) {
            $findings += New-ZTVPFinding -Title "Email-verified users can join the organization" -Detail "Email-verified users appear allowed to join the organization. Review whether this matches tenant governance expectations."
            $recommendations += New-ZTVPRecommendation -Title "Review email-verified join setting" -Detail "Disable or justify email-verified user join behavior according to tenant governance requirements."
        }

        if ($allowedToSignUpEmailBasedSubscriptions -eq $true) {
            $findings += New-ZTVPFinding -Title "Email-based subscription sign-up is allowed" -Detail "Users appear allowed to sign up for email-based subscriptions. Review whether this is intended."
            $recommendations += New-ZTVPRecommendation -Title "Review email-based subscription sign-up" -Detail "Confirm whether users should be allowed to sign up for email-based subscriptions."
        }

        $recommendations += New-ZTVPRecommendation -Title "Review OAuth consent separately in B3" -Detail "B2 records assigned permission grant policies only as context. User consent, admin consent workflow, and enterprise application consent posture should be reviewed in B3."

        $status = "PASS"
        $risk = "LOW"

        if ($highRiskItems.Count -ge 2 -or $allowedToCreateTenants -eq $true) {
            $status = "FAIL"
            $risk = "HIGH"
        }
        elseif ($highRiskItems.Count -eq 1) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }
        elseif ($mediumRiskItems.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }

        $permissionOverview = @(
            "App registration: $(ConvertTo-B2ReadableState $allowedToCreateApps)"
            "Security group creation: $(ConvertTo-B2ReadableState $allowedToCreateSecurityGroups)"
            "Tenant creation: $(ConvertTo-B2ReadableState $allowedToCreateTenants)"
            "Guest invitations: $inviteMeaning"
            "Email-verified join: $(ConvertTo-B2ReadableState $allowEmailVerifiedUsersToJoinOrganization)"
            "Email subscription sign-up: $(ConvertTo-B2ReadableState $allowedToSignUpEmailBasedSubscriptions)"
            "Read other users: $(ConvertTo-B2ReadableState $allowedToReadOtherUsers)"
        ) -join "; "

        $currentState = @(
            "Users can register applications: $allowedToCreateApps."
            "Users can create security groups: $allowedToCreateSecurityGroups."
            "Users can create tenants: $allowedToCreateTenants."
            "Users can read other users: $allowedToReadOtherUsers."
            "Guest invite setting: $allowInvitesFrom ($inviteMeaning)."
            "Email-verified users can join organization: $allowEmailVerifiedUsersToJoinOrganization."
            "Email-based subscription sign-up allowed: $allowedToSignUpEmailBasedSubscriptions."
            "Permission grant policies assigned count: $($permissionGrantPoliciesAssigned.Count)."
        ) -join " "

        $zeroTrustTarget = "Default user permissions should follow least privilege. Normal users should not freely create application registrations, security groups, tenants, or broad external collaboration paths without governance. OAuth/user consent is reviewed separately in B3, and password/SSPR posture is reviewed separately in B4."

        if ($status -eq "PASS") {
            $summary = "Default user permissions are controlled. $permissionOverview."
            $gap = "No major default user permission baseline gap was detected."
        }
        elseif ($status -eq "PARTIAL") {
            $summary = "Default user permissions are mostly controlled, but some self-service settings need review. $permissionOverview."
            $gap = "Default user permission posture is partially aligned because some settings require restriction or justification."
        }
        else {
            $summary = "Default user permissions are too permissive. $permissionOverview."
            $gap = "Default user permission posture is not aligned with least privilege."
        }

        $resultArgs = @{
            ScenarioId      = "B2"
            ScenarioName    = "Default User Permissions and App Registration Review"
            Category        = "Baseline Security"
            Status          = $status
            Risk            = $risk
            Findings        = $findings
            Recommendations = $recommendations
            Evidence        = [PSCustomObject]@{
                executive_summary = $summary
                permission_overview = $permissionOverview
                authorization_policy_readable = $true
                users_can_register_applications = $allowedToCreateApps
                users_can_create_security_groups = $allowedToCreateSecurityGroups
                users_can_create_tenants = $allowedToCreateTenants
                users_can_read_other_users = $allowedToReadOtherUsers
                guest_invite_setting = $allowInvitesFrom
                guest_invite_meaning = $inviteMeaning
                email_verified_users_can_join_organization = $allowEmailVerifiedUsersToJoinOrganization
                email_based_subscription_signup_allowed = $allowedToSignUpEmailBasedSubscriptions
                users_can_use_sspr = $allowedToUseSSPR
                permission_grant_policies_assigned_count = $permissionGrantPoliciesAssigned.Count
                high_risk_default_permission_count = $highRiskItems.Count
                medium_risk_default_permission_count = $mediumRiskItems.Count
                controlled_default_permission_count = $controlledItems.Count
                informational_setting_count = $infoItems.Count
                settings = $settings
                high_risk_settings = $highRiskItems
                medium_risk_settings = $mediumRiskItems
                controlled_settings = $controlledItems
                informational_settings = $infoItems
            }
            CurrentState    = $currentState
            ZeroTrustTarget = $zeroTrustTarget
            GapSummary      = $gap
        }

        return New-ZTVPResult @resultArgs
    }
    catch {
        $resultArgs = @{
            ScenarioId      = "B2"
            ScenarioName    = "Default User Permissions and App Registration Review"
            Category        = "Baseline Security"
            Status          = "ERROR"
            Risk            = "CRITICAL"
            Findings        = @(New-ZTVPFinding -Title "Execution error" -Detail $_.Exception.Message)
            Recommendations = @(New-ZTVPRecommendation -Title "Fix B2 execution issue" -Detail "Review Microsoft Graph permissions for authorization policy evidence.")
            Evidence        = $null
            CurrentState    = "B2 could not complete default user permission assessment."
            ZeroTrustTarget = "Default user permissions should follow least privilege."
            GapSummary      = "B2 could not be evaluated because execution failed."
        }

        return New-ZTVPResult @resultArgs
    }
}
