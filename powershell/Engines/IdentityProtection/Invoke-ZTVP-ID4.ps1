Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Identity.SignIns -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Groups -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Users -Force -ErrorAction SilentlyContinue

function ConvertTo-ID4StringArray {
    param($Value)

    $items = @()

    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $items += $item.ToString()
        }
    }

    return $items
}

function ConvertTo-ID4LowerArray {
    param($Value)

    $items = @()

    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $items += $item.ToString().ToLowerInvariant()
        }
    }

    return $items
}

function Test-ID4EmergencyName {
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
        $v -match "break glass" -or
        $v -match "recovery" -or
        $v -match "glass"
    )
}

function Test-ID4BroadName {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    $v = $Value.ToLowerInvariant()

    return (
        $v -match "all users" -or
        $v -match "everyone" -or
        $v -match "all employees" -or
        $v -match "all staff" -or
        $v -match "all members" -or
        $v -match "all admins" -or
        $v -match "all privileged" -or
        $v -match "domain users"
    )
}

function Get-ID4StateLabel {
    param([string]$State)

    switch ($State) {
        "enabled" { return "Enabled" }
        "enabledForReportingButNotEnforced" { return "Report-only" }
        "disabled" { return "Disabled" }
        default { return $State }
    }
}

function Add-ID4KnownEmergencyValue {
    param(
        [hashtable]$Set,
        $Value
    )

    if ($null -eq $Value) {
        return
    }

    $text = $Value.ToString().Trim()

    if ([string]::IsNullOrWhiteSpace($text)) {
        return
    }

    $key = $text.ToLowerInvariant()

    if (-not $Set.ContainsKey($key)) {
        $Set[$key] = $true
    }
}

function Get-ID4A4EmergencyContext {
    $known = @{}
    $path = Join-Path (Get-Location) "powershell\Reports\A4-result.json"

    if (-not (Test-Path $path)) {
        return [PSCustomObject]@{
            available = $false
            source    = $path
            known     = $known
            count     = 0
        }
    }

    try {
        $json = Get-Content -Path $path -Raw | ConvertFrom-Json
    }
    catch {
        return [PSCustomObject]@{
            available = $false
            source    = $path
            known     = $known
            count     = 0
        }
    }

    function Walk-A4Object {
        param(
            $Object,
            [string]$Path,
            [bool]$EmergencyContext
        )

        if ($null -eq $Object) {
            return
        }

        if ($Object -is [string]) {
            if ($EmergencyContext -or (Test-ID4EmergencyName -Value $Object)) {
                Add-ID4KnownEmergencyValue -Set $known -Value $Object
            }
            return
        }

        if ($Object -is [System.ValueType]) {
            return
        }

        if ($Object -is [System.Collections.IEnumerable] -and -not ($Object -is [string])) {
            foreach ($item in $Object) {
                Walk-A4Object -Object $item -Path $Path -EmergencyContext $EmergencyContext
            }
            return
        }

        foreach ($prop in $Object.PSObject.Properties) {
            $propName = $prop.Name
            $nextPath = "$Path.$propName"
            $isEmergencyPath = [bool](
                $EmergencyContext -or
                (Test-ID4EmergencyName -Value $propName) -or
                $propName.ToLowerInvariant() -match "break|glass|recovery"
            )

            if ($null -ne $prop.Value -and $prop.Value -is [string]) {
                if ($isEmergencyPath -or (Test-ID4EmergencyName -Value $prop.Value)) {
                    Add-ID4KnownEmergencyValue -Set $known -Value $prop.Value
                }
            }
            else {
                Walk-A4Object -Object $prop.Value -Path $nextPath -EmergencyContext $isEmergencyPath
            }
        }
    }

    Walk-A4Object -Object $json -Path "A4" -EmergencyContext $false

    return [PSCustomObject]@{
        available = $true
        source    = $path
        known     = $known
        count     = $known.Count
    }
}

function Test-ID4KnownEmergencyValue {
    param(
        [hashtable]$Known,
        $Value
    )

    if ($null -eq $Known -or $null -eq $Value) {
        return $false
    }

    $text = $Value.ToString().Trim()

    if ([string]::IsNullOrWhiteSpace($text)) {
        return $false
    }

    return $Known.ContainsKey($text.ToLowerInvariant())
}

function Get-ID4DirectoryObjectText {
    param($Object)

    $values = @()

    if ($null -eq $Object) {
        return $values
    }

    foreach ($field in @("Id", "DisplayName", "UserPrincipalName", "Mail")) {
        if ($Object.PSObject.Properties[$field] -and -not [string]::IsNullOrWhiteSpace($Object.$field)) {
            $values += $Object.$field.ToString()
        }
    }

    if ($Object.AdditionalProperties) {
        foreach ($key in @("id", "displayName", "userPrincipalName", "mail")) {
            if ($Object.AdditionalProperties.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace($Object.AdditionalProperties[$key])) {
                $values += $Object.AdditionalProperties[$key].ToString()
            }
        }
    }

    return @($values | Select-Object -Unique)
}

function Test-ID4ObjectMatchesEmergency {
    param(
        [hashtable]$Known,
        $Object,
        [string]$FallbackName
    )

    foreach ($v in @(Get-ID4DirectoryObjectText -Object $Object)) {
        if (Test-ID4KnownEmergencyValue -Known $Known -Value $v) {
            return $true
        }

        if (Test-ID4EmergencyName -Value $v) {
            return $true
        }
    }

    if (Test-ID4KnownEmergencyValue -Known $Known -Value $FallbackName) {
        return $true
    }

    if (Test-ID4EmergencyName -Value $FallbackName) {
        return $true
    }

    return $false
}

function Resolve-ID4GroupMembers {
    param(
        [string]$GroupId,
        [hashtable]$KnownEmergency
    )

    $members = @()
    $memberCount = 0
    $emergencyMemberCount = 0
    $normalMemberCount = 0
    $unknownMemberCount = 0

    try {
        $rawMembers = @(Get-MgGroupMember -GroupId $GroupId -All -ErrorAction Stop)
    }
    catch {
        return [PSCustomObject]@{
            resolved                = $false
            member_count            = 0
            emergency_member_count  = 0
            normal_member_count     = 0
            unknown_member_count    = 0
            members                 = @()
            reason                  = "Could not read group members. $($_.Exception.Message)"
        }
    }

    foreach ($member in $rawMembers) {
        $memberCount++

        $memberId = ""
        $displayName = ""
        $upn = ""
        $odataType = ""

        if ($member.Id) {
            $memberId = $member.Id
        }

        if ($member.AdditionalProperties) {
            if ($member.AdditionalProperties.ContainsKey("displayName")) {
                $displayName = $member.AdditionalProperties["displayName"]
            }

            if ($member.AdditionalProperties.ContainsKey("userPrincipalName")) {
                $upn = $member.AdditionalProperties["userPrincipalName"]
            }

            if ($member.AdditionalProperties.ContainsKey("@odata.type")) {
                $odataType = $member.AdditionalProperties["@odata.type"]
            }
        }

        $memberName = $upn
        if ([string]::IsNullOrWhiteSpace($memberName)) {
            $memberName = $displayName
        }

        if ([string]::IsNullOrWhiteSpace($memberName)) {
            $memberName = $memberId
        }

        $isEmergency = [bool](
            (Test-ID4KnownEmergencyValue -Known $KnownEmergency -Value $memberId) -or
            (Test-ID4KnownEmergencyValue -Known $KnownEmergency -Value $upn) -or
            (Test-ID4KnownEmergencyValue -Known $KnownEmergency -Value $displayName) -or
            (Test-ID4EmergencyName -Value $upn) -or
            (Test-ID4EmergencyName -Value $displayName)
        )

        $classification = "Normal"

        if ($isEmergency) {
            $classification = "Emergency"
            $emergencyMemberCount++
        }
        elseif ([string]::IsNullOrWhiteSpace($memberName)) {
            $classification = "Unknown"
            $unknownMemberCount++
        }
        else {
            $normalMemberCount++
        }

        $members += [PSCustomObject]@{
            id             = $memberId
            name           = $memberName
            display_name   = $displayName
            upn            = $upn
            type           = $odataType
            classification = $classification
        }
    }

    return [PSCustomObject]@{
        resolved                = $true
        member_count            = $memberCount
        emergency_member_count  = $emergencyMemberCount
        normal_member_count     = $normalMemberCount
        unknown_member_count    = $unknownMemberCount
        members                 = $members
        reason                  = "Group members read successfully."
    }
}

function Resolve-ID4ExcludedObject {
    param(
        [string]$Id,
        [string]$ObjectType,
        [hashtable]$KnownEmergency
    )

    $name = $Id
    $resolved = $false
    $classification = "Unknown"
    $confidence = "Low"
    $reason = "Object could not be resolved."
    $memberSummary = $null

    if ([string]::IsNullOrWhiteSpace($Id)) {
        return [PSCustomObject]@{
            object_id               = $Id
            object_type             = $ObjectType
            object_name             = ""
            resolved                = $false
            classification          = "Unknown"
            confidence              = "Low"
            reason                  = "Empty exclusion identifier."
            member_count            = 0
            emergency_member_count  = 0
            normal_member_count     = 0
            unknown_member_count    = 0
        }
    }

    if ($Id -eq "All") {
        return [PSCustomObject]@{
            object_id               = $Id
            object_type             = $ObjectType
            object_name             = "All"
            resolved                = $true
            classification          = "Broad"
            confidence              = "High"
            reason                  = "All users/groups style exclusion."
            member_count            = 0
            emergency_member_count  = 0
            normal_member_count     = 0
            unknown_member_count    = 0
        }
    }

    if ($Id -eq "GuestsOrExternalUsers") {
        return [PSCustomObject]@{
            object_id               = $Id
            object_type             = $ObjectType
            object_name             = "Guests or external users"
            resolved                = $true
            classification          = "Normal"
            confidence              = "Medium"
            reason                  = "Guest/external user exclusion requires review."
            member_count            = 0
            emergency_member_count  = 0
            normal_member_count     = 0
            unknown_member_count    = 0
        }
    }

    if ($ObjectType -eq "User") {
        try {
            $user = Get-MgUser -UserId $Id -Property "id,displayName,userPrincipalName,mail" -ErrorAction Stop
            $resolved = $true

            if (-not [string]::IsNullOrWhiteSpace($user.UserPrincipalName)) {
                $name = $user.UserPrincipalName
            }
            elseif (-not [string]::IsNullOrWhiteSpace($user.DisplayName)) {
                $name = $user.DisplayName
            }

            if (
                (Test-ID4KnownEmergencyValue -Known $KnownEmergency -Value $user.Id) -or
                (Test-ID4KnownEmergencyValue -Known $KnownEmergency -Value $user.UserPrincipalName) -or
                (Test-ID4KnownEmergencyValue -Known $KnownEmergency -Value $user.DisplayName)
            ) {
                $classification = "Emergency"
                $confidence = "High"
                $reason = "Direct excluded user matches A4 emergency evidence."
            }
            elseif (Test-ID4EmergencyName -Value $name) {
                $classification = "Emergency"
                $confidence = "Medium"
                $reason = "Direct excluded user matches emergency naming pattern. Validate in A4."
            }
            else {
                $classification = "Normal"
                $confidence = "High"
                $reason = "Direct excluded user is not identified as emergency."
            }
        }
        catch {
            $reason = "Could not resolve user. $($_.Exception.Message)"
        }
    }
    elseif ($ObjectType -eq "Group") {
        try {
            $group = Get-MgGroup -GroupId $Id -Property "id,displayName,mail,securityEnabled" -ErrorAction Stop
            $resolved = $true
            $name = $group.DisplayName

            $memberSummary = Resolve-ID4GroupMembers -GroupId $Id -KnownEmergency $KnownEmergency

            if (
                (Test-ID4KnownEmergencyValue -Known $KnownEmergency -Value $group.Id) -or
                (Test-ID4KnownEmergencyValue -Known $KnownEmergency -Value $group.DisplayName)
            ) {
                $classification = "Emergency"
                $confidence = "High"
                $reason = "Excluded group matches A4 emergency evidence."
            }
            elseif ($memberSummary.resolved -eq $true -and $memberSummary.member_count -gt 0 -and $memberSummary.normal_member_count -eq 0 -and $memberSummary.unknown_member_count -eq 0 -and $memberSummary.emergency_member_count -gt 0) {
                $classification = "Emergency"
                $confidence = "High"
                $reason = "All resolved group members are emergency/break-glass accounts."
            }
            elseif (Test-ID4BroadName -Value $name) {
                $classification = "Broad"
                $confidence = "High"
                $reason = "Group name suggests a broad population."
            }
            elseif ($memberSummary.resolved -eq $true -and $memberSummary.normal_member_count -gt 0) {
                $classification = "Normal"
                $confidence = "High"
                $reason = "Group contains non-emergency members."
            }
            elseif ($memberSummary.resolved -eq $true -and $memberSummary.unknown_member_count -gt 0) {
                $classification = "Unknown"
                $confidence = "Low"
                $reason = "Group contains unresolved members."
            }
            elseif (Test-ID4EmergencyName -Value $name) {
                $classification = "Emergency"
                $confidence = "Medium"
                $reason = "Group name matches emergency/break-glass pattern. Validate against A4."
            }
            else {
                $classification = "Normal"
                $confidence = "Medium"
                $reason = "Group is not identified as emergency."
            }
        }
        catch {
            $reason = "Could not resolve group. $($_.Exception.Message)"
        }
    }
    elseif ($ObjectType -eq "Role") {
        $resolved = $true
        $name = $Id
        $classification = "Role"
        $confidence = "High"
        $reason = "Directory role exclusion should be strongly justified."
    }

    $memberCount = 0
    $emergencyMemberCount = 0
    $normalMemberCount = 0
    $unknownMemberCount = 0

    if ($null -ne $memberSummary) {
        $memberCount = $memberSummary.member_count
        $emergencyMemberCount = $memberSummary.emergency_member_count
        $normalMemberCount = $memberSummary.normal_member_count
        $unknownMemberCount = $memberSummary.unknown_member_count
    }

    return [PSCustomObject]@{
        object_id               = $Id
        object_type             = $ObjectType
        object_name             = $name
        resolved                = $resolved
        classification          = $classification
        confidence              = $confidence
        reason                  = $reason
        member_count            = $memberCount
        emergency_member_count  = $emergencyMemberCount
        normal_member_count     = $normalMemberCount
        unknown_member_count    = $unknownMemberCount
    }
}

function Get-ID4RiskPolicyEvidence {
    param(
        $Policy,
        [hashtable]$KnownEmergency
    )

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
        $userRiskLevels = @(ConvertTo-ID4LowerArray $Policy.Conditions.UserRiskLevels)
        $signInRiskLevels = @(ConvertTo-ID4LowerArray $Policy.Conditions.SignInRiskLevels)
    }

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
        $excludeUsers  = @(ConvertTo-ID4StringArray $Policy.Conditions.Users.ExcludeUsers)
        $excludeGroups = @(ConvertTo-ID4StringArray $Policy.Conditions.Users.ExcludeGroups)
        $excludeRoles  = @(ConvertTo-ID4StringArray $Policy.Conditions.Users.ExcludeRoles)
    }

    $exclusions = @()

    foreach ($id in $excludeUsers) {
        $exclusions += Resolve-ID4ExcludedObject -Id $id -ObjectType "User" -KnownEmergency $KnownEmergency
    }

    foreach ($id in $excludeGroups) {
        $exclusions += Resolve-ID4ExcludedObject -Id $id -ObjectType "Group" -KnownEmergency $KnownEmergency
    }

    foreach ($id in $excludeRoles) {
        $exclusions += Resolve-ID4ExcludedObject -Id $id -ObjectType "Role" -KnownEmergency $KnownEmergency
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

    return [PSCustomObject]@{
        policy_id             = $Policy.Id
        policy_name           = $name
        state                 = $state
        state_label           = Get-ID4StateLabel -State $state
        enabled               = ($state -eq "enabled")
        report_only           = ($state -eq "enabledForReportingButNotEnforced")
        disabled              = ($state -eq "disabled")
        risk_policy           = [bool]($isUserRisk -or $isSignInRisk)
        user_risk_policy      = $isUserRisk
        sign_in_risk_policy   = $isSignInRisk
        risk_type             = ($riskType -join " + ")
        user_risk_levels      = $userRiskLevels
        sign_in_risk_levels   = $signInRiskLevels
        has_exclusions        = [bool]($exclusions.Count -gt 0)
        exclude_users_count   = $excludeUsers.Count
        exclude_groups_count  = $excludeGroups.Count
        exclude_roles_count   = $excludeRoles.Count
        exclusions            = $exclusions
        excluded_object_names = @($exclusions | ForEach-Object { "$($_.object_name) [$($_.object_type)/$($_.classification)/$($_.confidence)]" })
    }
}

function Invoke-ZTVP-ID4 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== ID4 - Identity Protection Exclusion Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        $a4Context = Get-ID4A4EmergencyContext

        try {
            $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        }
        catch {
            return New-ZTVPResult `
                -ScenarioId "ID4" `
                -ScenarioName "Identity Protection Exclusion Review" `
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
                -ZeroTrustTarget "Risk-based Conditional Access exclusions should be minimal, documented, and reviewed." `
                -GapSummary "ID4 could not be evaluated because Conditional Access evidence was unavailable."
        }

        $policyEvidence = @()

        foreach ($policy in $policies) {
            $policyEvidence += Get-ID4RiskPolicyEvidence -Policy $policy -KnownEmergency $a4Context.known
        }

        $riskPolicies = @($policyEvidence | Where-Object { $_.risk_policy -eq $true })
        $riskPoliciesWithExclusions = @($riskPolicies | Where-Object { $_.has_exclusions -eq $true })
        $enabledRiskPoliciesWithExclusions = @($riskPoliciesWithExclusions | Where-Object { $_.enabled -eq $true })
        $reportOnlyRiskPoliciesWithExclusions = @($riskPoliciesWithExclusions | Where-Object { $_.report_only -eq $true })

        $exclusionInventory = @()

        foreach ($policy in $riskPoliciesWithExclusions) {
            foreach ($exclusion in @($policy.exclusions)) {
                $exclusionInventory += [PSCustomObject]@{
                    policy_name             = $policy.policy_name
                    policy_state            = $policy.state_label
                    risk_type               = $policy.risk_type
                    object_type             = $exclusion.object_type
                    object_name             = $exclusion.object_name
                    object_id               = $exclusion.object_id
                    classification          = $exclusion.classification
                    confidence              = $exclusion.confidence
                    reason                  = $exclusion.reason
                    member_count            = $exclusion.member_count
                    emergency_member_count  = $exclusion.emergency_member_count
                    normal_member_count     = $exclusion.normal_member_count
                    unknown_member_count    = $exclusion.unknown_member_count
                }
            }
        }

        $enabledExclusions = @($exclusionInventory | Where-Object { $_.policy_state -eq "Enabled" })

        $emergencyExclusions = @($enabledExclusions | Where-Object { $_.classification -eq "Emergency" })
        $normalExclusions = @($enabledExclusions | Where-Object { $_.classification -eq "Normal" })
        $broadExclusions = @($enabledExclusions | Where-Object { $_.classification -eq "Broad" })
        $roleExclusions = @($enabledExclusions | Where-Object { $_.classification -eq "Role" })
        $unknownExclusions = @($enabledExclusions | Where-Object { $_.classification -eq "Unknown" })
        $mediumConfidenceEmergencyExclusions = @($emergencyExclusions | Where-Object { $_.confidence -ne "High" })

        if ($broadExclusions.Count -gt 0 -or $roleExclusions.Count -gt 0) {
            $badItems = @($broadExclusions + $roleExclusions)

            $findings += New-ZTVPFinding `
                -Title "High-risk risk-policy exclusions detected" `
                -Detail ("Broad or role-based exclusions can weaken Identity Protection enforcement. Exclusions: " + (($badItems | Select-Object -First 20 | ForEach-Object { "$($_.policy_name): $($_.object_name) [$($_.classification)]" }) -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Remove or strictly justify high-risk exclusions" `
                -Detail "Remove broad or role-based exclusions from risk policies unless there is a documented and approved exception."
        }

        if ($normalExclusions.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Enabled risk policies contain normal exclusions" `
                -Detail ("Normal exclusions may weaken Identity Protection enforcement. Exclusions: " + (($normalExclusions | Select-Object -First 20 | ForEach-Object { "$($_.policy_name): $($_.object_name)" }) -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Remove or justify normal risk-policy exclusions" `
                -Detail "Normal users or normal groups should not be excluded from user-risk or sign-in-risk enforcement unless formally documented and approved."
        }

        if ($unknownExclusions.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Enabled risk policies contain unresolved exclusions" `
                -Detail ("Some exclusions could not be resolved and require manual review. Exclusions: " + (($unknownExclusions | Select-Object -First 20 | ForEach-Object { "$($_.policy_name): $($_.object_id)" }) -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Resolve unknown risk-policy exclusions" `
                -Detail "Confirm unresolved excluded objects are not normal users, broad groups, or privileged roles."
        }

        if (
            $emergencyExclusions.Count -gt 0 -and
            $normalExclusions.Count -eq 0 -and
            $broadExclusions.Count -eq 0 -and
            $roleExclusions.Count -eq 0 -and
            $unknownExclusions.Count -eq 0
        ) {
            $findings += New-ZTVPFinding `
                -Title "Only emergency risk-policy exclusions detected" `
                -Detail ("Enabled risk policies exclude only emergency or break-glass objects. Exclusions: " + (($emergencyExclusions | ForEach-Object { "$($_.policy_name): $($_.object_name) [$($_.confidence)]" }) -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Validate emergency exclusions" `
                -Detail "Confirm emergency exclusions are limited, monitored, tested, documented, and not used for daily administration. Cross-check with A4."
        }

        if ($mediumConfidenceEmergencyExclusions.Count -gt 0) {
            $recommendations += New-ZTVPRecommendation `
                -Title "Improve emergency exclusion evidence" `
                -Detail "Some emergency classifications were based on naming fallback rather than strong A4 or membership evidence. Run or review A4 to improve confidence."
        }

        if ($riskPoliciesWithExclusions.Count -eq 0) {
            $recommendations += New-ZTVPRecommendation `
                -Title "Maintain minimal risk-policy exclusions" `
                -Detail "No risk-policy exclusions were detected. Continue avoiding unnecessary exclusions."
        }

        if ($reportOnlyRiskPoliciesWithExclusions.Count -gt 0) {
            $recommendations += New-ZTVPRecommendation `
                -Title "Review report-only exclusions before enforcement" `
                -Detail "Report-only risk policies with exclusions should be reviewed before they are enabled."
        }

        $status = "PASS"
        $risk = "LOW"

        if ($broadExclusions.Count -gt 0 -or $roleExclusions.Count -gt 0) {
            $status = "FAIL"
            $risk = "HIGH"
        }
        elseif ($normalExclusions.Count -gt 0 -or $unknownExclusions.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }
        elseif ($mediumConfidenceEmergencyExclusions.Count -gt 0) {
            $status = "PASS"
            $risk = "MEDIUM"
        }
        else {
            $status = "PASS"
            $risk = "LOW"
        }

        $currentState = @(
            "Risk-based policies assessed: $($riskPolicies.Count)."
            "Risk policies with exclusions: $($riskPoliciesWithExclusions.Count)."
            "Enabled risk policies with exclusions: $($enabledRiskPoliciesWithExclusions.Count)."
            "Report-only risk policies with exclusions: $($reportOnlyRiskPoliciesWithExclusions.Count)."
            "Enabled emergency exclusions: $($emergencyExclusions.Count)."
            "Enabled normal exclusions: $($normalExclusions.Count)."
            "Enabled broad exclusions: $($broadExclusions.Count)."
            "Enabled role exclusions: $($roleExclusions.Count)."
            "Enabled unknown exclusions: $($unknownExclusions.Count)."
            "A4 evidence available: $($a4Context.available)."
            "A4 emergency evidence values loaded: $($a4Context.count)."
        ) -join " "

        $zeroTrustTarget = "Identity Protection risk-policy exclusions should be minimal, documented, justified, monitored, and reviewed. Emergency exclusions may be acceptable only when validated through A4 or group membership evidence."

        if ($status -eq "PASS") {
            if ($emergencyExclusions.Count -gt 0) {
                $summary = "Risk-policy exclusions are limited to emergency or break-glass objects. Validate them in A4, but no non-emergency exclusion gap was detected."
                $gap = "No non-emergency Identity Protection exclusion gap was detected."
            }
            else {
                $summary = "No enabled risk-policy exclusions requiring action were detected."
                $gap = "No Identity Protection exclusion gap was detected."
            }
        }
        elseif ($status -eq "PARTIAL") {
            $summary = "Risk-policy exclusions require review. Normal or unresolved exclusions were detected."
            $gap = "Identity Protection exclusion posture is partially aligned because normal or unresolved exclusions require validation."
        }
        else {
            $summary = "High-risk risk-policy exclusions detected. Broad or role-based exclusions may weaken Identity Protection enforcement."
            $gap = "Identity Protection exclusion posture is not aligned because broad or role exclusions were detected."
        }

        return New-ZTVPResult `
            -ScenarioId "ID4" `
            -ScenarioName "Identity Protection Exclusion Review" `
            -Category "Identity Protection" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary = $summary

                a4_evidence_available = $a4Context.available
                a4_evidence_source = $a4Context.source
                a4_emergency_value_count = $a4Context.count

                risk_policy_count = $riskPolicies.Count
                risk_policy_with_exclusion_count = $riskPoliciesWithExclusions.Count
                enabled_risk_policy_with_exclusion_count = $enabledRiskPoliciesWithExclusions.Count
                report_only_risk_policy_with_exclusion_count = $reportOnlyRiskPoliciesWithExclusions.Count

                enabled_emergency_exclusion_count = $emergencyExclusions.Count
                enabled_normal_exclusion_count = $normalExclusions.Count
                enabled_broad_exclusion_count = $broadExclusions.Count
                enabled_role_exclusion_count = $roleExclusions.Count
                enabled_unknown_exclusion_count = $unknownExclusions.Count
                medium_confidence_emergency_exclusion_count = $mediumConfidenceEmergencyExclusions.Count

                risk_policies = $riskPolicies
                risk_policies_with_exclusions = $riskPoliciesWithExclusions
                exclusion_inventory = $exclusionInventory
                emergency_exclusions = $emergencyExclusions
                normal_exclusions = $normalExclusions
                broad_exclusions = $broadExclusions
                role_exclusions = $roleExclusions
                unknown_exclusions = $unknownExclusions
                medium_confidence_emergency_exclusions = $mediumConfidenceEmergencyExclusions
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gap
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "ID4" `
            -ScenarioName "Identity Protection Exclusion Review" `
            -Category "Identity Protection" `
            -Status "ERROR" `
            -Risk "CRITICAL" `
            -Findings @(
                New-ZTVPFinding -Title "Execution error" -Detail $_.Exception.Message
            ) `
            -Recommendations @(
                New-ZTVPRecommendation -Title "Fix ID4 execution issue" -Detail "Review Graph permissions and Conditional Access visibility."
            ) `
            -Evidence $null `
            -CurrentState "ID4 could not complete Identity Protection exclusion assessment." `
            -ZeroTrustTarget "Identity Protection risk-policy exclusions should be minimal, documented, justified, monitored, and reviewed." `
            -GapSummary "ID4 could not be evaluated because execution failed."
    }
}
