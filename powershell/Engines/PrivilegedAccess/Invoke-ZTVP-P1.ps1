Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Identity.DirectoryManagement -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Identity.Governance -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Users -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Groups -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Applications -Force -ErrorAction SilentlyContinue

function Get-ZTVPP1Property {
    param($Object, [string[]]$Names)

    if ($null -eq $Object) { return $null }

    foreach ($name in $Names) {
        if ($Object.PSObject.Properties[$name]) {
            return $Object.$name
        }

        if ($Object.AdditionalProperties -and $Object.AdditionalProperties.ContainsKey($name)) {
            return $Object.AdditionalProperties[$name]
        }
    }

    return $null
}

function Test-ZTVPP1EmergencyName {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }

    $v = $Value.ToLowerInvariant()

    return (
        $v -match "emergency" -or
        $v -match "breakglass" -or
        $v -match "break-glass" -or
        $v -match "break_glass" -or
        $v -match "recovery"
    )
}

function Get-ZTVPP1RoleImpact {
    param([string]$RoleName)

    switch ($RoleName) {
        "Global Administrator" { "Critical"; break }
        "Privileged Role Administrator" { "Critical"; break }
        "Conditional Access Administrator" { "Critical"; break }
        "Authentication Policy Administrator" { "Critical"; break }
        "Security Administrator" { "High"; break }
        "Authentication Administrator" { "High"; break }
        "User Administrator" { "High"; break }
        "Exchange Administrator" { "High"; break }
        "SharePoint Administrator" { "High"; break }
        "Intune Administrator" { "High"; break }
        "Application Administrator" { "High"; break }
        "Cloud Application Administrator" { "High"; break }
        "Groups Administrator" { "High"; break }
        "Global Reader" { "Medium"; break }
        "Security Reader" { "Medium"; break }
        default { "Medium" }
    }
}

function Get-ZTVPP1RoleCategory {
    param([string]$RoleName)

    switch ($RoleName) {
        "Global Administrator" { "Tenant-wide administration"; break }
        "Privileged Role Administrator" { "Role management"; break }
        "Conditional Access Administrator" { "Access enforcement"; break }
        "Authentication Policy Administrator" { "Authentication policy"; break }
        "Security Administrator" { "Security administration"; break }
        "Authentication Administrator" { "Authentication administration"; break }
        "User Administrator" { "Identity administration"; break }
        "Exchange Administrator" { "Workload administration"; break }
        "SharePoint Administrator" { "Workload administration"; break }
        "Intune Administrator" { "Device administration"; break }
        "Application Administrator" { "Application administration"; break }
        "Cloud Application Administrator" { "Application administration"; break }
        "Groups Administrator" { "Group administration"; break }
        "Global Reader" { "Read-only privileged visibility"; break }
        "Security Reader" { "Read-only security visibility"; break }
        default { "Privileged access" }
    }
}

function Test-ZTVPP1PermanentAssignment {
    param($EndDateTime)

    if ($null -eq $EndDateTime) { return $true }

    try {
        $dt = [datetime]$EndDateTime
        return ($dt.Year -ge 9999)
    }
    catch {
        return $false
    }
}




function Resolve-ZTVPP1Principal {
    param(
        [string]$PrincipalId,
        $ExpandedPrincipal
    )

    $displayName = $null
    $upn = $null
    $mail = $null
    $enabled = $null
    $type = "Unknown"

    if ($null -ne $ExpandedPrincipal) {
        $odata = Get-ZTVPP1Property -Object $ExpandedPrincipal -Names @("@odata.type", "ODataType")

        if ($odata -match "user") { $type = "User" }
        elseif ($odata -match "servicePrincipal") { $type = "ServicePrincipal" }
        elseif ($odata -match "group") { $type = "Group" }

        $displayName = Get-ZTVPP1Property -Object $ExpandedPrincipal -Names @("DisplayName", "displayName")
        $upn = Get-ZTVPP1Property -Object $ExpandedPrincipal -Names @("UserPrincipalName", "userPrincipalName")
        $mail = Get-ZTVPP1Property -Object $ExpandedPrincipal -Names @("Mail", "mail")
        $enabled = Get-ZTVPP1Property -Object $ExpandedPrincipal -Names @("AccountEnabled", "accountEnabled")
    }

    # Enrich whenever accountEnabled or identity fields are missing.
    # This avoids showing Enabled = No only because expanded Graph data was incomplete.
    if (-not [string]::IsNullOrWhiteSpace($PrincipalId)) {
        if ($type -eq "User" -or $type -eq "Unknown" -or [string]::IsNullOrWhiteSpace($upn) -or $null -eq $enabled) {
            try {
                $u = Get-MgUser -UserId $PrincipalId -Property "id,displayName,userPrincipalName,mail,accountEnabled" -ErrorAction Stop

                if ($u) {
                    $type = "User"
                    $displayName = $u.DisplayName
                    $upn = $u.UserPrincipalName
                    $mail = $u.Mail
                    $enabled = $u.AccountEnabled
                }
            }
            catch {
                # Not a user or cannot read user. Try service principal/group below.
            }
        }

        if (($type -eq "ServicePrincipal" -or $type -eq "Unknown") -and ($null -eq $enabled -or [string]::IsNullOrWhiteSpace($displayName))) {
            try {
                $sp = Get-MgServicePrincipal -ServicePrincipalId $PrincipalId -Property "id,displayName,appId,accountEnabled" -ErrorAction Stop

                if ($sp) {
                    $type = "ServicePrincipal"
                    $displayName = $sp.DisplayName
                    $mail = $sp.AppId
                    $enabled = $sp.AccountEnabled
                }
            }
            catch {
                # Not a service principal or cannot read.
            }
        }

        if (($type -eq "Group" -or $type -eq "Unknown") -and [string]::IsNullOrWhiteSpace($displayName)) {
            try {
                $g = Get-MgGroup -GroupId $PrincipalId -Property "id,displayName,mail" -ErrorAction Stop

                if ($g) {
                    $type = "Group"
                    $displayName = $g.DisplayName
                    $mail = $g.Mail
                }
            }
            catch {
                # Best-effort only.
            }
        }
    }

    $label = $upn
    if ([string]::IsNullOrWhiteSpace($label)) { $label = $displayName }
    if ([string]::IsNullOrWhiteSpace($label)) { $label = $PrincipalId }

    $isEmergency = [bool](
        (Test-ZTVPP1EmergencyName $label) -or
        (Test-ZTVPP1EmergencyName $displayName) -or
        (Test-ZTVPP1EmergencyName $mail)
    )

    [PSCustomObject]@{
        principalId       = $PrincipalId
        principalLabel    = $label
        displayName       = $displayName
        userPrincipalName = $upn
        mail              = $mail
        accountEnabled    = $enabled
        principalType     = $type
        emergency         = $isEmergency
    }
}

function New-ZTVPP1Assignment {
    param(
        $Instance,
        [string]$Kind,
        $RoleMap
    )

    $roleName = $null
    $roleDefinition = Get-ZTVPP1Property -Object $Instance -Names @("RoleDefinition", "roleDefinition")
    $roleDefinitionId = Get-ZTVPP1Property -Object $Instance -Names @("RoleDefinitionId", "roleDefinitionId")

    if ($roleDefinition) {
        $roleName = Get-ZTVPP1Property -Object $roleDefinition -Names @("DisplayName", "displayName")
    }

    if ([string]::IsNullOrWhiteSpace($roleName) -and $RoleMap.ContainsKey($roleDefinitionId)) {
        $roleName = $RoleMap[$roleDefinitionId]
    }

    if ([string]::IsNullOrWhiteSpace($roleName)) {
        $roleName = "Unknown role"
    }

    $principalId = Get-ZTVPP1Property -Object $Instance -Names @("PrincipalId", "principalId")
    $principalObject = Get-ZTVPP1Property -Object $Instance -Names @("Principal", "principal")
    $principal = Resolve-ZTVPP1Principal -PrincipalId $principalId -ExpandedPrincipal $principalObject

    $start = Get-ZTVPP1Property -Object $Instance -Names @("StartDateTime", "startDateTime")
    $end = Get-ZTVPP1Property -Object $Instance -Names @("EndDateTime", "endDateTime")
    $assignmentType = Get-ZTVPP1Property -Object $Instance -Names @("AssignmentType", "assignmentType")
    $memberType = Get-ZTVPP1Property -Object $Instance -Names @("MemberType", "memberType")

    $permanent = Test-ZTVPP1PermanentAssignment -EndDateTime $end

    $model = "Unknown"

    if ($Kind -eq "Eligible") {
        if ($permanent) { $model = "Permanent eligible" }
        else { $model = "Time-bound eligible" }
    }
    else {
        if ($assignmentType -match "Activated") { $model = "JIT active activation" }
        elseif ($permanent) { $model = "Permanent active" }
        else { $model = "Time-bound active" }
    }

    [PSCustomObject]@{
        roleName          = $roleName
        impact            = Get-ZTVPP1RoleImpact $roleName
        category          = Get-ZTVPP1RoleCategory $roleName

        principalId       = $principal.principalId
        principalLabel    = $principal.principalLabel
        principalType     = $principal.principalType
        accountEnabled    = $principal.accountEnabled
        emergency         = $principal.emergency

        assignmentKind    = $Kind
        assignmentModel   = $model
        permanent         = $permanent
        startDateTime     = $start
        endDateTime       = $end
        assignmentType    = $assignmentType
        memberType        = $memberType
    }
}

function Invoke-ZTVP-P1 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== P1 - Privileged Role Assignment and JIT Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        $monitoredRoles = @(
            "Global Administrator",
            "Privileged Role Administrator",
            "Conditional Access Administrator",
            "Authentication Policy Administrator",
            "Security Administrator",
            "Authentication Administrator",
            "User Administrator",
            "Exchange Administrator",
            "SharePoint Administrator",
            "Intune Administrator",
            "Application Administrator",
            "Cloud Application Administrator",
            "Groups Administrator",
            "Global Reader",
            "Security Reader"
        )

        $roleMap = @{}
        $roleDefinitionError = $null

        try {
            $roleDefinitions = @(Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop)
            foreach ($rd in $roleDefinitions) {
                if ($rd.Id -and $rd.DisplayName) {
                    $roleMap[$rd.Id] = $rd.DisplayName
                }
            }
        }
        catch {
            $roleDefinitionError = $_.Exception.Message
        }

        $active = @()
        $eligible = @()
        $activeError = $null
        $eligibleError = $null
        $fallbackUsed = $false
        $fallbackError = $null

        try {
            $activeInstances = @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty @("principal","roleDefinition") -ErrorAction Stop)

            foreach ($i in $activeInstances) {
                $a = New-ZTVPP1Assignment -Instance $i -Kind "Active" -RoleMap $roleMap
                if ($a.roleName -in $monitoredRoles) {
                    $active += $a
                }
            }
        }
        catch {
            $activeError = $_.Exception.Message
        }

        try {
            $eligibleInstances = @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty @("principal","roleDefinition") -ErrorAction Stop)

            foreach ($i in $eligibleInstances) {
                $e = New-ZTVPP1Assignment -Instance $i -Kind "Eligible" -RoleMap $roleMap
                if ($e.roleName -in $monitoredRoles) {
                    $eligible += $e
                }
            }
        }
        catch {
            $eligibleError = $_.Exception.Message
        }

        if ($active.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($activeError)) {
            try {
                $fallbackUsed = $true
                $directoryRoles = @(Get-MgDirectoryRole -All -ErrorAction Stop)
                $roles = @($directoryRoles | Where-Object { $_.DisplayName -in $monitoredRoles })

                foreach ($role in $roles) {
                    $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop)

                    foreach ($m in $members) {
                        $p = Resolve-ZTVPP1Principal -PrincipalId $m.Id -ExpandedPrincipal $m

                        $active += [PSCustomObject]@{
                            roleName          = $role.DisplayName
                            impact            = Get-ZTVPP1RoleImpact $role.DisplayName
                            category          = Get-ZTVPP1RoleCategory $role.DisplayName
                            principalId       = $p.principalId
                            principalLabel    = $p.principalLabel
                            principalType     = $p.principalType
                            accountEnabled    = $p.accountEnabled
                            emergency         = $p.emergency
                            assignmentKind    = "Active"
                            assignmentModel   = "Active directory role membership fallback"
                            permanent         = $true
                            startDateTime     = $null
                            endDateTime       = $null
                            assignmentType    = $null
                            memberType        = $null
                        }
                    }
                }
            }
            catch {
                $fallbackError = $_.Exception.Message
            }
        }

        $active = @($active | Sort-Object roleName, principalLabel)
        $eligible = @($eligible | Sort-Object roleName, principalLabel)

        $eligibleKeys = @{}
        foreach ($e in $eligible) {
            $eligibleKeys["$($e.principalId)|$($e.roleName)"] = $true
        }

        $activeWithoutEligibility = @()
        foreach ($a in $active) {
            if (-not $eligibleKeys.ContainsKey("$($a.principalId)|$($a.roleName)")) {
                $activeWithoutEligibility += $a
            }
        }

        $permanentActive = @($active | Where-Object { $_.permanent -eq $true })
        $timeBoundActive = @($active | Where-Object { $_.permanent -ne $true })
        $permanentCritical = @($permanentActive | Where-Object { $_.impact -eq "Critical" })
        $highImpactActive = @($active | Where-Object { $_.impact -in @("Critical","High") })
        $criticalActive = @($active | Where-Object { $_.impact -eq "Critical" })

        $principals = @()

        foreach ($g in ($active | Group-Object principalId)) {
            $items = @($g.Group)
            $first = $items[0]
            $roles = @($items | ForEach-Object { $_.roleName } | Sort-Object -Unique)
            $criticalRoles = @($items | Where-Object { $_.impact -eq "Critical" } | ForEach-Object { $_.roleName } | Sort-Object -Unique)
            $permanentRoles = @($items | Where-Object { $_.permanent -eq $true } | ForEach-Object { $_.roleName } | Sort-Object -Unique)
            $eligibleRoles = @($eligible | Where-Object { $_.principalId -eq $first.principalId } | ForEach-Object { $_.roleName } | Sort-Object -Unique)

            $principals += [PSCustomObject]@{
                principalId        = $first.principalId
                principalLabel     = $first.principalLabel
                principalType      = $first.principalType
                accountEnabled     = $first.accountEnabled
                emergency          = $first.emergency
                roles              = $roles
                roleCount          = $roles.Count
                criticalRoles      = $criticalRoles
                criticalRoleCount  = $criticalRoles.Count
                permanentRoles     = $permanentRoles
                permanentRoleCount = $permanentRoles.Count
                eligibleRoles      = $eligibleRoles
                eligibleRoleCount  = $eligibleRoles.Count
                globalAdmin        = [bool]($roles -contains "Global Administrator")
                privilegedRoleAdmin = [bool]($roles -contains "Privileged Role Administrator")
            }
        }

        $globalAdmins = @($principals | Where-Object { $_.globalAdmin -eq $true })
        $privilegedRoleAdmins = @($principals | Where-Object { $_.privilegedRoleAdmin -eq $true })
        $roleStacked = @($principals | Where-Object { $_.roleCount -gt 1 })
        $criticalRoleStacked = @($principals | Where-Object { $_.criticalRoleCount -gt 1 })
        $emergencyPrincipals = @($principals | Where-Object { $_.emergency -eq $true })
        $disabledPrivilegedUsers = @($principals | Where-Object { $_.principalType -eq "User" -and $_.accountEnabled -eq $false })
        $nonUserPrivileged = @($principals | Where-Object { $_.principalType -ne "User" })
        $nonUserCritical = @($active | Where-Object { $_.principalType -ne "User" -and $_.impact -eq "Critical" })

        $roleSummary = @()

        foreach ($r in $monitoredRoles) {
            $ra = @($active | Where-Object { $_.roleName -eq $r })
            $re = @($eligible | Where-Object { $_.roleName -eq $r })

            if ($ra.Count -gt 0 -or $re.Count -gt 0) {
                $roleSummary += [PSCustomObject]@{
                    roleName             = $r
                    impact               = Get-ZTVPP1RoleImpact $r
                    category             = Get-ZTVPP1RoleCategory $r
                    activeCount          = $ra.Count
                    permanentActiveCount = @($ra | Where-Object { $_.permanent -eq $true }).Count
                    timeBoundActiveCount = @($ra | Where-Object { $_.permanent -ne $true }).Count
                    eligibleCount        = $re.Count
                }
            }
        }

        $jitModel = "Not confirmed"

        if (-not [string]::IsNullOrWhiteSpace($eligibleError)) {
            $jitModel = "PIM eligibility evidence unavailable"
        }
        elseif ($eligible.Count -eq 0 -and $active.Count -gt 0) {
            $jitModel = "Standing active model detected"
        }
        elseif ($eligible.Count -gt 0 -and $permanentActive.Count -gt 0) {
            $jitModel = "Mixed model: eligible access exists, but permanent active access remains"
        }
        elseif ($eligible.Count -gt 0 -and $permanentActive.Count -eq 0) {
            $jitModel = "JIT / eligible-first model detected"
        }

        $unknownRoleCount = @($active + $eligible | Where-Object { $_.roleName -eq "Unknown role" }).Count

        if ($roleDefinitionError -and $unknownRoleCount -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Role definition evidence partially unavailable" `
                -Detail "Some role names could not be resolved because role definition collection failed. Error: $roleDefinitionError"

            $recommendations += New-ZTVPRecommendation `
                -Title "Review role definition permissions or connectivity" `
                -Detail "Confirm Graph connectivity and permissions allow reading role management directory role definitions."
        }

        if ($fallbackUsed) {
            $findings += New-ZTVPFinding -Title "PIM active schedule evidence unavailable; fallback used" -Detail "P1 used classic directory role membership as active assignment evidence. Original error: $activeError"
            $recommendations += New-ZTVPRecommendation -Title "Enable PIM active assignment evidence" -Detail "Grant RoleAssignmentSchedule.Read.Directory or RoleManagement.Read.Directory to collect PIM-aware active assignment schedule instances."
        }

        if ($eligibleError) {
            $findings += New-ZTVPFinding -Title "PIM/JIT eligibility evidence unavailable" -Detail $eligibleError
            $recommendations += New-ZTVPRecommendation -Title "Enable PIM eligibility evidence" -Detail "Grant RoleEligibilitySchedule.Read.Directory or RoleManagement.Read.Directory to collect eligible privileged role assignments."
        }
        elseif ($eligible.Count -eq 0 -and $active.Count -gt 0) {
            $findings += New-ZTVPFinding -Title "No PIM/JIT eligibility evidence detected" -Detail "Active privileged assignments exist, but no eligible privileged role assignments were found."
            $recommendations += New-ZTVPRecommendation -Title "Adopt eligible/time-bound privileged access" -Detail "Use Microsoft Entra PIM where available so privileged access is eligible, time-bound, approved, and activated only when needed."
        }

        if ($permanentCritical.Count -gt 0) {
            $sample = $permanentCritical | Select-Object -First 10 | ForEach-Object { "$($_.principalLabel) [$($_.roleName)]" }
            $findings += New-ZTVPFinding -Title "Critical admin roles are permanently active" -Detail ("These users or apps already have powerful roles all the time instead of activating them only when needed. Move normal admins to PIM eligible/time-bound access. Sample: " + ($sample -join " | "))
            $recommendations += New-ZTVPRecommendation -Title "Move normal admins to PIM eligible/time-bound access" -Detail "Do not leave normal admin users permanently active in critical roles. Make them eligible in PIM and require activation only when needed."
        }

        if ($activeWithoutEligibility.Count -gt 0 -and $eligible.Count -gt 0) {
            $sample = $activeWithoutEligibility | Select-Object -First 10 | ForEach-Object { "$($_.principalLabel) [$($_.roleName)]" }
            $findings += New-ZTVPFinding -Title "Privileged access is not activated through PIM/JIT" -Detail ("These active privileged roles do not have matching PIM eligible assignments, which means they appear to be standing access instead of just-in-time activation. Sample: " + ($sample -join " | "))
            $recommendations += New-ZTVPRecommendation -Title "Use PIM/JIT for privileged access" -Detail "Privileged access should be activated from PIM eligibility, time-limited, approved where required, and audited."
        }

        if ($globalAdmins.Count -eq 0) {
            $findings += New-ZTVPFinding -Title "No Global Administrator detected" -Detail "No Global Administrator was detected. This may indicate collection limitations or a recovery risk."
            $recommendations += New-ZTVPRecommendation -Title "Validate Global Administrator membership" -Detail "Confirm Global Administrator membership in Entra ID."
        }
        elseif ($globalAdmins.Count -eq 1) {
            $findings += New-ZTVPFinding -Title "Single Global Administrator detected" -Detail "Only one Global Administrator was detected. This may create recovery risk."
            $recommendations += New-ZTVPRecommendation -Title "Maintain controlled Global Administrator redundancy" -Detail "Maintain a small number of approved Global Administrators, including controlled emergency access."
        }
        elseif ($globalAdmins.Count -gt 5) {
            $findings += New-ZTVPFinding -Title "Too many Global Administrators" -Detail ("Global Administrator should be limited to a very small number of approved accounts. This tenant currently has too many: " + (($globalAdmins | ForEach-Object { $_.principalLabel }) -join ", "))
            $recommendations += New-ZTVPRecommendation -Title "Reduce Global Administrators" -Detail "Keep only a small number of approved Global Administrators. Use narrower roles such as Conditional Access Administrator, Security Administrator, User Administrator, or Exchange Administrator where possible."
        }

        if ($privilegedRoleAdmins.Count -gt 2) {
            $findings += New-ZTVPFinding -Title "Privileged Role Administrator exposure requires review" -Detail ("More than two Privileged Role Administrators were detected: " + (($privilegedRoleAdmins | ForEach-Object { $_.principalLabel }) -join ", "))
            $recommendations += New-ZTVPRecommendation -Title "Limit Privileged Role Administrator assignments" -Detail "Restrict Privileged Role Administrator because it can manage privileged role assignments."
        }

        if ($roleStacked.Count -gt 0) {
            $sample = $roleStacked | Select-Object -First 10 | ForEach-Object { "$($_.principalLabel) [$($_.roles -join ", ")]" }
            $findings += New-ZTVPFinding -Title "Role stacking detected" -Detail ("Some principals hold multiple privileged roles. Sample: " + ($sample -join " | "))
            $recommendations += New-ZTVPRecommendation -Title "Apply least privilege" -Detail "Review principals with multiple roles and keep only the roles required."
        }

        if ($criticalRoleStacked.Count -gt 0) {
            $sample = $criticalRoleStacked | Select-Object -First 10 | ForEach-Object { "$($_.principalLabel) [$($_.criticalRoles -join ", ")]" }
            $findings += New-ZTVPFinding -Title "Multiple critical roles assigned to same principal" -Detail ("Some principals hold more than one critical role. Sample: " + ($sample -join " | "))
            $recommendations += New-ZTVPRecommendation -Title "Separate critical duties" -Detail "Avoid assigning multiple critical tenant-wide roles to the same user unless justified."
        }

        if ($emergencyPrincipals.Count -gt 0) {
            $sample = $emergencyPrincipals | Select-Object -First 10 | ForEach-Object { "$($_.principalLabel) [$($_.roles -join ", ")]" }
            $findings += New-ZTVPFinding -Title "Break-glass accounts have Global Administrator" -Detail ("Break-glass accounts have Global Administrator. Accounts: " + ($sample -join " | "))
            $recommendations += New-ZTVPRecommendation -Title "Keep break-glass accounts controlled" -Detail "Emergency accounts can keep Global Administrator, but they must be limited, cloud-only, monitored, and tested in A4. They should not be used for daily administration."
        }

        if ($disabledPrivilegedUsers.Count -gt 0) {
            $findings += New-ZTVPFinding -Title "Disabled users hold privileged roles" -Detail ("Disabled users still hold roles: " + (($disabledPrivilegedUsers | ForEach-Object { $_.principalLabel }) -join ", "))
            $recommendations += New-ZTVPRecommendation -Title "Remove privileged roles from disabled users" -Detail "Remove role assignments from disabled users unless documented for recovery."
        }

        if ($nonUserPrivileged.Count -gt 0) {
            $findings += New-ZTVPFinding -Title "Service principals have privileged roles" -Detail ("Apps/service principals have privileged roles. This must be justified because app credentials can be abused if compromised. Principals: " + (($nonUserPrivileged | ForEach-Object { "$($_.principalLabel) [$($_.principalType)]" }) -join ", "))
            $recommendations += New-ZTVPRecommendation -Title "Review privileged service principals" -Detail "Check each privileged service principal or app. Confirm owner, purpose, credential hygiene, monitoring, and whether the role can be reduced or removed."
        }

        $status = "PASS"
        $risk = "LOW"

        if (
            (-not [string]::IsNullOrWhiteSpace($activeError) -and $fallbackUsed -eq $false) -or
            $globalAdmins.Count -eq 0 -or
            $globalAdmins.Count -gt 5 -or
            $privilegedRoleAdmins.Count -gt 2 -or
            $permanentCritical.Count -gt 0 -or
            $nonUserCritical.Count -gt 0
        ) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif (
            $eligibleError -or
            ($eligible.Count -eq 0 -and $active.Count -gt 0) -or
            $permanentActive.Count -gt 0 -or
            $globalAdmins.Count -eq 1 -or
            $globalAdmins.Count -gt 3 -or
            $roleStacked.Count -gt 0 -or
            $emergencyPrincipals.Count -gt 0 -or
            $disabledPrivilegedUsers.Count -gt 0
        ) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }

        $currentState = @(
            "Privileged roles assessed: $($roleSummary.Count)."
            "Active privileged assignments: $($active.Count)."
            "Eligible privileged assignments: $($eligible.Count)."
            "JIT/PIM model: $jitModel."
            "Permanent active assignments: $($permanentActive.Count)."
            "Permanent critical assignments: $($permanentCritical.Count)."
            "Active assignments without matching eligibility: $($activeWithoutEligibility.Count)."
            "Unique privileged principals: $($principals.Count)."
            "Global Administrators: $($globalAdmins.Count)."
            "Privileged Role Administrators: $($privilegedRoleAdmins.Count)."
            "Role-stacked principals: $($roleStacked.Count)."
            "Emergency privileged principals: $($emergencyPrincipals.Count)."
            "Disabled privileged users: $($disabledPrivilegedUsers.Count)."
            "Non-user privileged principals: $($nonUserPrivileged.Count)."
        ) -join " "

        $zeroTrustTarget = "Privileged access should follow least privilege. Normal admins should not be permanently active in critical roles; they should be PIM eligible, activate only when needed, and use narrower roles whenever possible."

        if ($status -eq "PASS") {
            $summary = "Privileged role posture appears controlled. Active privileged exposure is limited and PIM/JIT evidence supports the privileged access model."
            $gap = "No major privileged role assignment gap was detected."
        }
        elseif ($status -eq "PARTIAL") {
            $summary = "Privileged role posture requires review. Standing access, limited JIT evidence, emergency roles, or role stacking reduce least-privilege confidence."
            $gap = "Privileged access is partially aligned but requires cleanup, justification, or stronger JIT adoption."
        }
        else {
            $summary = "Too many powerful admin roles are permanently active. Reduce Global Administrators, move normal admin access to PIM eligible/time-bound activation, and review service principals with privileged roles."
            $gap = "The tenant relies too much on permanent privileged access instead of least privilege and PIM/JIT."
        }

        return New-ZTVPResult `
            -ScenarioId "P1" `
            -ScenarioName "Privileged Role Assignment and JIT Review" `
            -Category "Privileged Access" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary = $summary
                assessment_scope_note = "P1 reviews active privileged assignments and PIM/JIT eligibility evidence when available. If PIM schedule permissions are missing, P1 falls back to active directory role membership and reports the evidence gap."

                privileged_role_count = $roleSummary.Count
                active_privileged_assignment_count = $active.Count
                eligible_privileged_assignment_count = $eligible.Count
                jit_model = $jitModel

                active_permanent_assignment_count = $permanentActive.Count
                active_timebound_assignment_count = $timeBoundActive.Count
                permanent_critical_assignment_count = $permanentCritical.Count
                high_impact_assignment_count = $highImpactActive.Count
                critical_assignment_count = $criticalActive.Count
                active_without_eligibility_count = $activeWithoutEligibility.Count

                unique_privileged_principal_count = $principals.Count
                global_admin_count = $globalAdmins.Count
                privileged_role_admin_count = $privilegedRoleAdmins.Count
                multiple_role_principal_count = $roleStacked.Count
                multiple_critical_role_principal_count = $criticalRoleStacked.Count
                emergency_privileged_principal_count = $emergencyPrincipals.Count
                disabled_privileged_user_count = $disabledPrivilegedUsers.Count
                non_user_privileged_principal_count = $nonUserPrivileged.Count

                active_collection_error = $activeError
                eligibility_collection_error = $eligibleError
                fallback_used = $fallbackUsed
                fallback_error = $fallbackError
                unknown_role_count = $unknownRoleCount

                role_evidence = $roleSummary
                active_assignments = $active
                eligible_assignments = $eligible
                active_permanent_assignments = $permanentActive
                permanent_critical_assignments = $permanentCritical
                active_without_eligibility = $activeWithoutEligibility
                privileged_principals = $principals
                global_admins = $globalAdmins
                privileged_role_admins = $privilegedRoleAdmins
                multiple_role_principals = $roleStacked
                multiple_critical_role_principals = $criticalRoleStacked
                emergency_privileged_principals = $emergencyPrincipals
                disabled_privileged_users = $disabledPrivilegedUsers
                non_user_privileged_principals = $nonUserPrivileged
                high_impact_assignments = $highImpactActive
                critical_assignments = $criticalActive
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gap
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "P1" `
            -ScenarioName "Privileged Role Assignment and JIT Review" `
            -Category "Privileged Access" `
            -Status "ERROR" `
            -Risk "CRITICAL" `
            -Findings @(
                New-ZTVPFinding -Title "Execution error" -Detail $_.Exception.Message
            ) `
            -Recommendations @(
                New-ZTVPRecommendation -Title "Fix P1 execution issue" -Detail "Review Graph permissions, RoleManagement modules, and directory role visibility."
            ) `
            -Evidence $null `
            -CurrentState "P1 could not complete privileged role and JIT assessment." `
            -ZeroTrustTarget "Privileged roles should follow least privilege and just-in-time access." `
            -GapSummary "P1 could not be evaluated because execution failed."
    }
}


