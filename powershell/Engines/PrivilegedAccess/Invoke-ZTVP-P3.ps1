Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Identity.DirectoryManagement -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Identity.Governance -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Users -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Groups -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Applications -Force -ErrorAction SilentlyContinue

function Get-ZTVPP3Property {
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

function Get-ZTVPP3RoleImpact {
    param([string]$RoleName)

    switch ($RoleName) {
        "Global Administrator" { return "Critical" }
        "Privileged Role Administrator" { return "Critical" }
        "Conditional Access Administrator" { return "Critical" }
        "Authentication Policy Administrator" { return "Critical" }
        "Security Administrator" { return "High" }
        "Authentication Administrator" { return "High" }
        "User Administrator" { return "High" }
        "Exchange Administrator" { return "High" }
        "SharePoint Administrator" { return "High" }
        "Intune Administrator" { return "High" }
        "Application Administrator" { return "High" }
        "Cloud Application Administrator" { return "High" }
        "Groups Administrator" { return "High" }
        "Global Reader" { return "Medium" }
        "Security Reader" { return "Medium" }
        default { return "Medium" }
    }
}

function Get-ZTVPP3RoleCategory {
    param([string]$RoleName)

    switch ($RoleName) {
        "Global Administrator" { return "Tenant-wide administration" }
        "Privileged Role Administrator" { return "Role management" }
        "Conditional Access Administrator" { return "Access enforcement" }
        "Authentication Policy Administrator" { return "Authentication policy" }
        "Security Administrator" { return "Security administration" }
        "Authentication Administrator" { return "Authentication administration" }
        "User Administrator" { return "Identity administration" }
        "Exchange Administrator" { return "Workload administration" }
        "SharePoint Administrator" { return "Workload administration" }
        "Intune Administrator" { return "Device administration" }
        "Application Administrator" { return "Application administration" }
        "Cloud Application Administrator" { return "Application administration" }
        "Groups Administrator" { return "Group administration" }
        "Global Reader" { return "Read-only privileged visibility" }
        "Security Reader" { return "Read-only security visibility" }
        default { return "Privileged access" }
    }
}

function Test-ZTVPP3PermanentAssignment {
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

function Resolve-ZTVPP3Principal {
    param(
        [string]$PrincipalId,
        $ExpandedPrincipal,
        $OwnerCache
    )

    $displayName = $null
    $upn = $null
    $mail = $null
    $enabled = $null
    $type = "Unknown"
    $appId = $null
    $servicePrincipalType = $null
    $ownerCount = $null
    $ownerLabels = @()
    $ownerCollectionError = $null

    if ($null -ne $ExpandedPrincipal) {
        $odata = Get-ZTVPP3Property -Object $ExpandedPrincipal -Names @("@odata.type", "ODataType")

        if ($odata -match "user") { $type = "User" }
        elseif ($odata -match "servicePrincipal") { $type = "ServicePrincipal" }
        elseif ($odata -match "group") { $type = "Group" }

        $displayName = Get-ZTVPP3Property -Object $ExpandedPrincipal -Names @("DisplayName", "displayName")
        $upn = Get-ZTVPP3Property -Object $ExpandedPrincipal -Names @("UserPrincipalName", "userPrincipalName")
        $mail = Get-ZTVPP3Property -Object $ExpandedPrincipal -Names @("Mail", "mail")
        $enabled = Get-ZTVPP3Property -Object $ExpandedPrincipal -Names @("AccountEnabled", "accountEnabled")
        $appId = Get-ZTVPP3Property -Object $ExpandedPrincipal -Names @("AppId", "appId")
        $servicePrincipalType = Get-ZTVPP3Property -Object $ExpandedPrincipal -Names @("ServicePrincipalType", "servicePrincipalType")
    }

    if (-not [string]::IsNullOrWhiteSpace($PrincipalId)) {
        if ($type -eq "User" -or $type -eq "Unknown" -or [string]::IsNullOrWhiteSpace($upn)) {
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
            catch {}
        }

        if (($type -eq "ServicePrincipal" -or $type -eq "Unknown") -and ($null -eq $enabled -or [string]::IsNullOrWhiteSpace($displayName))) {
            try {
                $sp = Get-MgServicePrincipal -ServicePrincipalId $PrincipalId -Property "id,displayName,appId,accountEnabled,servicePrincipalType" -ErrorAction Stop

                if ($sp) {
                    $type = "ServicePrincipal"
                    $displayName = $sp.DisplayName
                    $appId = $sp.AppId
                    $mail = $sp.AppId
                    $enabled = $sp.AccountEnabled
                    $servicePrincipalType = $sp.ServicePrincipalType
                }
            }
            catch {}
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
            catch {}
        }
    }

    if ($type -eq "ServicePrincipal" -and -not [string]::IsNullOrWhiteSpace($PrincipalId)) {
        if ($OwnerCache.ContainsKey($PrincipalId)) {
            $cached = $OwnerCache[$PrincipalId]
            $ownerCount = $cached.ownerCount
            $ownerLabels = @($cached.ownerLabels)
            $ownerCollectionError = $cached.ownerCollectionError
        }
        else {
            try {
                $owners = @(Get-MgServicePrincipalOwner -ServicePrincipalId $PrincipalId -All -ErrorAction Stop)

                foreach ($owner in $owners) {
                    $ownerLabel = Get-ZTVPP3Property -Object $owner -Names @("UserPrincipalName", "userPrincipalName", "DisplayName", "displayName", "Id", "id")

                    if (-not [string]::IsNullOrWhiteSpace($ownerLabel)) {
                        $ownerLabels += $ownerLabel
                    }
                }

                $ownerCount = $owners.Count
            }
            catch {
                $ownerCollectionError = $_.Exception.Message
            }

            $OwnerCache[$PrincipalId] = [PSCustomObject]@{
                ownerCount = $ownerCount
                ownerLabels = $ownerLabels
                ownerCollectionError = $ownerCollectionError
            }
        }
    }

    $label = $upn
    if ([string]::IsNullOrWhiteSpace($label)) { $label = $displayName }
    if ([string]::IsNullOrWhiteSpace($label)) { $label = $PrincipalId }

    [PSCustomObject]@{
        principalId          = $PrincipalId
        principalLabel       = $label
        displayName          = $displayName
        userPrincipalName    = $upn
        mail                 = $mail
        appId                = $appId
        servicePrincipalType = $servicePrincipalType
        accountEnabled       = $enabled
        principalType        = $type
        ownerCount           = $ownerCount
        ownerLabels          = $ownerLabels
        ownerCollectionError = $ownerCollectionError
    }
}

function New-ZTVPP3Assignment {
    param(
        $Instance,
        [string]$Kind,
        $RoleMap,
        $OwnerCache
    )

    $roleName = $null
    $roleDefinition = Get-ZTVPP3Property -Object $Instance -Names @("RoleDefinition", "roleDefinition")
    $roleDefinitionId = Get-ZTVPP3Property -Object $Instance -Names @("RoleDefinitionId", "roleDefinitionId")

    if ($roleDefinition) {
        $roleName = Get-ZTVPP3Property -Object $roleDefinition -Names @("DisplayName", "displayName")
    }

    if ([string]::IsNullOrWhiteSpace($roleName) -and $RoleMap.ContainsKey($roleDefinitionId)) {
        $roleName = $RoleMap[$roleDefinitionId]
    }

    if ([string]::IsNullOrWhiteSpace($roleName)) {
        $roleName = "Unknown role"
    }

    $principalId = Get-ZTVPP3Property -Object $Instance -Names @("PrincipalId", "principalId")
    $principalObject = Get-ZTVPP3Property -Object $Instance -Names @("Principal", "principal")
    $principal = Resolve-ZTVPP3Principal -PrincipalId $principalId -ExpandedPrincipal $principalObject -OwnerCache $OwnerCache

    $start = Get-ZTVPP3Property -Object $Instance -Names @("StartDateTime", "startDateTime")
    $end = Get-ZTVPP3Property -Object $Instance -Names @("EndDateTime", "endDateTime")
    $assignmentType = Get-ZTVPP3Property -Object $Instance -Names @("AssignmentType", "assignmentType")
    $memberType = Get-ZTVPP3Property -Object $Instance -Names @("MemberType", "memberType")

    $permanent = Test-ZTVPP3PermanentAssignment -EndDateTime $end

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
        roleName             = $roleName
        impact               = Get-ZTVPP3RoleImpact $roleName
        category             = Get-ZTVPP3RoleCategory $roleName
        principalId          = $principal.principalId
        principalLabel       = $principal.principalLabel
        displayName          = $principal.displayName
        appId                = $principal.appId
        servicePrincipalType = $principal.servicePrincipalType
        principalType        = $principal.principalType
        accountEnabled       = $principal.accountEnabled
        ownerCount           = $principal.ownerCount
        ownerLabels          = $principal.ownerLabels
        ownerCollectionError = $principal.ownerCollectionError
        assignmentKind       = $Kind
        assignmentModel      = $model
        permanent            = $permanent
        startDateTime        = $start
        endDateTime          = $end
        assignmentType       = $assignmentType
        memberType           = $memberType
    }
}

function Invoke-ZTVP-P3 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== P3 - Privileged Service Principal Role Review ===" -ForegroundColor Cyan

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
        $ownerCache = @{}

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
                $a = New-ZTVPP3Assignment -Instance $i -Kind "Active" -RoleMap $roleMap -OwnerCache $ownerCache

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
                $e = New-ZTVPP3Assignment -Instance $i -Kind "Eligible" -RoleMap $roleMap -OwnerCache $ownerCache

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
                        $principal = Resolve-ZTVPP3Principal -PrincipalId $m.Id -ExpandedPrincipal $m -OwnerCache $ownerCache

                        $active += [PSCustomObject]@{
                            roleName             = $role.DisplayName
                            impact               = Get-ZTVPP3RoleImpact $role.DisplayName
                            category             = Get-ZTVPP3RoleCategory $role.DisplayName
                            principalId          = $principal.principalId
                            principalLabel       = $principal.principalLabel
                            displayName          = $principal.displayName
                            appId                = $principal.appId
                            servicePrincipalType = $principal.servicePrincipalType
                            principalType        = $principal.principalType
                            accountEnabled       = $principal.accountEnabled
                            ownerCount           = $principal.ownerCount
                            ownerLabels          = $principal.ownerLabels
                            ownerCollectionError = $principal.ownerCollectionError
                            assignmentKind       = "Active"
                            assignmentModel      = "Active directory role membership fallback"
                            permanent            = $true
                            startDateTime        = $null
                            endDateTime          = $null
                            assignmentType       = $null
                            memberType           = $null
                        }
                    }
                }
            }
            catch {
                $fallbackError = $_.Exception.Message
            }
        }

        $active = @($active | Sort-Object principalType, impact, roleName, principalLabel)
        $eligible = @($eligible | Sort-Object principalType, impact, roleName, principalLabel)

        $nonHumanActive = @($active | Where-Object { $_.principalType -ne "User" })
        $servicePrincipalActive = @($nonHumanActive | Where-Object { $_.principalType -eq "ServicePrincipal" })
        $groupActive = @($nonHumanActive | Where-Object { $_.principalType -eq "Group" })
        $unknownActive = @($nonHumanActive | Where-Object { $_.principalType -eq "Unknown" })

        $nonHumanEligible = @($eligible | Where-Object { $_.principalType -ne "User" })

        $nonHumanGlobalAdmins = @($nonHumanActive | Where-Object { $_.roleName -eq "Global Administrator" })
        $servicePrincipalGlobalAdmins = @($servicePrincipalActive | Where-Object { $_.roleName -eq "Global Administrator" })

        $nonHumanCritical = @($nonHumanActive | Where-Object { $_.impact -eq "Critical" })
        $nonHumanHighImpact = @($nonHumanActive | Where-Object { $_.impact -in @("Critical","High") })
        $permanentNonHuman = @($nonHumanActive | Where-Object { $_.permanent -eq $true })
        $permanentCriticalNonHuman = @($permanentNonHuman | Where-Object { $_.impact -eq "Critical" })

        $disabledPrivilegedServicePrincipals = @($servicePrincipalActive | Where-Object { $_.accountEnabled -eq $false })

        $servicePrincipalsWithNoOwners = @(
            $servicePrincipalActive |
            Where-Object {
                $null -ne $_.ownerCount -and
                $_.ownerCount -eq 0
            }
        )

        $servicePrincipalsOwnerUnknown = @(
            $servicePrincipalActive |
            Where-Object {
                $null -ne $_.ownerCollectionError
            }
        )

        $nonHumanByPrincipal = @()

        foreach ($g in ($nonHumanActive | Group-Object principalId)) {
            $items = @($g.Group)
            $first = $items[0]
            $roles = @($items | ForEach-Object { $_.roleName } | Sort-Object -Unique)
            $criticalRoles = @($items | Where-Object { $_.impact -eq "Critical" } | ForEach-Object { $_.roleName } | Sort-Object -Unique)
            $highRoles = @($items | Where-Object { $_.impact -in @("Critical","High") } | ForEach-Object { $_.roleName } | Sort-Object -Unique)

            $nonHumanByPrincipal += [PSCustomObject]@{
                principalId          = $first.principalId
                principalLabel       = $first.principalLabel
                principalType        = $first.principalType
                appId                = $first.appId
                servicePrincipalType = $first.servicePrincipalType
                accountEnabled       = $first.accountEnabled
                ownerCount           = $first.ownerCount
                ownerLabels          = $first.ownerLabels
                ownerCollectionError = $first.ownerCollectionError
                roles                = $roles
                roleCount            = $roles.Count
                criticalRoles        = $criticalRoles
                criticalRoleCount    = $criticalRoles.Count
                highImpactRoles      = $highRoles
                highImpactRoleCount  = $highRoles.Count
                globalAdmin          = [bool]($roles -contains "Global Administrator")
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($activeError) -and $fallbackUsed -eq $true) {
            $findings += New-ZTVPFinding `
                -Title "PIM active schedule evidence unavailable; fallback used" `
                -Detail "P3 used active directory role membership as non-human privileged role evidence. Original error: $activeError"

            $recommendations += New-ZTVPRecommendation `
                -Title "Enable PIM active assignment evidence" `
                -Detail "Grant RoleAssignmentSchedule.Read.Directory or RoleManagement.Read.Directory so P3 can collect PIM-aware active assignment schedule instances."
        }

        if ($nonHumanActive.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No non-human privileged role assignments detected" `
                -Detail "No service principals, groups, or unknown non-user objects were found with monitored privileged directory roles."

            $recommendations += New-ZTVPRecommendation `
                -Title "Maintain non-human privileged access hygiene" `
                -Detail "Continue monitoring apps, service principals, groups, and managed identities for privileged role assignments."
        }
        else {
            $findings += New-ZTVPFinding `
                -Title "Non-human privileged role assignments detected" `
                -Detail "Service principals, groups, or non-user objects hold privileged roles. These should be removed, reduced, or formally justified because compromise of app credentials can become administrative compromise."
        }

        if ($nonHumanGlobalAdmins.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Service principals or non-user objects have Global Administrator" `
                -Detail ("Global Administrator on apps or non-user objects is high risk and should be removed unless strongly justified. Principals: " + (($nonHumanGlobalAdmins | ForEach-Object { "$($_.principalLabel) [$($_.principalType)]" }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Remove or justify Global Administrator from non-human identities" `
                -Detail "Remove Global Administrator from service principals, apps, or groups unless there is a documented, monitored, and strictly required reason."
        }

        if ($nonHumanHighImpact.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Non-human identities hold high-impact privileged roles" `
                -Detail ("Non-human identities hold Critical or High-impact roles. Assignments: " + (($nonHumanHighImpact | Select-Object -First 10 | ForEach-Object { "$($_.principalLabel) [$($_.roleName)]" }) -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Apply least privilege to non-human identities" `
                -Detail "Replace broad directory roles with the narrowest application permissions, workload roles, or managed identity permissions required."
        }

        if ($permanentCriticalNonHuman.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Critical non-human privileged access is permanent" `
                -Detail ("Critical roles assigned to non-human identities are permanently active. Assignments: " + (($permanentCriticalNonHuman | Select-Object -First 10 | ForEach-Object { "$($_.principalLabel) [$($_.roleName)]" }) -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review permanent critical app access" `
                -Detail "Critical role access for apps or service principals should be exceptional, documented, monitored, and reduced wherever possible."
        }

        if ($groupActive.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Groups hold privileged directory roles" `
                -Detail ("Groups assigned to privileged roles can expand access through group membership. Groups: " + (($groupActive | ForEach-Object { "$($_.principalLabel) [$($_.roleName)]" }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review group-based privileged role assignment" `
                -Detail "Confirm privileged groups have controlled membership, owners, access reviews, and no broad nested membership."
        }

        if ($servicePrincipalsWithNoOwners.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Privileged service principals have no owners" `
                -Detail ("Service principals with privileged roles have no owner returned by Graph. Principals: " + (($servicePrincipalsWithNoOwners | ForEach-Object { $_.principalLabel }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Assign owners to privileged service principals" `
                -Detail "Every privileged service principal should have accountable owners, documented purpose, and monitored credentials."
        }

        if ($servicePrincipalsOwnerUnknown.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Service principal owner evidence unavailable" `
                -Detail "Owner collection failed for one or more privileged service principals. Review permissions or manually confirm ownership."
        }

        if ($disabledPrivilegedServicePrincipals.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Disabled service principals still hold privileged roles" `
                -Detail ("Disabled service principals should not retain privileged roles unless explicitly justified. Principals: " + (($disabledPrivilegedServicePrincipals | ForEach-Object { $_.principalLabel }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Remove roles from disabled service principals" `
                -Detail "Remove privileged directory role assignments from disabled service principals unless there is a documented recovery or dependency reason."
        }

        $status = "PASS"
        $risk = "LOW"

        if (
            (-not [string]::IsNullOrWhiteSpace($activeError) -and $fallbackUsed -eq $false) -or
            $nonHumanGlobalAdmins.Count -gt 0 -or
            $permanentCriticalNonHuman.Count -gt 0 -or
            $disabledPrivilegedServicePrincipals.Count -gt 0
        ) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif (
            $nonHumanHighImpact.Count -gt 0 -or
            $servicePrincipalsWithNoOwners.Count -gt 0 -or
            $groupActive.Count -gt 0 -or
            $servicePrincipalsOwnerUnknown.Count -gt 0
        ) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }

        $currentState = @(
            "Non-human privileged assignments: $($nonHumanActive.Count)."
            "Privileged service principal assignments: $($servicePrincipalActive.Count)."
            "Privileged group assignments: $($groupActive.Count)."
            "Non-human Global Administrator assignments: $($nonHumanGlobalAdmins.Count)."
            "Critical non-human assignments: $($nonHumanCritical.Count)."
            "High-impact non-human assignments: $($nonHumanHighImpact.Count)."
            "Permanent non-human assignments: $($permanentNonHuman.Count)."
            "Privileged service principals with no owners: $($servicePrincipalsWithNoOwners.Count)."
            "Disabled privileged service principals: $($disabledPrivilegedServicePrincipals.Count)."
        ) -join " "

        $zeroTrustTarget = "Service principals, apps, groups, and non-human identities should not hold broad privileged directory roles unless explicitly justified. Global Administrator should normally not be assigned to non-human identities. Privileged apps should have owners, documented purpose, credential hygiene, monitoring, and least-privilege permissions."

        if ($status -eq "PASS") {
            $summary = "Non-human privileged access appears controlled. No risky service principal, app, or group privileged role exposure was detected."
            $gap = "No major non-human privileged role gap was detected."
        }
        elseif ($status -eq "PARTIAL") {
            $summary = "Non-human privileged access requires review. Some service principals, groups, or non-user identities hold privileged roles that need justification or cleanup."
            $gap = "Non-human privileged access is partially aligned but requires ownership, monitoring, or least-privilege review."
        }
        else {
            $summary = "Critical non-human privileged access detected. Service principals or non-user objects have powerful roles such as Global Administrator or permanent critical privileged access."
            $gap = "Non-human privileged access is not aligned with least privilege and requires immediate review."
        }

        return New-ZTVPResult `
            -ScenarioId "P3" `
            -ScenarioName "Privileged Service Principal Role Review" `
            -Category "Privileged Access" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary = $summary
                assessment_scope_note = "P3 focuses on service principals, apps, groups, and non-user identities with privileged directory role assignments."

                non_human_privileged_assignment_count = $nonHumanActive.Count
                service_principal_privileged_assignment_count = $servicePrincipalActive.Count
                group_privileged_assignment_count = $groupActive.Count
                unknown_non_human_assignment_count = $unknownActive.Count

                non_human_global_admin_count = $nonHumanGlobalAdmins.Count
                service_principal_global_admin_count = $servicePrincipalGlobalAdmins.Count
                non_human_critical_assignment_count = $nonHumanCritical.Count
                non_human_high_impact_assignment_count = $nonHumanHighImpact.Count
                permanent_non_human_assignment_count = $permanentNonHuman.Count
                permanent_critical_non_human_assignment_count = $permanentCriticalNonHuman.Count

                service_principal_no_owner_count = $servicePrincipalsWithNoOwners.Count
                service_principal_owner_unknown_count = $servicePrincipalsOwnerUnknown.Count
                disabled_privileged_service_principal_count = $disabledPrivilegedServicePrincipals.Count

                active_collection_error = $activeError
                eligibility_collection_error = $eligibleError
                fallback_used = $fallbackUsed
                fallback_error = $fallbackError

                non_human_privileged_assignments = $nonHumanActive
                service_principal_privileged_assignments = $servicePrincipalActive
                group_privileged_assignments = $groupActive
                non_human_global_admins = $nonHumanGlobalAdmins
                service_principal_global_admins = $servicePrincipalGlobalAdmins
                non_human_critical_assignments = $nonHumanCritical
                non_human_high_impact_assignments = $nonHumanHighImpact
                permanent_non_human_assignments = $permanentNonHuman
                permanent_critical_non_human_assignments = $permanentCriticalNonHuman
                service_principals_with_no_owners = $servicePrincipalsWithNoOwners
                service_principals_owner_unknown = $servicePrincipalsOwnerUnknown
                disabled_privileged_service_principals = $disabledPrivilegedServicePrincipals
                non_human_by_principal = $nonHumanByPrincipal
                eligible_non_human_assignments = $nonHumanEligible
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gap
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "P3" `
            -ScenarioName "Privileged Service Principal Role Review" `
            -Category "Privileged Access" `
            -Status "ERROR" `
            -Risk "CRITICAL" `
            -Findings @(
                New-ZTVPFinding -Title "Execution error" -Detail $_.Exception.Message
            ) `
            -Recommendations @(
                New-ZTVPRecommendation -Title "Fix P3 execution issue" -Detail "Review Graph permissions, RoleManagement modules, service principal visibility, and owner collection permissions."
            ) `
            -Evidence $null `
            -CurrentState "P3 could not complete non-human privileged role assessment." `
            -ZeroTrustTarget "Service principals, apps, groups, and non-human identities should not hold broad privileged directory roles unless explicitly justified." `
            -GapSummary "P3 could not be evaluated because execution failed."
    }
}
