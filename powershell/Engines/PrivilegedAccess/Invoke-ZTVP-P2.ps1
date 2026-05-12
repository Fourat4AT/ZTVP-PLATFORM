Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Identity.DirectoryManagement -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Identity.Governance -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Users -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Groups -Force -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Applications -Force -ErrorAction SilentlyContinue

function Get-ZTVPP2Property {
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

function Test-ZTVPP2EmergencyName {
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

function Test-ZTVPP2PermanentAssignment {
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

function Resolve-ZTVPP2Principal {
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
        $odata = Get-ZTVPP2Property -Object $ExpandedPrincipal -Names @("@odata.type", "ODataType")

        if ($odata -match "user") { $type = "User" }
        elseif ($odata -match "servicePrincipal") { $type = "ServicePrincipal" }
        elseif ($odata -match "group") { $type = "Group" }

        $displayName = Get-ZTVPP2Property -Object $ExpandedPrincipal -Names @("DisplayName", "displayName")
        $upn = Get-ZTVPP2Property -Object $ExpandedPrincipal -Names @("UserPrincipalName", "userPrincipalName")
        $mail = Get-ZTVPP2Property -Object $ExpandedPrincipal -Names @("Mail", "mail")
        $enabled = Get-ZTVPP2Property -Object $ExpandedPrincipal -Names @("AccountEnabled", "accountEnabled")
    }

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
            catch {}
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

    $label = $upn
    if ([string]::IsNullOrWhiteSpace($label)) { $label = $displayName }
    if ([string]::IsNullOrWhiteSpace($label)) { $label = $PrincipalId }

    $isEmergency = [bool](
        (Test-ZTVPP2EmergencyName $label) -or
        (Test-ZTVPP2EmergencyName $displayName) -or
        (Test-ZTVPP2EmergencyName $mail)
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

function New-ZTVPP2Assignment {
    param(
        $Instance,
        [string]$Kind,
        $RoleMap
    )

    $roleName = $null
    $roleDefinition = Get-ZTVPP2Property -Object $Instance -Names @("RoleDefinition", "roleDefinition")
    $roleDefinitionId = Get-ZTVPP2Property -Object $Instance -Names @("RoleDefinitionId", "roleDefinitionId")

    if ($roleDefinition) {
        $roleName = Get-ZTVPP2Property -Object $roleDefinition -Names @("DisplayName", "displayName")
    }

    if ([string]::IsNullOrWhiteSpace($roleName) -and $RoleMap.ContainsKey($roleDefinitionId)) {
        $roleName = $RoleMap[$roleDefinitionId]
    }

    if ([string]::IsNullOrWhiteSpace($roleName)) {
        $roleName = "Unknown role"
    }

    $principalId = Get-ZTVPP2Property -Object $Instance -Names @("PrincipalId", "principalId")
    $principalObject = Get-ZTVPP2Property -Object $Instance -Names @("Principal", "principal")
    $principal = Resolve-ZTVPP2Principal -PrincipalId $principalId -ExpandedPrincipal $principalObject

    $start = Get-ZTVPP2Property -Object $Instance -Names @("StartDateTime", "startDateTime")
    $end = Get-ZTVPP2Property -Object $Instance -Names @("EndDateTime", "endDateTime")
    $assignmentType = Get-ZTVPP2Property -Object $Instance -Names @("AssignmentType", "assignmentType")
    $memberType = Get-ZTVPP2Property -Object $Instance -Names @("MemberType", "memberType")

    $permanent = Test-ZTVPP2PermanentAssignment -EndDateTime $end

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

function Invoke-ZTVP-P2 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== P2 - Global Administrator Count and Hygiene Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

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
                $a = New-ZTVPP2Assignment -Instance $i -Kind "Active" -RoleMap $roleMap

                if ($a.roleName -eq "Global Administrator") {
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
                $e = New-ZTVPP2Assignment -Instance $i -Kind "Eligible" -RoleMap $roleMap

                if ($e.roleName -eq "Global Administrator") {
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
                $gaRole = $directoryRoles | Where-Object { $_.DisplayName -eq "Global Administrator" } | Select-Object -First 1

                if ($gaRole) {
                    $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All -ErrorAction Stop)

                    foreach ($m in $members) {
                        $p = Resolve-ZTVPP2Principal -PrincipalId $m.Id -ExpandedPrincipal $m

                        $active += [PSCustomObject]@{
                            roleName          = "Global Administrator"
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

        $active = @($active | Sort-Object principalType, principalLabel)
        $eligible = @($eligible | Sort-Object principalType, principalLabel)

        $eligibleKeys = @{}

        foreach ($e in $eligible) {
            $eligibleKeys[$e.principalId] = $true
        }

        $activeWithoutEligibility = @()

        foreach ($a in $active) {
            if (-not $eligibleKeys.ContainsKey($a.principalId)) {
                $activeWithoutEligibility += $a
            }
        }

        $permanentActive = @($active | Where-Object { $_.permanent -eq $true })
        $timeBoundActive = @($active | Where-Object { $_.permanent -ne $true })

        $userGAs = @($active | Where-Object { $_.principalType -eq "User" })
        $normalUserGAs = @($active | Where-Object { $_.principalType -eq "User" -and $_.emergency -ne $true })
        $emergencyGAs = @($active | Where-Object { $_.emergency -eq $true })
        $nonUserGAs = @($active | Where-Object { $_.principalType -ne "User" })

        $permanentNormalUserGAs = @($normalUserGAs | Where-Object { $_.permanent -eq $true })
        $permanentEmergencyGAs = @($emergencyGAs | Where-Object { $_.permanent -eq $true })
        $disabledUserGAs = @($active | Where-Object { $_.principalType -eq "User" -and $_.accountEnabled -eq $false })

        $jitModel = "Not confirmed"

        if (-not [string]::IsNullOrWhiteSpace($eligibleError)) {
            $jitModel = "PIM eligibility evidence unavailable"
        }
        elseif ($eligible.Count -eq 0 -and $active.Count -gt 0) {
            $jitModel = "Standing active Global Administrator model"
        }
        elseif ($eligible.Count -gt 0 -and $permanentActive.Count -gt 0) {
            $jitModel = "Mixed model: eligible access exists, but permanent Global Administrators remain"
        }
        elseif ($eligible.Count -gt 0 -and $permanentActive.Count -eq 0) {
            $jitModel = "JIT / eligible-first Global Administrator model"
        }

        if (-not [string]::IsNullOrWhiteSpace($activeError) -and $fallbackUsed -eq $true) {
            $findings += New-ZTVPFinding `
                -Title "PIM active schedule evidence unavailable; fallback used" `
                -Detail "P2 used active directory role membership as Global Administrator evidence. Original error: $activeError"

            $recommendations += New-ZTVPRecommendation `
                -Title "Enable PIM active assignment evidence" `
                -Detail "Grant RoleAssignmentSchedule.Read.Directory or RoleManagement.Read.Directory so P2 can collect PIM-aware active Global Administrator assignments."
        }

        if (-not [string]::IsNullOrWhiteSpace($eligibleError)) {
            $findings += New-ZTVPFinding `
                -Title "PIM eligibility evidence unavailable" `
                -Detail $eligibleError

            $recommendations += New-ZTVPRecommendation `
                -Title "Enable PIM eligibility evidence" `
                -Detail "Grant RoleEligibilitySchedule.Read.Directory or RoleManagement.Read.Directory to collect eligible Global Administrator assignments."
        }

        if ($active.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No Global Administrator detected" `
                -Detail "No active Global Administrator was detected. This may indicate collection limitations or a tenant recovery risk."

            $recommendations += New-ZTVPRecommendation `
                -Title "Validate Global Administrator recovery access" `
                -Detail "Confirm that the tenant has approved Global Administrator recovery access and that Graph role-read permissions are working."
        }
        elseif ($active.Count -gt 5) {
            $findings += New-ZTVPFinding `
                -Title "Too many Global Administrators" `
                -Detail ("Global Administrator should be limited to a very small number of approved accounts. This tenant currently has $($active.Count): " + (($active | ForEach-Object { $_.principalLabel }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Reduce Global Administrators" `
                -Detail "Keep only a small number of approved Global Administrators. Delegate daily work to narrower roles such as Conditional Access Administrator, Security Administrator, User Administrator, Exchange Administrator, or SharePoint Administrator."
        }
        elseif ($active.Count -eq 1) {
            $findings += New-ZTVPFinding `
                -Title "Only one Global Administrator detected" `
                -Detail "Only one active Global Administrator was detected. This can create recovery risk if that account is unavailable."

            $recommendations += New-ZTVPRecommendation `
                -Title "Maintain controlled Global Administrator redundancy" `
                -Detail "Maintain a small number of approved Global Administrators, including controlled emergency access accounts."
        }

        if ($permanentNormalUserGAs.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Normal users have permanent Global Administrator" `
                -Detail ("Normal admin users are permanently active as Global Administrator instead of activating through PIM/JIT. Users: " + (($permanentNormalUserGAs | ForEach-Object { $_.principalLabel }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Move normal Global Administrators to PIM eligible access" `
                -Detail "Normal admins should be eligible for Global Administrator and activate only when needed, with time limits, approval, justification, and audit."
        }

        if ($activeWithoutEligibility.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Global Administrator access is not activated through PIM/JIT" `
                -Detail ("Active Global Administrators do not have matching PIM eligible assignments. This suggests standing access. Accounts: " + (($activeWithoutEligibility | ForEach-Object { $_.principalLabel }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Use PIM/JIT for Global Administrator" `
                -Detail "Global Administrator should be eligible and time-bound for normal admins. Keep permanent active Global Administrator only for approved break-glass recovery accounts when justified."
        }

        if ($emergencyGAs.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No break-glass Global Administrator detected" `
                -Detail "No emergency or break-glass Global Administrator account was identified by naming pattern."

            $recommendations += New-ZTVPRecommendation `
                -Title "Validate break-glass coverage" `
                -Detail "Maintain controlled emergency Global Administrator accounts and validate them in A4."
        }
        elseif ($emergencyGAs.Count -ne 2) {
            $findings += New-ZTVPFinding `
                -Title "Break-glass Global Administrator count requires review" `
                -Detail ("Expected a small controlled emergency set, commonly two accounts. Detected $($emergencyGAs.Count): " + (($emergencyGAs | ForEach-Object { $_.principalLabel }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Keep emergency Global Administrators controlled" `
                -Detail "Emergency Global Administrators should be limited, cloud-only, monitored, tested, and not used for daily administration."
        }
        else {
            $findings += New-ZTVPFinding `
                -Title "Break-glass Global Administrators detected" `
                -Detail ("Two emergency Global Administrator accounts were detected. Validate them in A4 and ensure they are not used for daily administration: " + (($emergencyGAs | ForEach-Object { $_.principalLabel }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Continue monitoring break-glass accounts" `
                -Detail "Keep emergency accounts cloud-only, monitored, tested, excluded only where justified, and reviewed in A4."
        }

        if ($nonUserGAs.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Service principals or non-user objects have Global Administrator" `
                -Detail ("Non-user principals with Global Administrator are high risk and must be justified. Principals: " + (($nonUserGAs | ForEach-Object { "$($_.principalLabel) [$($_.principalType)]" }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Remove or justify Global Administrator from service principals" `
                -Detail "Review each service principal or non-user object with Global Administrator. Remove the role unless there is a documented, monitored, and strictly required reason."
        }

        if ($disabledUserGAs.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Disabled users have Global Administrator" `
                -Detail ("Disabled users still have Global Administrator: " + (($disabledUserGAs | ForEach-Object { $_.principalLabel }) -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Remove Global Administrator from disabled users" `
                -Detail "Disabled accounts should not retain Global Administrator unless explicitly documented for emergency recovery."
        }

        $status = "PASS"
        $risk = "LOW"

        if (
            (-not [string]::IsNullOrWhiteSpace($activeError) -and $fallbackUsed -eq $false) -or
            $active.Count -eq 0 -or
            $active.Count -gt 5 -or
            $nonUserGAs.Count -gt 0 -or
            $permanentNormalUserGAs.Count -gt 0 -or
            $disabledUserGAs.Count -gt 0
        ) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif (
            $active.Count -eq 1 -or
            $active.Count -gt 3 -or
            $emergencyGAs.Count -ne 2 -or
            $activeWithoutEligibility.Count -gt 0 -or
            -not [string]::IsNullOrWhiteSpace($eligibleError)
        ) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }

        $currentState = @(
            "Active Global Administrators: $($active.Count)."
            "Normal user Global Administrators: $($normalUserGAs.Count)."
            "Emergency Global Administrators: $($emergencyGAs.Count)."
            "Service principals/non-user Global Administrators: $($nonUserGAs.Count)."
            "Permanent active Global Administrators: $($permanentActive.Count)."
            "Permanent normal user Global Administrators: $($permanentNormalUserGAs.Count)."
            "PIM eligible Global Administrator assignments: $($eligible.Count)."
            "Active Global Administrators without matching eligibility: $($activeWithoutEligibility.Count)."
            "JIT/PIM model: $jitModel."
        ) -join " "

        $zeroTrustTarget = "Global Administrator should be limited to a very small approved set. Normal administrators should use PIM eligible/time-bound activation and narrower roles wherever possible. Break-glass Global Administrator accounts should be controlled, monitored, tested, and not used for daily administration."

        if ($status -eq "PASS") {
            $summary = "Global Administrator posture appears controlled. Membership is limited, no risky non-user Global Administrators were found, and access aligns with least privilege."
            $gap = "No major Global Administrator count or hygiene gap was detected."
        }
        elseif ($status -eq "PARTIAL") {
            $summary = "Global Administrator posture requires review. Membership, break-glass coverage, or PIM/JIT alignment should be improved."
            $gap = "Global Administrator hygiene is partially aligned but requires cleanup or stronger PIM/JIT use."
        }
        else {
            $summary = "Too much Global Administrator exposure. Reduce Global Administrators, remove or justify service principals with Global Administrator, and move normal admins to PIM eligible/time-bound access."
            $gap = "Global Administrator hygiene is not aligned with least privilege and just-in-time expectations."
        }

        return New-ZTVPResult `
            -ScenarioId "P2" `
            -ScenarioName "Global Administrator Count and Hygiene Review" `
            -Category "Privileged Access" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary = $summary
                assessment_scope_note = "P2 focuses only on Global Administrator. It reviews active Global Administrators, PIM/JIT eligibility evidence, emergency accounts, normal users, and service principals."

                active_global_admin_count = $active.Count
                normal_user_global_admin_count = $normalUserGAs.Count
                emergency_global_admin_count = $emergencyGAs.Count
                non_user_global_admin_count = $nonUserGAs.Count
                permanent_global_admin_count = $permanentActive.Count
                permanent_normal_user_global_admin_count = $permanentNormalUserGAs.Count
                permanent_emergency_global_admin_count = $permanentEmergencyGAs.Count
                eligible_global_admin_count = $eligible.Count
                active_without_eligibility_count = $activeWithoutEligibility.Count
                disabled_global_admin_user_count = $disabledUserGAs.Count
                jit_model = $jitModel
                active_collection_error = $activeError
                eligibility_collection_error = $eligibleError
                fallback_used = $fallbackUsed
                fallback_error = $fallbackError

                active_global_admins = $active
                eligible_global_admins = $eligible
                normal_user_global_admins = $normalUserGAs
                emergency_global_admins = $emergencyGAs
                non_user_global_admins = $nonUserGAs
                permanent_global_admins = $permanentActive
                permanent_normal_user_global_admins = $permanentNormalUserGAs
                active_without_eligibility = $activeWithoutEligibility
                disabled_global_admin_users = $disabledUserGAs
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gap
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "P2" `
            -ScenarioName "Global Administrator Count and Hygiene Review" `
            -Category "Privileged Access" `
            -Status "ERROR" `
            -Risk "CRITICAL" `
            -Findings @(
                New-ZTVPFinding -Title "Execution error" -Detail $_.Exception.Message
            ) `
            -Recommendations @(
                New-ZTVPRecommendation -Title "Fix P2 execution issue" -Detail "Review Graph permissions, RoleManagement modules, and Global Administrator role visibility."
            ) `
            -Evidence $null `
            -CurrentState "P2 could not complete Global Administrator assessment." `
            -ZeroTrustTarget "Global Administrator should be limited, controlled, and preferably PIM/JIT based for normal administrators." `
            -GapSummary "P2 could not be evaluated because execution failed."
    }
}
