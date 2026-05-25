[CmdletBinding()]
param(
    [string]$ProjectRoot = ".",
    [string]$ProposedControl = "Require MFA",
    [string]$TargetScope = "All users",
    [string]$ResourceScope = "All cloud apps",
    [string]$ClientCondition = "Browser",
    [int]$LookbackDays = 30,
    [string]$SelectedGroup = "",
    [string]$SelectedUsers = "",
    [string]$ExcludedUsers = "",
    [string]$ExcludedGroups = "",
    [string]$BreakGlassKeywords = "breakglass,break-glass,emergency,admin-emergency",
    [string]$ServiceAccountKeywords = "svc,service,app,automation,scanner,printer,noreply,smtp,backup"
)

$ErrorActionPreference = "Stop"

$script:warnings = @()
$script:recommendations = @()
$script:limitations = @()

function Add-Warn {
    param([string]$Text)
    if (-not [string]::IsNullOrWhiteSpace($Text) -and $script:warnings -notcontains $Text) {
        $script:warnings += $Text
    }
}

function Add-Rec {
    param([string]$Text)
    if (-not [string]::IsNullOrWhiteSpace($Text) -and $script:recommendations -notcontains $Text) {
        $script:recommendations += $Text
    }
}

function Split-Csv {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @()
    }

    return @(
        $Value -split "[,`n`r;]" |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
    )
}

function Graph-All {
    param([string]$Uri)

    $items = @()
    $next = $Uri

    while (-not [string]::IsNullOrWhiteSpace($next)) {
        try {
            $response = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop

            if ($null -ne $response.value) {
                $items += @($response.value)
            }
            elseif ($null -ne $response) {
                $items += @($response)
            }

            $next = $null
            if ($response.PSObject.Properties.Name -contains "@odata.nextLink") {
                $next = $response.'@odata.nextLink'
            }
        }
        catch {
            Add-Warn "Graph request failed: $Uri :: $($_.Exception.Message)"
            break
        }
    }

    return @($items)
}

function Has-Keyword {
    param(
        [object]$User,
        [string[]]$Keywords
    )

    $text = "$($User.userPrincipalName) $($User.displayName)".ToLowerInvariant()

    foreach ($keyword in $Keywords) {
        if (-not [string]::IsNullOrWhiteSpace($keyword)) {
            if ($text.Contains($keyword.ToLowerInvariant())) {
                return $true
            }
        }
    }

    return $false
}

function Is-Legacy-Signal {
    param([object]$SignIn)

    $text = @(
        $SignIn.clientAppUsed
        $SignIn.appDisplayName
        $SignIn.resourceDisplayName
        $SignIn.authenticationProtocol
        $SignIn.signInEventTypes
    ) -join " "

    $text = $text.ToLowerInvariant()

    $terms = @(
        "legacy",
        "other clients",
        "imap",
        "pop",
        "smtp",
        "smtp auth",
        "exchange activesync",
        "activesync",
        "basic authentication"
    )

    foreach ($term in $terms) {
        if ($text.Contains($term)) {
            return $true
        }
    }

    return $false
}

function Match-Resource {
    param(
        [object]$SignIn,
        [string]$Resource
    )

    $scope = $Resource.ToLowerInvariant()
    $text = "$($SignIn.appDisplayName) $($SignIn.resourceDisplayName) $($SignIn.appId) $($SignIn.resourceId)".ToLowerInvariant()

    if ($scope -eq "all cloud apps") {
        return $true
    }

    if ($scope -eq "azure management") {
        return (
            $text.Contains("azure portal") -or
            $text.Contains("azure resource manager") -or
            $text.Contains("microsoft azure management") -or
            $text.Contains("797f4846-ba00-4fd7-ba43-dac1f8f63013")
        )
    }

    if ($scope -eq "exchange online") {
        return (
            $text.Contains("exchange") -or
            $text.Contains("office 365 exchange online") -or
            $text.Contains("00000002-0000-0ff1-ce00-000000000000")
        )
    }

    if ($scope -eq "microsoft 365") {
        return (
            $text.Contains("microsoft 365") -or
            $text.Contains("office 365") -or
            $text.Contains("sharepoint") -or
            $text.Contains("teams") -or
            $text.Contains("exchange")
        )
    }

    return $true
}

function Match-Client {
    param(
        [object]$SignIn,
        [string]$Condition
    )

    $conditionText = $Condition.ToLowerInvariant()
    $clientText = "$($SignIn.clientAppUsed) $($SignIn.appDisplayName) $($SignIn.resourceDisplayName)".ToLowerInvariant()

    if ($conditionText -eq "browser") {
        return $clientText.Contains("browser")
    }

    if ($conditionText -eq "mobile and desktop apps") {
        return (
            $clientText.Contains("mobile apps") -or
            $clientText.Contains("desktop clients") -or
            $clientText.Contains("mobile") -or
            $clientText.Contains("desktop")
        )
    }

    if ($conditionText -eq "legacy clients") {
        return Is-Legacy-Signal -SignIn $SignIn
    }

    if ($conditionText -eq "unknown device") {
        return $true
    }

    if ($conditionText -eq "untrusted location") {
        return $true
    }

    return $true
}

function Get-Privileged-Maps {
    $byId = @{}
    $byUpn = @{}

    $roleDefinitions = @{}

    try {
        $defs = Graph-All "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName,templateId&`$top=999"
        foreach ($def in $defs) {
            if ($def.id) {
                $roleDefinitions[[string]$def.id] = [string]$def.displayName
            }
        }
    }
    catch {
        Add-Warn "Could not read role definitions: $($_.Exception.Message)"
    }

    try {
        $directoryRoles = Graph-All "https://graph.microsoft.com/v1.0/directoryRoles?`$select=id,displayName,roleTemplateId&`$top=999"

        foreach ($role in $directoryRoles) {
            if (-not $role.id) {
                continue
            }

            $members = Graph-All "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members/microsoft.graph.user?`$select=id,userPrincipalName,displayName&`$top=999"

            foreach ($member in $members) {
                if (-not $member.id) {
                    continue
                }

                $id = ([string]$member.id).ToLowerInvariant()
                $upn = ([string]$member.userPrincipalName).ToLowerInvariant()
                $roleName = [string]$role.displayName

                if (-not $byId.ContainsKey($id)) {
                    $byId[$id] = @()
                }
                if ($byId[$id] -notcontains $roleName) {
                    $byId[$id] += $roleName
                }

                if ($upn) {
                    if (-not $byUpn.ContainsKey($upn)) {
                        $byUpn[$upn] = @()
                    }
                    if ($byUpn[$upn] -notcontains $roleName) {
                        $byUpn[$upn] += $roleName
                    }
                }
            }
        }
    }
    catch {
        Add-Warn "Could not read active directory role members: $($_.Exception.Message)"
    }

    try {
        $assignments = Graph-All "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$select=id,principalId,roleDefinitionId,directoryScopeId&`$top=999"

        foreach ($assignment in $assignments) {
            if (-not $assignment.principalId) {
                continue
            }

            $principalId = ([string]$assignment.principalId).ToLowerInvariant()
            $roleDefinitionId = [string]$assignment.roleDefinitionId

            $roleName = "Directory role"
            if ($roleDefinitions.ContainsKey($roleDefinitionId)) {
                $roleName = $roleDefinitions[$roleDefinitionId]
            }

            if (-not $byId.ContainsKey($principalId)) {
                $byId[$principalId] = @()
            }
            if ($byId[$principalId] -notcontains $roleName) {
                $byId[$principalId] += $roleName
            }
        }
    }
    catch {
        Add-Warn "Could not read directory role assignments: $($_.Exception.Message)"
    }

    try {
        $activeInstances = Graph-All "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$select=id,principalId,roleDefinitionId&`$top=999"

        foreach ($assignment in $activeInstances) {
            if (-not $assignment.principalId) {
                continue
            }

            $principalId = ([string]$assignment.principalId).ToLowerInvariant()
            $roleDefinitionId = [string]$assignment.roleDefinitionId

            $roleName = "Directory role assignment schedule"
            if ($roleDefinitions.ContainsKey($roleDefinitionId)) {
                $roleName = $roleDefinitions[$roleDefinitionId]
            }

            if (-not $byId.ContainsKey($principalId)) {
                $byId[$principalId] = @()
            }
            if ($byId[$principalId] -notcontains $roleName) {
                $byId[$principalId] += $roleName
            }
        }
    }
    catch {
        Add-Warn "Could not read active role assignment schedule instances: $($_.Exception.Message)"
    }

    try {
        $eligibleInstances = Graph-All "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$select=id,principalId,roleDefinitionId&`$top=999"

        foreach ($assignment in $eligibleInstances) {
            if (-not $assignment.principalId) {
                continue
            }

            $principalId = ([string]$assignment.principalId).ToLowerInvariant()
            $roleDefinitionId = [string]$assignment.roleDefinitionId

            $roleName = "Eligible: Directory role"
            if ($roleDefinitions.ContainsKey($roleDefinitionId)) {
                $roleName = "Eligible: $($roleDefinitions[$roleDefinitionId])"
            }

            if (-not $byId.ContainsKey($principalId)) {
                $byId[$principalId] = @()
            }
            if ($byId[$principalId] -notcontains $roleName) {
                $byId[$principalId] += $roleName
            }
        }
    }
    catch {
        Add-Warn "Could not read eligible role schedule instances: $($_.Exception.Message)"
    }

    return @{
        ById = $byId
        ByUpn = $byUpn
    }
}

function New-Identity-Row {
    param(
        [object]$User,
        [hashtable]$PrivById,
        [hashtable]$PrivByUpn,
        [string[]]$BreakGlassList,
        [string[]]$ServiceList,
        [object[]]$RecentSignals,
        [string]$ScopeReason
    )

    $id = ([string]$User.id).ToLowerInvariant()
    $upn = ([string]$User.userPrincipalName).ToLowerInvariant()

    $roles = @()

    if ($id -and $PrivById.ContainsKey($id)) {
        $roles += @($PrivById[$id])
    }

    if ($upn -and $PrivByUpn.ContainsKey($upn)) {
        $roles += @($PrivByUpn[$upn])
    }

    $roles = @($roles | Where-Object { $_ } | Select-Object -Unique)

    $userSignals = @(
        $RecentSignals | Where-Object {
            ([string]$_.userId).ToLowerInvariant() -eq $id -or
            ([string]$_.userPrincipalName).ToLowerInvariant() -eq $upn
        }
    )

    $successSignals = @(
        $userSignals | Where-Object {
            $null -eq $_.status.errorCode -or $_.status.errorCode -eq 0
        }
    )

    return [pscustomobject]@{
        id = $User.id
        userPrincipalName = $User.userPrincipalName
        displayName = $User.displayName
        userType = $User.userType
        accountEnabled = $User.accountEnabled
        isPrivileged = ($roles.Count -gt 0)
        privilegedRoles = ($roles -join ", ")
        isGuest = ([string]$User.userType -eq "Guest")
        isServiceLike = (Has-Keyword -User $User -Keywords $ServiceList)
        isBreakGlass = (Has-Keyword -User $User -Keywords $BreakGlassList)
        recentRelevantSignIns = $userSignals.Count
        recentSuccessfulRelevantSignIns = $successSignals.Count
        scopeReason = $ScopeReason
    }
}

function Get-Policy-Overlap {
    param(
        [object[]]$Policies,
        [string]$Control,
        [string]$Target,
        [string]$Resource,
        [string]$Condition
    )

    $rows = @()

    foreach ($policy in $Policies) {
        $state = [string]$policy.state
        $score = 0

        $grantText = ""
        if ($policy.grantControls -and $policy.grantControls.builtInControls) {
            $grantText = (@($policy.grantControls.builtInControls) -join " ").ToLowerInvariant()
        }

        $clientText = ""
        if ($policy.conditions -and $policy.conditions.clientAppTypes) {
            $clientText = (@($policy.conditions.clientAppTypes) -join " ").ToLowerInvariant()
        }

        if ($Control.ToLowerInvariant().Contains("block") -and $grantText.Contains("block")) {
            $score++
        }
        if ($Control.ToLowerInvariant().Contains("mfa") -and ($grantText.Contains("mfa") -or $grantText.Contains("multifactor"))) {
            $score++
        }
        if ($Control.ToLowerInvariant().Contains("compliant") -and $grantText.Contains("compliant")) {
            $score++
        }
        if ($Control.ToLowerInvariant().Contains("legacy") -and ($clientText.Contains("other") -or $clientText.Contains("exchange"))) {
            $score++
        }

        if ($policy.conditions -and $policy.conditions.users) {
            $users = $policy.conditions.users

            if ($users.includeUsers -contains "All") {
                $score++
            }
            if ($Target -eq "Privileged users" -and $users.includeRoles) {
                $score++
            }
            if ($Target -eq "Guests / external users" -and $users.includeGuestsOrExternalUsers) {
                $score++
            }
        }

        if ($policy.conditions -and $policy.conditions.applications) {
            $apps = @($policy.conditions.applications.includeApplications)
            $appsText = ($apps -join " ").ToLowerInvariant()

            if ($apps -contains "All") {
                $score++
            }
            elseif ($Resource -eq "Azure Management" -and $appsText.Contains("797f4846-ba00-4fd7-ba43-dac1f8f63013")) {
                $score++
            }
            elseif ($Resource -eq "Exchange Online" -and $appsText.Contains("00000002-0000-0ff1-ce00-000000000000")) {
                $score++
            }
        }

        if ($state -eq "enabled") {
            $score++
        }

        if ($score -gt 0) {
            $rows += [pscustomobject]@{
                policyId = $policy.id
                policyName = $policy.displayName
                state = $state
                overlapType = if ($score -ge 4) { "Strong" } else { "Potential" }
                score = $score
                grantControls = $grantText
                clientAppTypes = $clientText
            }
        }
    }

    return @($rows | Sort-Object -Property score -Descending)
}

try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
}
catch {
    throw "Microsoft Graph PowerShell module is required. Install it with: Install-Module Microsoft.Graph -Scope CurrentUser"
}

$scopes = @(
    "Policy.Read.All",
    "Directory.Read.All",
    "User.Read.All",
    "Group.Read.All",
    "AuditLog.Read.All",
    "RoleManagement.Read.Directory"
)

Connect-MgGraph -Scopes $scopes -ContextScope CurrentUser -NoWelcome | Out-Null
$context = Get-MgContext
$tenantId = $context.TenantId

$reportDir = Join-Path $ProjectRoot "powershell\Reports\Simulation"
$htmlDir = Join-Path $reportDir "Html"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null

$generatedAt = (Get-Date).ToUniversalTime()
$startUtc = $generatedAt.AddDays(-1 * [Math]::Abs($LookbackDays)).ToString("yyyy-MM-ddTHH:mm:ssZ")

$breakGlassList = Split-Csv $BreakGlassKeywords
$serviceList = Split-Csv $ServiceAccountKeywords
$selectedUserList = Split-Csv $SelectedUsers
$excludedUserList = Split-Csv $ExcludedUsers
$excludedGroupList = Split-Csv $ExcludedGroups

$users = Graph-All "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName,displayName,userType,accountEnabled&`$top=999"
$enabledUsers = @($users | Where-Object { $_.accountEnabled -eq $true })

$policies = Graph-All "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

$priv = Get-Privileged-Maps
$privById = $priv.ById
$privByUpn = $priv.ByUpn

$signIns = Graph-All "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $startUtc&`$top=999"

$scopeUsers = @()
$scopeReason = ""

switch ($TargetScope) {
    "All users" {
        $scopeUsers = @($enabledUsers)
        $scopeReason = "All enabled users"
    }
    "Guests / external users" {
        $scopeUsers = @($enabledUsers | Where-Object { $_.userType -eq "Guest" })
        $scopeReason = "Guest or external users"
    }
    "Privileged users" {
        $scopeUsers = @(
            $enabledUsers | Where-Object {
                $id = ([string]$_.id).ToLowerInvariant()
                $upn = ([string]$_.userPrincipalName).ToLowerInvariant()
                $privById.ContainsKey($id) -or $privByUpn.ContainsKey($upn)
            }
        )
        $scopeReason = "Users assigned or eligible for Entra directory roles"
    }
    "Selected users" {
        $lookup = @{}
        foreach ($u in $selectedUserList) {
            $lookup[$u.ToLowerInvariant()] = $true
        }
        $scopeUsers = @(
            $enabledUsers | Where-Object {
                $lookup.ContainsKey(([string]$_.userPrincipalName).ToLowerInvariant())
            }
        )
        $scopeReason = "Selected user UPNs"
    }
    "Selected group" {
        if ([string]::IsNullOrWhiteSpace($SelectedGroup)) {
            Add-Warn "Selected group target was chosen but no group name or ID was provided."
            $scopeUsers = @()
        }
        else {
            Add-Warn "Selected group resolution is not implemented in this safe engine version. Use Selected users for now."
            $scopeUsers = @()
        }
        $scopeReason = "Selected group"
    }
    default {
        $scopeUsers = @($enabledUsers)
        $scopeReason = "Defaulted to all enabled users"
    }
}

$scopeIds = @{}
foreach ($u in $scopeUsers) {
    if ($u.id) {
        $scopeIds[([string]$u.id).ToLowerInvariant()] = $true
    }
}

$recentRelevant = @(
    $signIns | Where-Object {
        $uid = ([string]$_.userId).ToLowerInvariant()
        $inScope = $scopeIds.ContainsKey($uid)
        $inScope -and (Match-Resource -SignIn $_ -Resource $ResourceScope) -and (Match-Client -SignIn $_ -Condition $ClientCondition)
    }
)

$isLegacySimulation = (
    $ProposedControl.ToLowerInvariant().Contains("legacy") -or
    $ClientCondition.ToLowerInvariant().Contains("legacy")
)

if ($isLegacySimulation) {
    $recentRelevant = @($recentRelevant | Where-Object { Is-Legacy-Signal -SignIn $_ })
}

$identityRows = @()
foreach ($user in $scopeUsers) {
    $identityRows += New-Identity-Row `
        -User $user `
        -PrivById $privById `
        -PrivByUpn $privByUpn `
        -BreakGlassList $breakGlassList `
        -ServiceList $serviceList `
        -RecentSignals $recentRelevant `
        -ScopeReason $scopeReason
}

if ($isLegacySimulation) {
    $legacyKeys = @{}
    foreach ($s in $recentRelevant) {
        if ($s.userId) {
            $legacyKeys[([string]$s.userId).ToLowerInvariant()] = $true
        }
        if ($s.userPrincipalName) {
            $legacyKeys[([string]$s.userPrincipalName).ToLowerInvariant()] = $true
        }
    }

    $affectedRows = @(
        $identityRows | Where-Object {
            $legacyKeys.ContainsKey(([string]$_.id).ToLowerInvariant()) -or
            $legacyKeys.ContainsKey(([string]$_.userPrincipalName).ToLowerInvariant())
        }
    )
}
else {
    $affectedRows = @($identityRows)
}

$riskyRows = @()
foreach ($identity in $identityRows) {
    $reasons = @()

    if ($identity.isPrivileged) {
        $reasons += "Privileged account in scope"
    }
    if ($identity.isBreakGlass) {
        $reasons += "Break-glass-like account"
    }
    if ($identity.isServiceLike) {
        $reasons += "Service-like account"
    }
    if ($ProposedControl -eq "Block access" -and $identity.recentSuccessfulRelevantSignIns -gt 0) {
        $reasons += "Recent successful sign-ins may be interrupted by block control"
    }

    if ($reasons.Count -gt 0) {
        $riskyRows += [pscustomobject]@{
            id = $identity.id
            userPrincipalName = $identity.userPrincipalName
            displayName = $identity.displayName
            userType = $identity.userType
            privilegedRoles = $identity.privilegedRoles
            reasons = ($reasons -join "; ")
            recentRelevantSignIns = $identity.recentRelevantSignIns
            recentSuccessfulRelevantSignIns = $identity.recentSuccessfulRelevantSignIns
        }
    }
}

$overlapRows = Get-Policy-Overlap -Policies $policies -Control $ProposedControl -Target $TargetScope -Resource $ResourceScope -Condition $ClientCondition

$privilegedCount = @($identityRows | Where-Object { $_.isPrivileged }).Count
$guestCount = @($identityRows | Where-Object { $_.isGuest }).Count
$serviceCount = @($identityRows | Where-Object { $_.isServiceLike }).Count
$breakGlassCount = @($identityRows | Where-Object { $_.isBreakGlass }).Count

$impact = "LOW"
$confidence = "MEDIUM"
$rollout = "Pilot first"

if ($isLegacySimulation) {
    if ($recentRelevant.Count -eq 0) {
        $impact = "LOW"
        $confidence = "LOW"
        $rollout = "Report-only first or extend lookback"
        Add-Rec "No recent legacy authentication activity was detected in the selected lookback period."
        Add-Rec "Use a 30-day lookback before enforcement to reduce the chance of missing infrequent legacy usage."
        Add-Rec "Keep the policy in report-only mode first and monitor legacy client sign-ins."
    }
    elseif ($affectedRows.Count -ge 10 -or $privilegedCount -gt 0 -or $serviceCount -gt 0) {
        $impact = "HIGH"
        $confidence = "MEDIUM"
        $rollout = "Report-only first"
    }
    elseif ($affectedRows.Count -ge 3) {
        $impact = "MEDIUM"
        $confidence = "MEDIUM"
        $rollout = "Pilot first"
    }
    else {
        $impact = "LOW"
        $confidence = "MEDIUM"
        $rollout = "Pilot carefully"
    }
}
else {
    if ($ProposedControl -eq "Block access" -and $TargetScope -eq "All users" -and $ResourceScope -eq "All cloud apps") {
        $impact = "HIGH"
        $rollout = "Report-only first"
    }
    elseif ($ProposedControl -eq "Block access" -and ($affectedRows.Count -ge 10 -or $privilegedCount -gt 0)) {
        $impact = "HIGH"
        $rollout = "Report-only first"
    }
    elseif ($affectedRows.Count -ge 10 -or $privilegedCount -gt 0 -or $serviceCount -gt 0) {
        $impact = "MEDIUM"
        $rollout = "Pilot first"
    }
    else {
        $impact = "LOW"
        $rollout = "Pilot carefully"
    }

    if ($recentRelevant.Count -gt 0) {
        $confidence = "MEDIUM"
    }
    else {
        $confidence = "LOW"
    }
}

if ($privilegedCount -gt 0) {
    Add-Rec "Privileged users are in scope. Review carefully to avoid administrator lockout."
}
if ($serviceCount -gt 0) {
    Add-Rec "Review service-like accounts before enforcement because automated workflows may be affected."
}
if ($breakGlassCount -gt 0) {
    Add-Rec "Exclude break-glass accounts intentionally and document the exception."
}
if ($overlapRows.Count -gt 0) {
    Add-Rec "A similar enabled policy already exists. Confirm whether the proposed change is redundant or intentionally stricter."
}

Add-Rec "Start in report-only mode before enforcing this proposed Conditional Access change."
Add-Rec "Pilot the policy with a small controlled group before broad rollout."
Add-Rec "Monitor Entra sign-in logs during rollout and keep rollback instructions ready."

if ($isLegacySimulation -and $recentRelevant.Count -eq 0) {
    $summary = "ZTVP found $($identityRows.Count) identities in the proposed policy scope, but no recent legacy authentication activity was detected in the selected $LookbackDays-day lookback period. Immediate disruption appears low, but the result has low confidence because legacy usage may exist outside the selected window or in unavailable logs."
}
elseif ($isLegacySimulation) {
    $summary = "ZTVP found $($identityRows.Count) identities in the proposed policy scope and $($affectedRows.Count) identities with recent legacy authentication activity. These identities may be affected if legacy authentication is blocked."
}
else {
    $summary = "Based on current tenant configuration and recent signals, ZTVP estimates that this proposed Conditional Access policy may affect $($affectedRows.Count) identities. Review service-like accounts, privileged users, exclusions, and overlapping policies before production enforcement."
}

$confidenceReason = switch ($confidence) {
    "HIGH" { "High confidence means ZTVP resolved the target scope and found enough recent tenant signals to support the prediction." }
    "MEDIUM" { "Medium confidence means ZTVP resolved useful tenant data, but some conditions may still depend on assumptions, exclusions, device state, location, or incomplete logs." }
    default { "Low confidence means ZTVP could not find enough recent or complete evidence. Review with longer lookback, report-only mode, or manual verification." }
}

$rolloutExplanation = if ($rollout.ToLowerInvariant().Contains("report-only")) {
    "Report-only first means create or test the policy without enforcing it, then review sign-in impact before blocking or requiring controls."
}
elseif ($rollout.ToLowerInvariant().Contains("pilot")) {
    "Pilot first means test the policy on a small controlled group before applying it broadly to production users."
}
else {
    "Rollout mode explains the safest way to test or deploy the proposed policy."
}

$recentSignalSummary = @(
    $recentRelevant | Select-Object `
        createdDateTime,
        userId,
        userPrincipalName,
        appDisplayName,
        resourceDisplayName,
        clientAppUsed,
        @{Name="statusCode";Expression={ if ($_.status) { $_.status.errorCode } else { $null } }},
        @{Name="statusReason";Expression={ if ($_.status) { $_.status.failureReason } else { $null } }}
)

$report = [ordered]@{
    feature = "Simulation - Conditional Access Policy Change Sandbox"
    simulationType = "PolicyChangeImpact"
    generatedAtUtc = $generatedAt.ToString("o")
    tenantId = $tenantId
    inputs = [ordered]@{
        proposedControl = $ProposedControl
        targetScope = $TargetScope
        resourceScope = $ResourceScope
        clientCondition = $ClientCondition
        lookbackDays = $LookbackDays
        selectedGroup = $SelectedGroup
        selectedUsers = $selectedUserList
        excludedUsers = $excludedUserList
        excludedGroups = $excludedGroupList
    }
    prediction = [ordered]@{
        predictedImpact = $impact
        confidence = $confidence
        confidenceReason = $confidenceReason
        summary = $summary
        recommendedRolloutMode = $rollout
        rolloutExplanation = $rolloutExplanation
    }
    counts = [ordered]@{
        legacyAuthSimulation = $isLegacySimulation
        inScopeIdentities = $identityRows.Count
        potentiallyAffectedIdentities = $affectedRows.Count
        recentlyAffectedIdentities = if ($isLegacySimulation) { $affectedRows.Count } else { $null }
        recentLegacyAuthenticationSignals = if ($isLegacySimulation) { $recentRelevant.Count } else { $null }
        privilegedUsersInScope = $privilegedCount
        guestUsersInScope = $guestCount
        serviceLikeAccountsDetected = $serviceCount
        breakGlassAccountsDetected = $breakGlassCount
        excludedIdentities = $excludedUserList.Count
        recentRelevantSignIns = $recentRelevant.Count
        overlappingPolicies = $overlapRows.Count
    }
    affectedIdentities = @($affectedRows)
    scopeIdentities = @($identityRows)
    riskyIdentities = @($riskyRows)
    existingPolicyOverlap = @($overlapRows)
    exclusionsDetected = @()
    recentSignalSummary = @($recentSignalSummary)
    clientOrProtocolBreakdown = @{}
    recommendations = @($script:recommendations)
    limitations = @($script:limitations + $script:warnings)
    rawEvaluation = [ordered]@{
        privilegedPrincipalIdsDetected = $privById.Keys.Count
        privilegedUpnsDetected = $privByUpn.Keys.Count
        totalUsersRead = $users.Count
        enabledUsersRead = $enabledUsers.Count
        signInsRead = $signIns.Count
        relevantSignIns = $recentRelevant.Count
        policiesRead = $policies.Count
        warnings = @($script:warnings)
    }
}

$jsonPath = Join-Path $reportDir "CA-Policy-Change-Sandbox-result.json"
$htmlPath = Join-Path $htmlDir "CA-Policy-Change-Sandbox-result.html"

$report | ConvertTo-Json -Depth 25 | Set-Content -Path $jsonPath -Encoding UTF8

$encSummary = [System.Net.WebUtility]::HtmlEncode($summary)
$encImpact = [System.Net.WebUtility]::HtmlEncode($impact)
$encConfidence = [System.Net.WebUtility]::HtmlEncode($confidence)
$encRollout = [System.Net.WebUtility]::HtmlEncode($rollout)
$recHtml = ($script:recommendations | ForEach-Object { "<li>$([System.Net.WebUtility]::HtmlEncode($_))</li>" }) -join "`n"

$html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>ZTVP Simulation Report</title>
<style>
body { font-family: Arial, sans-serif; background:#f8fafc; color:#0f172a; margin:32px; }
.card { background:white; border:1px solid #dbe3ef; border-radius:14px; padding:18px; margin-bottom:18px; }
.badge { display:inline-block; background:#dbeafe; border-radius:10px; padding:8px 12px; font-weight:bold; }
table { width:100%; border-collapse:collapse; }
td, th { border:1px solid #e2e8f0; padding:8px; text-align:left; }
th { background:#eff6ff; }
.warning { color:#7c2d12; font-weight:bold; }
</style>
</head>
<body>
<h1>Simulation — Conditional Access Policy Change Sandbox</h1>
<div class="card">
<p class="warning">Simulation prediction only. No policy was created, modified, or enforced.</p>
<p><strong>Predicted impact:</strong> <span class="badge">$encImpact</span></p>
<p><strong>Confidence:</strong> $encConfidence</p>
<p><strong>Recommended rollout:</strong> $encRollout</p>
</div>
<div class="card">
<h2>Executive Summary</h2>
<p>$encSummary</p>
</div>
<div class="card">
<h2>Key Counts</h2>
<table>
<tr><td>In-scope identities</td><td>$($identityRows.Count)</td></tr>
<tr><td>Potentially affected identities</td><td>$($affectedRows.Count)</td></tr>
<tr><td>Privileged users in scope</td><td>$privilegedCount</td></tr>
<tr><td>Guest users in scope</td><td>$guestCount</td></tr>
<tr><td>Service-like accounts</td><td>$serviceCount</td></tr>
<tr><td>Overlapping policies</td><td>$($overlapRows.Count)</td></tr>
</table>
</div>
<div class="card">
<h2>Recommendations</h2>
<ul>
$recHtml
</ul>
</div>
</body>
</html>
"@

$html | Set-Content -Path $htmlPath -Encoding UTF8

Write-Host "ZTVP Simulation completed."
Write-Host "JSON report: $jsonPath"
Write-Host "HTML report: $htmlPath"
