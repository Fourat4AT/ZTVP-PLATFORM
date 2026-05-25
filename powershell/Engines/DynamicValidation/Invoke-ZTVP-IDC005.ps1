param(
    [ValidateSet("AUTO_DETECT","NOT_RECORDED","ACCESS_BLOCKED","REACHED_ADMIN_PORTAL","SIGNIN_INTERRUPTED","INVITATION_NOT_REDEEMED")]
    [string]$ObservedOutcome = "AUTO_DETECT",

    [int]$LookbackMinutes = 240,

    [int]$EvidenceWaitSeconds = 60,

    [string]$EvidenceStartUtc = ""
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "AuditLog.Read.All",
    "Directory.Read.All",
    "User.Read.All",
    "Policy.Read.All"
)

function Get-ZTVPValue {
    param([object]$Object, [string]$Name)

    if ($null -eq $Object) { return $null }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ([string]$key -eq $Name) { return $Object[$key] }
        }
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }

    return $null
}

function ConvertTo-ZTVPArray {
    param([object]$Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Array]) { return @($Value) }
    return @($Value)
}

function Ensure-ZTVPGraphConnection {
    param([string[]]$Scopes)

    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    $needReconnect = $false

    if (-not $ctx) {
        $needReconnect = $true
    }
    else {
        $currentScopes = @()

        if ($ctx.Scopes) {
            $currentScopes = @($ctx.Scopes | ForEach-Object { $_.ToLowerInvariant() })
        }

        foreach ($scope in $Scopes) {
            if ($currentScopes -notcontains $scope.ToLowerInvariant()) {
                $needReconnect = $true
            }
        }
    }

    if ($needReconnect) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
        Connect-MgGraph -Scopes $Scopes -NoWelcome | Out-Null
        $ctx = Get-MgContext
    }

    return $ctx
}

function Invoke-ZTVPPagedGraphQuery {
    param([string]$Uri, [int]$MaxPages = 30)

    $items = @()
    $page = 0
    $nextUri = $Uri

    while ($nextUri -and $page -lt $MaxPages) {
        $page++
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri
        $value = Get-ZTVPValue -Object $response -Name "value"

        if ($value) { $items += @($value) }

        $nextLink = Get-ZTVPValue -Object $response -Name "@odata.nextLink"

        if ([string]::IsNullOrWhiteSpace([string]$nextLink)) {
            $nextUri = $null
        }
        else {
            $nextUri = [string]$nextLink
        }
    }

    return $items
}

function Convert-ZTVPGraphDateTimeUtc {
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [DateTimeOffset]) {
        return ([DateTimeOffset]$Value).ToUniversalTime()
    }

    if ($Value -is [datetime]) {
        return ([DateTimeOffset]([datetime]$Value)).ToUniversalTime()
    }

    $text = [string]$Value

    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    if ($text -match "/Date\((\d+)\)/") {
        try {
            $milliseconds = [int64]$Matches[1]
            return ([DateTimeOffset]::FromUnixTimeMilliseconds($milliseconds)).ToUniversalTime()
        }
        catch {
            return $null
        }
    }

    try {
        return ([DateTimeOffset]::Parse(
            $text,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal
        )).ToUniversalTime()
    }
    catch {
        try {
            return ([DateTimeOffset]([datetime]::Parse($text))).ToUniversalTime()
        }
        catch {
            return $null
        }
    }
}

function Format-ZTVPDateTimeUtc {
    param([object]$Value)

    $dto = Convert-ZTVPGraphDateTimeUtc -Value $Value

    if ($null -eq $dto) {
        if ($null -eq $Value) { return $null }
        return [string]$Value
    }

    return $dto.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss UTC")
}

function Format-ZTVPDateTimeIsoUtc {
    param([object]$Value)

    $dto = Convert-ZTVPGraphDateTimeUtc -Value $Value

    if ($null -eq $dto) { return $null }

    return $dto.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Get-ZTVPGuestUserFresh {
    param([string]$UserId)

    if ([string]::IsNullOrWhiteSpace($UserId)) { return $null }

    try {
        return Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$UserId?`$select=id,userPrincipalName,displayName,mail,userType,externalUserState,accountEnabled"
    }
    catch {
        return $null
    }
}

function New-ZTVPSignInUri {
    param([string]$Filter)

    $encodedFilter = [System.Uri]::EscapeDataString($Filter)
    return "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$encodedFilter"
}

function Escape-ZTVPODataString {
    param([string]$Value)
    return ([string]$Value).Replace("'", "''")
}

function Get-ZTVPNestedStrings {
    param([object]$Object, [int]$Depth = 0)

    if ($null -eq $Object -or $Depth -gt 7) { return @() }

    if ($Object -is [string]) { return @([string]$Object) }

    if ($Object -is [ValueType]) { return @([string]$Object) }

    $items = @()

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            $items += @(Get-ZTVPNestedStrings -Object $Object[$key] -Depth ($Depth + 1))
        }

        return $items
    }

    if ($Object -is [System.Collections.IEnumerable]) {
        foreach ($item in $Object) {
            $items += @(Get-ZTVPNestedStrings -Object $item -Depth ($Depth + 1))
        }

        return $items
    }

    foreach ($property in $Object.PSObject.Properties) {
        $items += @(Get-ZTVPNestedStrings -Object $property.Value -Depth ($Depth + 1))
    }

    return $items
}

function Resolve-ZTVPGuestMatch {
    param(
        [object]$SignIn,
        [string]$ExternalEmail,
        [string]$GuestUpn,
        [string]$GuestUserId
    )

    $externalLower = $ExternalEmail.Trim().ToLowerInvariant()
    $guestUpnLower = $GuestUpn.Trim().ToLowerInvariant()
    $guestIdLower = $GuestUserId.Trim().ToLowerInvariant()

    $matched = @()

    $userPrincipalName = ([string](Get-ZTVPValue -Object $SignIn -Name "userPrincipalName")).Trim()
    $userId = ([string](Get-ZTVPValue -Object $SignIn -Name "userId")).Trim()

    if (-not [string]::IsNullOrWhiteSpace($guestIdLower) -and $userId.ToLowerInvariant() -eq $guestIdLower) {
        $matched += "guestId"
    }

    if (-not [string]::IsNullOrWhiteSpace($externalLower) -and $userPrincipalName.ToLowerInvariant() -eq $externalLower) {
        $matched += "externalEmail"
    }

    if (-not [string]::IsNullOrWhiteSpace($guestUpnLower) -and $userPrincipalName.ToLowerInvariant() -eq $guestUpnLower) {
        $matched += "guestUpn"
    }

    $alternateFields = @(
        "alternateSignInName",
        "originalUserPrincipalName",
        "signInIdentifier",
        "userSignInName",
        "loginHint",
        "uniqueTokenIdentifier"
    )

    foreach ($field in $alternateFields) {
        $value = ([string](Get-ZTVPValue -Object $SignIn -Name $field)).Trim().ToLowerInvariant()

        if ([string]::IsNullOrWhiteSpace($value)) { continue }

        if (-not [string]::IsNullOrWhiteSpace($externalLower) -and $value -eq $externalLower) {
            $matched += "externalEmail"
        }

        if (-not [string]::IsNullOrWhiteSpace($guestUpnLower) -and $value -eq $guestUpnLower) {
            $matched += "guestUpn"
        }

        if (-not [string]::IsNullOrWhiteSpace($guestIdLower) -and $value -eq $guestIdLower) {
            $matched += "guestId"
        }
    }

    $allStrings = @(Get-ZTVPNestedStrings -Object $SignIn)

    foreach ($text in $allStrings) {
        $value = ([string]$text).Trim().ToLowerInvariant()

        if ([string]::IsNullOrWhiteSpace($value)) { continue }

        if (-not [string]::IsNullOrWhiteSpace($externalLower) -and ($value -eq $externalLower -or $value.Contains($externalLower))) {
            $matched += "externalEmail"
        }

        if (-not [string]::IsNullOrWhiteSpace($guestUpnLower) -and ($value -eq $guestUpnLower -or $value.Contains($guestUpnLower))) {
            $matched += "guestUpn"
        }

        if (-not [string]::IsNullOrWhiteSpace($guestIdLower) -and ($value -eq $guestIdLower -or $value.Contains($guestIdLower))) {
            $matched += "guestId"
        }
    }

    $matched = @($matched | Sort-Object -Unique)

    return [PSCustomObject]@{
        matched = ($matched.Count -gt 0)
        matched_identifiers = @($matched)
        matched_identifier = if ($matched.Count -gt 0) { ($matched -join ", ") } else { "" }
    }
}

function Get-ZTVPSignInsSince {
    param(
        [DateTimeOffset]$StartUtcDate,
        [string]$ExternalEmail,
        [string]$GuestUpn,
        [string]$GuestUserId
    )

    $startUtc = $StartUtcDate.UtcDateTime.ToString("o")
    $filters = @()

    # Broad time-window queries are the primary source. Guest matching is done client-side.
    $filters += "createdDateTime ge $startUtc"
    $filters += "createdDateTime ge $startUtc and signInEventTypes/any(t: t eq 'interactiveUser')"
    $filters += "createdDateTime ge $startUtc and signInEventTypes/any(t: t eq 'nonInteractiveUser')"

    # Targeted queries are only supplemental, so busy tenants do not page past the guest.
    if (-not [string]::IsNullOrWhiteSpace($GuestUserId)) {
        $filters += "createdDateTime ge $startUtc and userId eq '$(Escape-ZTVPODataString -Value $GuestUserId)'"
    }

    if (-not [string]::IsNullOrWhiteSpace($GuestUpn)) {
        $filters += "createdDateTime ge $startUtc and userPrincipalName eq '$(Escape-ZTVPODataString -Value $GuestUpn)'"
    }

    if (-not [string]::IsNullOrWhiteSpace($ExternalEmail)) {
        $filters += "createdDateTime ge $startUtc and userPrincipalName eq '$(Escape-ZTVPODataString -Value $ExternalEmail)'"
    }

    $all = @()

    foreach ($filter in $filters) {
        $uri = New-ZTVPSignInUri -Filter $filter

        try {
            $all += @(Invoke-ZTVPPagedGraphQuery -Uri $uri -MaxPages 30)
        }
        catch {
            Write-Host "Sign-in query skipped: $filter"
            Write-Host "Reason: $($_.Exception.Message)"
        }
    }

    $seen = @{}
    $deduped = @()

    foreach ($item in $all) {
        $id = [string](Get-ZTVPValue -Object $item -Name "id")

        if ([string]::IsNullOrWhiteSpace($id)) {
            $id = ([string](Get-ZTVPValue -Object $item -Name "createdDateTime")) + "|" +
                ([string](Get-ZTVPValue -Object $item -Name "userPrincipalName")) + "|" +
                ([string](Get-ZTVPValue -Object $item -Name "appDisplayName")) + "|" +
                ([string](Get-ZTVPValue -Object $item -Name "resourceDisplayName"))
        }

        if (-not $seen.ContainsKey($id)) {
            $seen[$id] = $true
            $deduped += $item
        }
    }

    return $deduped
}

function Convert-ZTVPSignInType {
    param([object]$SignIn)

    $isInteractive = Get-ZTVPValue -Object $SignIn -Name "isInteractive"
    $eventTypes = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $SignIn -Name "signInEventTypes"))
    $eventText = ($eventTypes -join ",")

    if ($eventText -match "nonInteractiveUser") { return "non-interactive" }
    if ($eventText -match "interactiveUser") { return "interactive" }

    if ($null -ne $isInteractive) {
        if ([bool]$isInteractive) { return "interactive" }
        return "non-interactive"
    }

    return "unknown"
}

function Convert-ZTVPPolicyEvidence {
    param([object]$Policies)

    $policyObjects = @()
    $allPolicyNames = @()
    $blockingPolicyNames = @()

    foreach ($policy in @(ConvertTo-ZTVPArray $Policies)) {
        if ($null -eq $policy) { continue }

        $policyName = [string](Get-ZTVPValue -Object $policy -Name "displayName")
        $policyResult = [string](Get-ZTVPValue -Object $policy -Name "result")
        $grantControls = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $policy -Name "enforcedGrantControls"))
        $sessionControls = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $policy -Name "enforcedSessionControls"))

        if (-not [string]::IsNullOrWhiteSpace($policyName)) {
            $allPolicyNames += $policyName
        }

        $policyText = "$policyName $policyResult $($grantControls -join ' ') $($sessionControls -join ' ')"
        $resultLower = $policyResult.Trim().ToLowerInvariant()

        $treatAsBlocking = (
            $resultLower -match "failure|block|denied" -or
            (($grantControls -join ",") -match "block|Block") -or
            ($resultLower -match "notapplied" -and $policyText -match "block|Block|failure|Failure")
        )

        if ($treatAsBlocking -and -not [string]::IsNullOrWhiteSpace($policyName)) {
            $blockingPolicyNames += $policyName
        }

        $policyObjects += [PSCustomObject]@{
            displayName = $policyName
            result = $policyResult
            enforcedGrantControls = @($grantControls)
            enforcedSessionControls = @($sessionControls)
            treatedAsBlocking = $treatAsBlocking
        }
    }

    return [PSCustomObject]@{
        policy_objects = @($policyObjects)
        all_policy_names = @($allPolicyNames | Sort-Object -Unique)
        blocking_policy_names = @($blockingPolicyNames | Sort-Object -Unique)
        blocking_policy_applied = ($blockingPolicyNames.Count -gt 0)
    }
}

function Convert-ZTVPGuestSignInEvidence {
    param(
        [object[]]$SignIns,
        [string]$ExternalEmail,
        [string]$GuestUpn,
        [string]$GuestUserId
    )

    $rows = @()

    foreach ($signIn in $SignIns) {
        $match = Resolve-ZTVPGuestMatch -SignIn $signIn -ExternalEmail $ExternalEmail -GuestUpn $GuestUpn -GuestUserId $GuestUserId

        if ($match.matched -ne $true) { continue }

        $createdDto = Convert-ZTVPGraphDateTimeUtc -Value (Get-ZTVPValue -Object $signIn -Name "createdDateTime")

        if ($null -eq $createdDto) { continue }

        $statusObj = Get-ZTVPValue -Object $signIn -Name "status"
        $statusCode = Get-ZTVPValue -Object $statusObj -Name "errorCode"
        $failureReason = [string](Get-ZTVPValue -Object $statusObj -Name "failureReason")
        $additionalDetails = [string](Get-ZTVPValue -Object $statusObj -Name "additionalDetails")
        $statusText = [string]$statusObj

        $app = [string](Get-ZTVPValue -Object $signIn -Name "appDisplayName")
        $resource = [string](Get-ZTVPValue -Object $signIn -Name "resourceDisplayName")
        $client = [string](Get-ZTVPValue -Object $signIn -Name "clientAppUsed")
        $caStatus = [string](Get-ZTVPValue -Object $signIn -Name "conditionalAccessStatus")
        $policies = Get-ZTVPValue -Object $signIn -Name "appliedConditionalAccessPolicies"
        $policyEvidence = Convert-ZTVPPolicyEvidence -Policies $policies

        $appResource = "$app $resource"
        $appContainsPortal = ($app -match "Azure Portal|Azure Portal Fx")
        $resourceIsGraph = ($resource -match "^Microsoft Graph$")

        $isAdminPortal = (
            $appResource -match "Azure Portal" -or
            $appResource -match "Azure Portal Fx" -or
            $appResource -match "Azure Resource Manager" -or
            $appResource -match "AzureCopilotServiceProd" -or
            ($appContainsPortal -and $resourceIsGraph)
        )

        $isInvitation = (
            $appResource -match "Microsoft Invitation Acceptance Portal" -or
            $appResource -match "Invitation" -or
            $appResource -match "B2B redemption"
        )

        $evidenceCategory = "OTHER_GUEST"

        if ($isAdminPortal) {
            $evidenceCategory = "ADMIN_PORTAL"
        }
        elseif ($isInvitation) {
            $evidenceCategory = "INVITATION_REDEMPTION"
        }

        $statusCodeText = ([string]$statusCode).Trim()
        $statusCodeIsZero = (-not [string]::IsNullOrWhiteSpace($statusCodeText) -and $statusCodeText -eq "0")
        $statusCodeNonZero = (-not [string]::IsNullOrWhiteSpace($statusCodeText) -and $statusCodeText -ne "0")
        $success = ($statusCodeIsZero -or $statusText -match "Success" -or $caStatus -match "^success$")

        $blockedOrInterruptedSignal = (
            $statusCodeNonZero -or
            $caStatus -match "failure|interrupted" -or
            $policyEvidence.blocking_policy_applied -eq $true -or
            $failureReason -match "blocked|denied|interrupt|Conditional Access|does not allow token issuance|access policy|not allowed|failure|must enroll|multi-factor|MFA|AADSTS" -or
            $additionalDetails -match "blocked|denied|interrupt|Conditional Access|not allowed|failure|must enroll|multi-factor|MFA|AADSTS"
        )

        $resultCategory = "OBSERVED"

        if ($isAdminPortal -and $success) {
            $resultCategory = "SUCCESS"
        }
        elseif ($isAdminPortal -and $blockedOrInterruptedSignal) {
            $resultCategory = "BLOCKED_OR_INTERRUPTED"
        }
        elseif ($blockedOrInterruptedSignal) {
            $resultCategory = "BLOCKED_OR_INTERRUPTED"
        }

        $signInType = Convert-ZTVPSignInType -SignIn $signIn
        $isInteractive = Get-ZTVPValue -Object $signIn -Name "isInteractive"

        $row = [PSCustomObject]@{
            createdDateTimeUtc = Format-ZTVPDateTimeUtc -Value $createdDto
            createdDateTimeIsoUtc = Format-ZTVPDateTimeIsoUtc -Value $createdDto
            createdDateTimeTicks = $createdDto.UtcTicks
            signInType = $signInType
            evidenceSource = if ($signInType -eq "non-interactive") { "non-interactive sign-in log" } elseif ($signInType -eq "interactive") { "interactive sign-in log" } else { "sign-in log" }
            isInteractive = $isInteractive
            userPrincipalName = Get-ZTVPValue -Object $signIn -Name "userPrincipalName"
            userId = Get-ZTVPValue -Object $signIn -Name "userId"
            appDisplayName = $app
            resourceDisplayName = $resource
            clientAppUsed = $client
            statusErrorCode = $statusCode
            statusFailureReason = $failureReason
            statusAdditionalDetails = $additionalDetails
            conditionalAccessStatus = $caStatus
            appliedPolicyNames = @($policyEvidence.all_policy_names)
            blockingPolicyNames = @($policyEvidence.blocking_policy_names)
            appliedConditionalAccessPolicies = @($policyEvidence.policy_objects)
            ipAddress = Get-ZTVPValue -Object $signIn -Name "ipAddress"
            matchedIdentifier = $match.matched_identifier
            matchedIdentifiers = @($match.matched_identifiers)
            evidenceCategory = $evidenceCategory
            resultCategory = $resultCategory
            adminPortalEvidence = $isAdminPortal
            invitationRedemptionEvidence = $isInvitation
            success = ($resultCategory -eq "SUCCESS")
            blockedOrInterrupted = ($resultCategory -eq "BLOCKED_OR_INTERRUPTED")
        }

        $rows += $row
    }

    return $rows
}

function Sort-ZTVPEvidenceDescending {
    param([object[]]$Rows)

    return @(
        $Rows |
        Sort-Object -Property @{
            Expression = { [int64]($_.createdDateTimeTicks) }
            Descending = $true
        }
    )
}

function Copy-ZTVPLatestAttempt {
    param([object]$Row)

    if ($null -eq $Row) { return $null }

    return [PSCustomObject]@{
        createdDateTimeUtc = $Row.createdDateTimeUtc
        createdDateTimeIsoUtc = $Row.createdDateTimeIsoUtc
        signInType = $Row.signInType
        evidenceSource = $Row.evidenceSource
        userPrincipalName = $Row.userPrincipalName
        userId = $Row.userId
        appDisplayName = $Row.appDisplayName
        resourceDisplayName = $Row.resourceDisplayName
        statusErrorCode = $Row.statusErrorCode
        statusFailureReason = $Row.statusFailureReason
        conditionalAccessStatus = $Row.conditionalAccessStatus
        appliedPolicyNames = @($Row.appliedPolicyNames)
        blockingPolicyNames = @($Row.blockingPolicyNames)
        ipAddress = $Row.ipAddress
        matchedIdentifier = $Row.matchedIdentifier
        resultCategory = $Row.resultCategory
    }
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-005"
$statePath = Join-Path $stateDir "guest-state.json"

if (-not (Test-Path $statePath)) {
    throw "No active ID-C-005 guest state was found. Invite an external guest first."
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

$guestUserId = [string]$state.guest_user.id
$guestUpn = [string]$state.guest_user.user_principal_name
$externalEmail = [string]$state.external_identity.external_email

if ([string]::IsNullOrWhiteSpace($guestUserId) -and [string]::IsNullOrWhiteSpace($guestUpn) -and [string]::IsNullOrWhiteSpace($externalEmail)) {
    throw "The active ID-C-005 state does not contain usable guest identifiers."
}

$nowUtc = [DateTimeOffset]::UtcNow
$lookbackStart = $nowUtc.AddMinutes(-1 * [Math]::Max(1, $LookbackMinutes))
$evidenceStartMode = "LookbackMinutes"
$decisionStart = $lookbackStart

if (-not [string]::IsNullOrWhiteSpace($EvidenceStartUtc)) {
    $parsedFreshStart = Convert-ZTVPGraphDateTimeUtc -Value $EvidenceStartUtc

    if ($null -eq $parsedFreshStart) {
        throw "EvidenceStartUtc could not be parsed as a UTC datetime: $EvidenceStartUtc"
    }

    $decisionStart = $parsedFreshStart
    $evidenceStartMode = "FreshRetestWindow"
}

$collectionStart = $lookbackStart

if ($evidenceStartMode -eq "LookbackMinutes" -or $decisionStart -lt $lookbackStart) {
    $collectionStart = $decisionStart
}

Write-Host ""
Write-Host "========================================="
Write-Host "ZTVP ID-C-005 - External Guest Admin Portal Block Validation"
Write-Host "========================================="
Write-Host ""
Write-Host "External email: $externalEmail"
Write-Host "Guest UPN: $guestUpn"
Write-Host "Guest object ID: $guestUserId"
Write-Host "Observed browser outcome: $ObservedOutcome"
Write-Host "Evidence start mode: $evidenceStartMode"
Write-Host "Decision evidence start UTC: $(Format-ZTVPDateTimeUtc -Value $decisionStart)"
Write-Host "Collection start UTC: $(Format-ZTVPDateTimeUtc -Value $collectionStart)"
Write-Host ""

$waitSafe = [Math]::Max(0, $EvidenceWaitSeconds)
$deadline = (Get-Date).AddSeconds($waitSafe)
$pollInterval = 15
$pollNumber = 0

$rawSignIns = @()
$allMatchedEvidence = @()
$decisionEvidence = @()
$adminPortalEvidence = @()
$invitationEvidence = @()
$historicalPortalEvidence = @()
$polls = @()

do {
    if ($pollNumber -gt 0) {
        Start-Sleep -Seconds $pollInterval
    }

    $pollNumber++
    Write-Host "Polling Entra sign-in logs... poll $pollNumber"

    $rawSignIns = @(Get-ZTVPSignInsSince -StartUtcDate $collectionStart -ExternalEmail $externalEmail -GuestUpn $guestUpn -GuestUserId $guestUserId)
    $allMatchedEvidence = @(Convert-ZTVPGuestSignInEvidence -SignIns $rawSignIns -ExternalEmail $externalEmail -GuestUpn $guestUpn -GuestUserId $guestUserId)

    $decisionEvidence = @(
        $allMatchedEvidence |
        Where-Object { [int64]$_.createdDateTimeTicks -ge [int64]$decisionStart.UtcTicks }
    )

    $adminPortalEvidence = @(Sort-ZTVPEvidenceDescending -Rows @($decisionEvidence | Where-Object { $_.evidenceCategory -eq "ADMIN_PORTAL" }))
    $invitationEvidence = @(Sort-ZTVPEvidenceDescending -Rows @($decisionEvidence | Where-Object { $_.evidenceCategory -eq "INVITATION_REDEMPTION" }))

    $successfulAdminEvidence = @($adminPortalEvidence | Where-Object { $_.resultCategory -eq "SUCCESS" })
    $blockedAdminEvidence = @($adminPortalEvidence | Where-Object { $_.resultCategory -eq "BLOCKED_OR_INTERRUPTED" })

    $latestPortalResult = if ($adminPortalEvidence.Count -gt 0) { [string]$adminPortalEvidence[0].resultCategory } else { "PENDING" }

    Write-Host "Matched $($decisionEvidence.Count) guest rows"
    Write-Host "Matched $($adminPortalEvidence.Count) admin portal rows"
    Write-Host "Latest admin portal result: $latestPortalResult"

    $polls += [PSCustomObject]@{
        poll = $pollNumber
        checked_at_utc = Format-ZTVPDateTimeUtc -Value ([DateTimeOffset]::UtcNow)
        raw_signins_queried = $rawSignIns.Count
        matched_guest_rows = $decisionEvidence.Count
        admin_portal_evidence = $adminPortalEvidence.Count
        successful_admin_portal_evidence = $successfulAdminEvidence.Count
        blocked_admin_portal_evidence = $blockedAdminEvidence.Count
        latest_admin_portal_result = $latestPortalResult
    }

    if ($adminPortalEvidence.Count -gt 0) {
        break
    }
}
while ((Get-Date) -lt $deadline)

$guestFresh = Get-ZTVPGuestUserFresh -UserId $guestUserId
$guestExternalState = $null

if ($null -ne $guestFresh) {
    $guestExternalState = [string](Get-ZTVPValue -Object $guestFresh -Name "externalUserState")
}

$decisionEvidence = @(Sort-ZTVPEvidenceDescending -Rows $decisionEvidence)
$adminPortalEvidence = @(Sort-ZTVPEvidenceDescending -Rows @($decisionEvidence | Where-Object { $_.evidenceCategory -eq "ADMIN_PORTAL" }))
$invitationEvidence = @(Sort-ZTVPEvidenceDescending -Rows @($decisionEvidence | Where-Object { $_.evidenceCategory -eq "INVITATION_REDEMPTION" }))
$otherGuestEvidence = @(Sort-ZTVPEvidenceDescending -Rows @($decisionEvidence | Where-Object { $_.evidenceCategory -eq "OTHER_GUEST" }))

$successfulAdminEvidence = @(Sort-ZTVPEvidenceDescending -Rows @($adminPortalEvidence | Where-Object { $_.resultCategory -eq "SUCCESS" }))
$blockedAdminEvidence = @(Sort-ZTVPEvidenceDescending -Rows @($adminPortalEvidence | Where-Object { $_.resultCategory -eq "BLOCKED_OR_INTERRUPTED" }))

if ($evidenceStartMode -eq "FreshRetestWindow") {
    $historicalPortalEvidence = @(
        Sort-ZTVPEvidenceDescending -Rows @(
            $allMatchedEvidence |
            Where-Object {
                [int64]$_.createdDateTimeTicks -lt [int64]$decisionStart.UtcTicks -and
                $_.evidenceCategory -eq "ADMIN_PORTAL"
            }
        )
    )
}
else {
    $historicalPortalEvidence = @()
}

$historicalSuccessfulPortalEvidence = @($historicalPortalEvidence | Where-Object { $_.resultCategory -eq "SUCCESS" })

$latestAdminPortalAttempt = if ($adminPortalEvidence.Count -gt 0) { Copy-ZTVPLatestAttempt -Row $adminPortalEvidence[0] } else { $null }
$latestSuccessfulAdminPortalAttempt = if ($successfulAdminEvidence.Count -gt 0) { Copy-ZTVPLatestAttempt -Row $successfulAdminEvidence[0] } else { $null }
$latestBlockedAdminPortalAttempt = if ($blockedAdminEvidence.Count -gt 0) { Copy-ZTVPLatestAttempt -Row $blockedAdminEvidence[0] } else { $null }

$blockingPolicyNames = @(
    $blockedAdminEvidence |
    ForEach-Object { $_.blockingPolicyNames } |
    Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
    Sort-Object -Unique
)

$allPolicyNames = @(
    $adminPortalEvidence |
    ForEach-Object { $_.appliedPolicyNames } |
    Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
    Sort-Object -Unique
)

$policyRows = @(
    $blockedAdminEvidence |
    ForEach-Object {
        [PSCustomObject]@{
            createdDateTimeUtc = $_.createdDateTimeUtc
            appDisplayName = $_.appDisplayName
            resourceDisplayName = $_.resourceDisplayName
            resultCategory = $_.resultCategory
            appliedPolicyNames = @($_.appliedPolicyNames)
            blockingPolicyNames = @($_.blockingPolicyNames)
            conditionalAccessStatus = $_.conditionalAccessStatus
        }
    }
)

$warnings = @()
$browserReached = ($ObservedOutcome -eq "REACHED_ADMIN_PORTAL")
$browserBlockedOrInterrupted = ($ObservedOutcome -eq "ACCESS_BLOCKED" -or $ObservedOutcome -eq "SIGNIN_INTERRUPTED")

if ($evidenceStartMode -eq "FreshRetestWindow" -and $historicalSuccessfulPortalEvidence.Count -gt 0) {
    $warnings += "Older successful portal access exists outside the active fresh retest window."
}

if ($browserReached) {
    $warnings += "Manual browser observation says the guest reached Azure/admin portal. ZTVP will not output PASS unless fresh admin portal telemetry supports a block without conflict."
}

if ($adminPortalEvidence.Count -eq 0 -and $invitationEvidence.Count -gt 0) {
    $warnings += "Invitation evidence found, but no Azure/admin portal access telemetry found."
}

if ($adminPortalEvidence.Count -eq 0 -and ($ObservedOutcome -eq "AUTO_DETECT" -or $ObservedOutcome -eq "NOT_RECORDED")) {
    $warnings += "No admin portal telemetry was found for the selected evidence window. Complete the portal access attempt, wait for Entra logs, then collect evidence again."
}

$status = "PARTIAL_NO_ADMIN_PORTAL_TELEMETRY"
$risk = "MEDIUM"
$evidenceQuality = "Partial - no admin portal telemetry found"
$summary = "No matching Azure/admin portal telemetry was found for this guest in the active decision window."
$finalClaim = "This run cannot prove whether guest admin portal access was blocked or allowed without admin portal telemetry or a browser-observed allow/block outcome."
$actualDecision = $finalClaim

if ($latestAdminPortalAttempt -and $latestAdminPortalAttempt.resultCategory -eq "SUCCESS") {
    $status = "FAIL_GUEST_ADMIN_PORTAL_ALLOWED"
    $risk = "HIGH"
    $evidenceQuality = "Strong - successful admin portal sign-in telemetry"
    $summary = "The latest matching Azure/admin portal attempt succeeded."
    $finalClaim = "The external guest reached Azure/admin portal. Guest admin portal access was not blocked for this attempt."
    $actualDecision = $finalClaim
}
elseif ($latestAdminPortalAttempt -and $latestAdminPortalAttempt.resultCategory -eq "BLOCKED_OR_INTERRUPTED") {
    if ($browserReached) {
        $status = "PARTIAL_CONFLICT_BROWSER_REACHED_TELEMETRY_BLOCKED"
        $risk = "HIGH"
        $evidenceQuality = "Conflicting - browser observation disagrees with latest telemetry"
        $summary = "The consultant recorded that the guest reached Azure/admin portal, but the latest matching Entra admin portal telemetry is blocked or interrupted."
        $finalClaim = "The consultant recorded that the guest reached Azure/admin portal, but the latest matching Entra admin portal telemetry is blocked or interrupted. This requires retest with a fresh window."
        $actualDecision = $finalClaim
        $warnings += "Browser observation conflicts with Entra admin portal telemetry. Start a fresh retest window and repeat the exact portal attempt."
    }
    else {
        $status = "PASS_LATEST_GUEST_ATTEMPT_BLOCKED_OR_INTERRUPTED"
        $risk = "LOW"
        $evidenceQuality = "Strong - latest admin portal sign-in telemetry blocked/interrupted"
        $summary = "The latest matching Azure/admin portal attempt was blocked or interrupted."
        $finalClaim = "The latest guest attempt did not reach Azure/admin portal. The tenant blocked or interrupted the admin portal access path."
        $actualDecision = $finalClaim
    }
}
elseif ($adminPortalEvidence.Count -eq 0) {
    if ($browserReached) {
        $status = "FAIL_BROWSER_OBSERVED_TELEMETRY_PENDING"
        $risk = "HIGH"
        $evidenceQuality = "Browser-observed, telemetry pending"
        $summary = "The consultant recorded that the guest reached Azure/admin portal, but matching Entra admin portal telemetry has not appeared yet."
        $finalClaim = "The consultant observed guest access to Azure/admin portal. Treat this as an insecure result unless a fresh retest proves otherwise."
        $actualDecision = $finalClaim
    }
    elseif ($browserBlockedOrInterrupted) {
        $status = "PARTIAL_BROWSER_BLOCKED_TELEMETRY_PENDING"
        $risk = "MEDIUM"
        $evidenceQuality = "Browser-observed block, telemetry pending"
        $summary = "The browser outcome was blocked or interrupted, but matching Azure/admin portal telemetry was not found yet."
        $finalClaim = "The browser suggested a block/interruption, but this run needs Entra admin portal telemetry for a strong PASS."
        $actualDecision = $finalClaim
    }
    else {
        $status = "PARTIAL_NO_ADMIN_PORTAL_TELEMETRY"
        $risk = "MEDIUM"
        $evidenceQuality = "Partial - no admin portal telemetry found"

        if ($ObservedOutcome -eq "INVITATION_NOT_REDEEMED" -or $guestExternalState -eq "PendingAcceptance") {
            $summary = "The guest invitation does not appear to have completed, and no Azure/admin portal telemetry was found."
            $finalClaim = "This run cannot prove guest admin portal enforcement because the external guest did not complete the invitation and portal access path."
        }
        elseif ($invitationEvidence.Count -gt 0) {
            $summary = "Invitation evidence was found, but no Azure/admin portal access telemetry was found."
            $finalClaim = "The guest reached the invitation/redemption flow, but this run did not prove whether Azure/admin portal access was blocked or allowed."
        }
        else {
            $summary = "No matching Azure/admin portal telemetry was found for this guest in the active decision window."
            $finalClaim = "The run cannot prove guest admin portal enforcement without a guest Azure/admin portal sign-in attempt or browser-observed outcome."
        }

        $actualDecision = $finalClaim
    }
}

$matchedByExternalEmailCount = @($decisionEvidence | Where-Object { $_.matchedIdentifiers -contains "externalEmail" }).Count
$matchedByGuestUpnCount = @($decisionEvidence | Where-Object { $_.matchedIdentifiers -contains "guestUpn" }).Count
$matchedByGuestIdCount = @($decisionEvidence | Where-Object { $_.matchedIdentifiers -contains "guestId" }).Count

$metrics = [PSCustomObject]@{
    raw_guest_signins = $decisionEvidence.Count
    admin_portal_evidence_count = $adminPortalEvidence.Count
    successful_admin_portal_evidence_count = $successfulAdminEvidence.Count
    blocked_admin_portal_evidence_count = $blockedAdminEvidence.Count
    invitation_redeem_evidence_count = $invitationEvidence.Count
    historical_successful_portal_evidence_count = $historicalSuccessfulPortalEvidence.Count
    matched_by_external_email_count = $matchedByExternalEmailCount
    matched_by_guest_upn_count = $matchedByGuestUpnCount
    matched_by_guest_id_count = $matchedByGuestIdCount
    latest_admin_portal_attempt_time = if ($latestAdminPortalAttempt) { $latestAdminPortalAttempt.createdDateTimeUtc } else { $null }
    latest_admin_portal_attempt_result = if ($latestAdminPortalAttempt) { $latestAdminPortalAttempt.resultCategory } else { "PENDING" }
    browser_outcome = $ObservedOutcome
    evidence_start_utc = Format-ZTVPDateTimeUtc -Value $decisionStart
    evidence_start_mode = $evidenceStartMode
    evidence_poll_count = $polls.Count
    raw_signins_queried = $rawSignIns.Count
    lookback_minutes = $LookbackMinutes
    evidence_wait_seconds = $EvidenceWaitSeconds
}

$result = [PSCustomObject]@{
    scenario_id = "ID-C-005"
    scenario_name = "External Guest Admin Portal Block Validation"
    pillar = "Identity"
    scope = "Cloud"
    generated_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    connected_account = $ctx.Account

    control_tested = "External or guest users should not be able to access Azure/admin portals unless explicitly allowed."
    expected_result = "The guest admin portal access attempt should be blocked by Conditional Access or platform controls."
    failure_condition = "The external guest successfully reaches Azure Portal or an admin portal resource."
    test_method = "Fresh B2B guest invitation, real external account sign-in, admin portal access attempt, Microsoft Entra interactive and non-interactive sign-in evidence collection, and cleanup."

    status = $status
    risk = $risk
    evidence_quality = $evidenceQuality
    executive_summary = $summary
    final_claim = $finalClaim
    actual_decision = $actualDecision
    warnings = @($warnings | Sort-Object -Unique)

    observed_browser_outcome = $ObservedOutcome
    browser_observation = [PSCustomObject]@{
        outcome = $ObservedOutcome
        treated_as_evidence = ($ObservedOutcome -ne "AUTO_DETECT" -and $ObservedOutcome -ne "NOT_RECORDED")
        reached_admin_portal = $browserReached
        blocked_or_interrupted = $browserBlockedOrInterrupted
    }

    latest_attempt = $latestAdminPortalAttempt
    latest_admin_portal_attempt = $latestAdminPortalAttempt
    latest_successful_admin_portal_attempt = $latestSuccessfulAdminPortalAttempt
    latest_blocked_admin_portal_attempt = $latestBlockedAdminPortalAttempt

    validation_window = [PSCustomObject]@{
        evidence_start_utc = Format-ZTVPDateTimeUtc -Value $decisionStart
        evidence_start_iso_utc = Format-ZTVPDateTimeIsoUtc -Value $decisionStart
        evidence_start_mode = $evidenceStartMode
        collection_start_utc = Format-ZTVPDateTimeUtc -Value $collectionStart
        collection_start_iso_utc = Format-ZTVPDateTimeIsoUtc -Value $collectionStart
        lookback_start_utc = Format-ZTVPDateTimeUtc -Value $lookbackStart
        lookback_start_iso_utc = Format-ZTVPDateTimeIsoUtc -Value $lookbackStart
        generated_at_utc = Format-ZTVPDateTimeUtc -Value ([DateTimeOffset]::UtcNow)
        older_rows_ignored_for_decision = ($evidenceStartMode -eq "FreshRetestWindow")
    }

    guest_user = [PSCustomObject]@{
        id = $guestUserId
        user_principal_name = $guestUpn
        external_email = $externalEmail
        external_user_state = $guestExternalState
    }

    policy_attribution = [PSCustomObject]@{
        block_policy_applied = ($blockingPolicyNames.Count -gt 0)
        block_policy_names = @($blockingPolicyNames)
        all_policy_names = @($allPolicyNames)
        blocked_admin_portal_evidence_count = $blockedAdminEvidence.Count
        policy_rows = @($policyRows)
    }

    metrics = $metrics
    evidence_polling = @($polls)

    admin_portal_evidence = @($adminPortalEvidence)
    invitation_redemption_evidence = @($invitationEvidence)
    other_guest_evidence = @($otherGuestEvidence)
    historical_portal_evidence = @($historicalPortalEvidence)
    historical_successful_portal_evidence = @($historicalSuccessfulPortalEvidence)

    sign_in_evidence = @($decisionEvidence)
}

$reportPath = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-005-result.json"

$result |
    ConvertTo-Json -Depth 100 |
    Set-Content -Path $reportPath -Encoding UTF8

Write-Host ""
Write-Host "========================================="
Write-Host "ID-C-005 COMPLETED"
Write-Host "========================================="
Write-Host ""
Write-Host "Status: $status"
Write-Host "Risk: $risk"
Write-Host "Evidence quality: $evidenceQuality"
Write-Host "Raw guest sign-ins: $($metrics.raw_guest_signins)"
Write-Host "Admin portal evidence: $($metrics.admin_portal_evidence_count)"
Write-Host "Successful admin portal evidence: $($metrics.successful_admin_portal_evidence_count)"
Write-Host "Blocked/interrupted admin portal evidence: $($metrics.blocked_admin_portal_evidence_count)"
Write-Host "Invitation/redemption evidence: $($metrics.invitation_redeem_evidence_count)"
Write-Host "Latest admin portal result: $($metrics.latest_admin_portal_attempt_result)"
Write-Host "Report saved to: $reportPath"
Write-Host ""
