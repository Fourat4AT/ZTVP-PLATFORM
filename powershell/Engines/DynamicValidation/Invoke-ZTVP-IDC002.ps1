param(
    [int]$PollMinutes = 8,
    [int]$LookbackMinutes = 240,
    [string]$EvidenceStartUtc = ""
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "AuditLog.Read.All",
    "Directory.Read.All",
    "User.Read.All",
    "User.ReadWrite.All",
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
            $currentScopes = @($ctx.Scopes | ForEach-Object { $_.ToLower() })
        }

        foreach ($scope in $Scopes) {
            if ($currentScopes -notcontains $scope.ToLower()) {
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
    param([string]$Uri, [int]$MaxPages = 20)

    $items = @()
    $page = 0
    $nextUri = $Uri

    while ($nextUri -and $page -lt $MaxPages) {
        $page++
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri
        $value = Get-ZTVPValue -Object $response -Name "value"

        if ($value) {
            $items += @($value)
        }

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

function Get-ZTVPRestError {
    param([object]$ErrorRecord)

    $message = $ErrorRecord.Exception.Message
    $jsonText = $null

    try {
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            $jsonText = $ErrorRecord.ErrorDetails.Message
        }
    }
    catch {}

    if (-not [string]::IsNullOrWhiteSpace($jsonText)) {
        try {
            return $jsonText | ConvertFrom-Json
        }
        catch {}
    }

    return [PSCustomObject]@{
        error = "unknown_error"
        error_description = $message
    }
}

function Poll-ZTVPDeviceCodeToken {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$DeviceCode,
        [int]$InitialIntervalSeconds,
        [int]$PollMinutes,
        [string]$TargetUpn = "",
        [string]$TargetUserId = "",
        [datetime]$EvidenceStartUtcDate = ([DateTime]::UtcNow),
        [string]$EvidenceClientId = ""
    )

    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $deadline = (Get-Date).AddMinutes($PollMinutes)
    $interval = [Math]::Max(3, $InitialIntervalSeconds)

    $events = @()
    $tokenIssued = $false
    $tokenOutcome = "TimeoutPending"
    $lastError = $null
    $pollCount = 0
    $earlyTenantEvidenceFound = $false
    $earlyTenantEvidenceCount = 0
    $lastEvidencePollUtc = $null

    while ((Get-Date) -lt $deadline) {
        $pollCount++

        $body = @{
            grant_type = "urn:ietf:params:oauth:grant-type:device_code"
            client_id = $ClientId
            device_code = $DeviceCode
        }

        try {
            $result = Invoke-RestMethod `
                -Method POST `
                -Uri $tokenUri `
                -Body $body `
                -ContentType "application/x-www-form-urlencoded"

            $tokenIssued = $true
            $tokenOutcome = "TokenIssued"

            $events += [PSCustomObject]@{
                time = (Get-Date).ToString("s")
                poll = $pollCount
                outcome = "TokenIssued"
                error = $null
                description = "Token endpoint returned access token. Token was not stored."
            }

            break
        }
        catch {
            $err = Get-ZTVPRestError -ErrorRecord $_
            $errorCode = [string](Get-ZTVPValue -Object $err -Name "error")
            $errorDescription = [string](Get-ZTVPValue -Object $err -Name "error_description")

            $lastError = [PSCustomObject]@{
                error = $errorCode
                error_description = $errorDescription
            }

            $events += [PSCustomObject]@{
                time = (Get-Date).ToString("s")
                poll = $pollCount
                outcome = "Error"
                error = $errorCode
                description = $errorDescription
            }

            if ($errorCode -eq "authorization_pending") {
                $shouldCheckTenantEvidence = -not [string]::IsNullOrWhiteSpace($TargetUpn)
                if ($shouldCheckTenantEvidence -and $lastEvidencePollUtc) {
                    $secondsSinceLastEvidencePoll = ((Get-Date).ToUniversalTime() - $lastEvidencePollUtc).TotalSeconds
                    $shouldCheckTenantEvidence = ($secondsSinceLastEvidencePoll -ge [Math]::Max(15, $interval))
                }

                if ($shouldCheckTenantEvidence) {
                    $lastEvidencePollUtc = (Get-Date).ToUniversalTime()
                    try {
                        Write-Host "Checking Entra sign-in evidence during token polling..."
                        $earlyRawSignIns = @(Get-ZTVPSignInsForUser -TargetUpn $TargetUpn -TargetUserId $TargetUserId -StartUtcDate $EvidenceStartUtcDate)
                        $earlyRows = @(Convert-ZTVPDeviceCodeEvidence -SignIns $earlyRawSignIns -StartUtcDate $EvidenceStartUtcDate -ClientId $EvidenceClientId)
                        $earlyRelevantRows = @(Select-ZTVPDeviceCodeMatchingRows -EvidenceRows $earlyRows -TargetUpn $TargetUpn -TargetUserId $TargetUserId)

                        if ($earlyRelevantRows.Count -gt 0) {
                            $earlyTenantEvidenceFound = $true
                            $earlyTenantEvidenceCount = $earlyRelevantRows.Count
                            $tokenOutcome = "TenantEvidenceFound"
                            Write-Host "Tenant sign-in evidence found during token polling. Stopping early."
                            break
                        }
                    }
                    catch {
                        Write-Host "Tenant evidence check during token polling did not complete: $($_.Exception.Message)"
                    }
                }

                Start-Sleep -Seconds $interval
                continue
            }

            if ($errorCode -eq "slow_down") {
                $interval += 5
                Start-Sleep -Seconds $interval
                continue
            }

            if ($errorCode -eq "expired_token") {
                $tokenOutcome = "Expired"
                break
            }

            if ($errorCode -match "access_denied|authorization_declined|interaction_required|invalid_grant|conditional|blocked|unauthorized_client") {
                $tokenOutcome = "BlockedOrDenied"
                break
            }

            $tokenOutcome = "Error"
            break
        }
    }

    return [PSCustomObject]@{
        token_issued = $tokenIssued
        token_outcome = $tokenOutcome
        last_error = $lastError
        poll_count = $pollCount
        early_tenant_evidence_found = $earlyTenantEvidenceFound
        early_tenant_evidence_count = $earlyTenantEvidenceCount
        poll_events = @($events)
    }
}

function Get-ZTVPDeviceCodeBlockPolicies {
    $policies = @()

    try {
        $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$top=100"
        $items = @(Invoke-ZTVPPagedGraphQuery -Uri $uri -MaxPages 10)

        foreach ($policy in $items) {
            $id = [string](Get-ZTVPValue -Object $policy -Name "id")
            $name = [string](Get-ZTVPValue -Object $policy -Name "displayName")
            $state = [string](Get-ZTVPValue -Object $policy -Name "state")
            $grantControls = Get-ZTVPValue -Object $policy -Name "grantControls"

            $policyJson = ""
            $grantJson = ""

            try { $policyJson = ($policy | ConvertTo-Json -Depth 50 -Compress) } catch {}
            try { $grantJson = ($grantControls | ConvertTo-Json -Depth 30 -Compress) } catch {}

            $looksDeviceCode = $false
            $hasBlock = $false

            if ("$name $policyJson" -match "DeviceCode|Device Code|deviceCode|device code|deviceCodeFlow|device_code") {
                $looksDeviceCode = $true
            }

            if ($grantJson -match "block|Block") {
                $hasBlock = $true
            }

            if (-not ($looksDeviceCode -and $hasBlock)) {
                continue
            }

            $stateLower = $state.Trim().ToLower()
            $mode = "Unknown"
            $enforces = $false
            $reportOnly = $false

            if ($stateLower -eq "enabled") {
                $mode = "Enabled"
                $enforces = $true
            }
            elseif ($stateLower -match "report") {
                $mode = "Report-only"
                $reportOnly = $true
            }
            elseif ($stateLower -eq "disabled") {
                $mode = "Disabled"
            }

            $policies += [PSCustomObject]@{
                id = $id
                displayName = $name
                state = $state
                mode = $mode
                enforces = $enforces
                reportOnly = $reportOnly
                deviceCodeDetected = $looksDeviceCode
                blockGrantDetected = $hasBlock
            }
        }
    }
    catch {
        $policies += [PSCustomObject]@{
            id = $null
            displayName = "Unable to read Conditional Access policies"
            state = "Unknown"
            mode = "Error"
            enforces = $false
            reportOnly = $false
            deviceCodeDetected = $false
            blockGrantDetected = $false
            error = $_.Exception.Message
        }
    }

    return $policies
}

function Get-ZTVPDeviceCodeDecoyPrefixes {
    param([string]$TargetUpn)

    $prefixes = @()
    $targetLower = ([string]$TargetUpn).Trim().ToLower()

    if (-not [string]::IsNullOrWhiteSpace($targetLower)) {
        $prefixes += $targetLower
        $localPart = ($targetLower -split "@", 2)[0]
        if (-not [string]::IsNullOrWhiteSpace($localPart)) {
            $prefixes += $localPart
            if ($localPart -match "^(ztvp-idc002-devicecode)") {
                $prefixes += $Matches[1]
            }
        }
    }

    return @($prefixes | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_)
    } | Sort-Object -Unique)
}

function Test-ZTVPDeviceCodeUserMatch {
    param(
        [string]$LogUpn,
        [string]$LogUserId,
        [string]$TargetUpn,
        [string]$TargetUserId
    )

    $logUpnLower = ([string]$LogUpn).Trim().ToLower()
    $targetLower = ([string]$TargetUpn).Trim().ToLower()

    if (-not [string]::IsNullOrWhiteSpace($targetLower) -and $logUpnLower -eq $targetLower) {
        return $true
    }

    if (-not [string]::IsNullOrWhiteSpace($TargetUserId) -and [string]$LogUserId -eq [string]$TargetUserId) {
        return $true
    }

    foreach ($prefix in @(Get-ZTVPDeviceCodeDecoyPrefixes -TargetUpn $TargetUpn)) {
        if ($logUpnLower.StartsWith([string]$prefix)) {
            return $true
        }
    }

    return $false
}

function Test-ZTVPDeviceCodeGraphAppMatch {
    param([object]$SignIn)

    $app = [string](Get-ZTVPValue -Object $SignIn -Name "appDisplayName")
    $resource = [string](Get-ZTVPValue -Object $SignIn -Name "resourceDisplayName")

    return (
        $app -match "Microsoft Graph Command Line Tools" -or
        $resource -match "Microsoft Graph"
    )
}

function Get-ZTVPSignInsForUser {
    param(
        [string]$TargetUpn,
        [string]$TargetUserId,
        [datetime]$StartUtcDate
    )

    $all = @()
    $queryStartUtcDate = $StartUtcDate.AddMinutes(-2)
    $startUtc = $queryStartUtcDate.ToString("o")
    $targetLower = $TargetUpn.Trim().ToLower()
    $safeOriginal = $TargetUpn.Replace("'", "''")
    $safeLower = $targetLower.Replace("'", "''")
    $prefixes = @(Get-ZTVPDeviceCodeDecoyPrefixes -TargetUpn $TargetUpn)
    $prefixForGraphFilter = @($prefixes | Where-Object { [string]$_ -eq "ztvp-idc002-devicecode" } | Select-Object -First 1)
    if (-not $prefixForGraphFilter) {
        $prefixForGraphFilter = @($prefixes | Where-Object { [string]$_ -notmatch "@" } | Select-Object -First 1)
    }
    if (-not $prefixForGraphFilter) {
        $prefixForGraphFilter = @($prefixes | Select-Object -First 1)
    }
    $safePrefix = ([string]$prefixForGraphFilter).Replace("'", "''")

    $queries = @()
    $eventTypeFilters = @(
        "",
        " and signInEventTypes/any(t: t eq 'interactiveUser')",
        " and signInEventTypes/any(t: t eq 'nonInteractiveUser')"
    )

    foreach ($eventTypeFilter in $eventTypeFilters) {
        $filter1 = "createdDateTime ge $startUtc and userPrincipalName eq '$safeOriginal'$eventTypeFilter"
        $queries += "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$([System.Uri]::EscapeDataString($filter1))"

        if ($safeLower -ne $safeOriginal) {
            $filter2 = "createdDateTime ge $startUtc and userPrincipalName eq '$safeLower'$eventTypeFilter"
            $queries += "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$([System.Uri]::EscapeDataString($filter2))"
        }

        if (-not [string]::IsNullOrWhiteSpace($TargetUserId)) {
            $filter3 = "createdDateTime ge $startUtc and userId eq '$TargetUserId'$eventTypeFilter"
            $queries += "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$([System.Uri]::EscapeDataString($filter3))"
        }

        if (-not [string]::IsNullOrWhiteSpace($safePrefix)) {
            $filter4 = "createdDateTime ge $startUtc and startswith(userPrincipalName,'$safePrefix')$eventTypeFilter"
            $queries += "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$([System.Uri]::EscapeDataString($filter4))"
        }
    }

    foreach ($uri in $queries) {
        try {
            $all += @(Invoke-ZTVPPagedGraphQuery -Uri $uri -MaxPages 10)
        }
        catch {}
    }

    try {
        $recent = @()
        foreach ($eventTypeFilter in $eventTypeFilters) {
            $recentFilter = "createdDateTime ge $startUtc$eventTypeFilter"
            $recentUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$([System.Uri]::EscapeDataString($recentFilter))"
            $recent += @(Invoke-ZTVPPagedGraphQuery -Uri $recentUri -MaxPages 20)
        }

        $all += @(
            $recent | Where-Object {
                $logUpn = [string](Get-ZTVPValue -Object $_ -Name "userPrincipalName")
                $logUserId = [string](Get-ZTVPValue -Object $_ -Name "userId")

                (Test-ZTVPDeviceCodeUserMatch -LogUpn $logUpn -LogUserId $logUserId -TargetUpn $TargetUpn -TargetUserId $TargetUserId) -and
                (Test-ZTVPDeviceCodeGraphAppMatch -SignIn $_)
            }
        )
    }
    catch {}

    $seen = @{}
    $deduped = @()

    foreach ($item in $all) {
        $id = [string](Get-ZTVPValue -Object $item -Name "id")

        if ([string]::IsNullOrWhiteSpace($id)) {
            $id = ([string](Get-ZTVPValue -Object $item -Name "createdDateTime")) + "|" + ([string](Get-ZTVPValue -Object $item -Name "appDisplayName"))
        }

        if (-not $seen.ContainsKey($id)) {
            $seen[$id] = $true
            $deduped += $item
        }
    }

    return $deduped
}

function Convert-ZTVPDeviceCodeEvidence {
    param(
        [object[]]$SignIns,
        [datetime]$StartUtcDate,
        [string]$ClientId
    )

    $rows = @()

    foreach ($signIn in $SignIns) {
        $createdRaw = [string](Get-ZTVPValue -Object $signIn -Name "createdDateTime")
        $withinLookback = $false
        $matchStartUtcDate = $StartUtcDate.AddMinutes(-2)

        try {
            $createdUtc = ([DateTimeOffset]::Parse($createdRaw)).UtcDateTime
            if ($createdUtc -ge $matchStartUtcDate) { $withinLookback = $true }
        }
        catch {}

        $isInteractiveRaw = Get-ZTVPValue -Object $signIn -Name "isInteractive"
        $isInteractive = $null

        if ($null -ne $isInteractiveRaw) {
            $isInteractive = [bool]$isInteractiveRaw
        }

        $evidenceType = "Unknown"

        if ($isInteractive -eq $true) {
            $evidenceType = "Interactive"
        }
        elseif ($isInteractive -eq $false) {
            $evidenceType = "NonInteractive"
        }

        $statusObj = Get-ZTVPValue -Object $signIn -Name "status"
        $statusCode = Get-ZTVPValue -Object $statusObj -Name "errorCode"
        $failureReason = [string](Get-ZTVPValue -Object $statusObj -Name "failureReason")
        $additionalDetails = [string](Get-ZTVPValue -Object $statusObj -Name "additionalDetails")

        $appDisplayName = [string](Get-ZTVPValue -Object $signIn -Name "appDisplayName")
        $resourceDisplayName = [string](Get-ZTVPValue -Object $signIn -Name "resourceDisplayName")
        $requestId = [string](Get-ZTVPValue -Object $signIn -Name "requestId")
        $signInId = [string](Get-ZTVPValue -Object $signIn -Name "id")
        $authProtocol = [string](Get-ZTVPValue -Object $signIn -Name "authenticationProtocol")
        $clientAppUsed = [string](Get-ZTVPValue -Object $signIn -Name "clientAppUsed")
        $caStatus = [string](Get-ZTVPValue -Object $signIn -Name "conditionalAccessStatus")

        $policies = Get-ZTVPValue -Object $signIn -Name "appliedConditionalAccessPolicies"
        $location = Get-ZTVPValue -Object $signIn -Name "location"

        $locationSummary = ""

        try {
            $city = Get-ZTVPValue -Object $location -Name "city"
            $state = Get-ZTVPValue -Object $location -Name "state"
            $country = Get-ZTVPValue -Object $location -Name "countryOrRegion"

            $locationSummary = (@($city, $state, $country) | Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            }) -join ", "
        }
        catch {}

        $policyObjects = @()
        $blockPolicyApplied = $false
        $blockPolicyNames = @()
        $reportOnlyBlockNames = @()

        foreach ($policy in @(ConvertTo-ZTVPArray $policies)) {
            if ($null -eq $policy) { continue }

            $policyName = [string](Get-ZTVPValue -Object $policy -Name "displayName")
            $policyResult = [string](Get-ZTVPValue -Object $policy -Name "result")
            $grantControls = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $policy -Name "enforcedGrantControls"))

            $policyJson = ""
            try { $policyJson = ($policy | ConvertTo-Json -Depth 30 -Compress) } catch {}

            $hasBlock = "$($grantControls -join ',') $policyJson" -match "block|Block"
            $looksDeviceCode = "$policyName $policyJson" -match "DeviceCode|Device Code|deviceCode|device code|deviceCodeFlow|device_code"
            $resultLower = $policyResult.Trim().ToLower()
            $isReportOnly = $resultLower -match "reportonly"
            $isNotApplied = $resultLower -eq "notapplied"
            $isApplied = (-not $isReportOnly -and -not $isNotApplied -and -not [string]::IsNullOrWhiteSpace($resultLower))
            $isFailureBlock = ($resultLower -eq "failure" -and $hasBlock)
            $isBlockingPolicyForThisAttempt = ($isApplied -and ($isFailureBlock -or ($hasBlock -and $resultLower -match "block")))

            if ($isBlockingPolicyForThisAttempt) {
                $blockPolicyApplied = $true
                if (-not [string]::IsNullOrWhiteSpace($policyName)) { $blockPolicyNames += $policyName }
            }

            if ($hasBlock -and $looksDeviceCode -and $isReportOnly) {
                if (-not [string]::IsNullOrWhiteSpace($policyName)) { $reportOnlyBlockNames += $policyName }
            }

            $policyObjects += [PSCustomObject]@{
                displayName = $policyName
                result = $policyResult
                enforcedGrantControls = @($grantControls)
                grantControlsText = ($grantControls -join ", ")
                deviceCodeDetected = $looksDeviceCode
                blockGrantDetected = $hasBlock
                failureBlockPolicy = $isFailureBlock
                blockPolicyApplied = $isBlockingPolicyForThisAttempt
                reportOnlyBlockPolicyMatched = ($hasBlock -and $looksDeviceCode -and $isReportOnly)
            }
        }

        $policySummary = (@($policyObjects | ForEach-Object {
            "$($_.displayName) : $($_.result) : $($_.enforcedGrantControls -join ',')"
        }) -join "; ")

        $success = $false

        if ($statusCode -eq 0 -or [string]$statusCode -eq "0") {
            $success = $true
        }

        $combined = "$authProtocol $clientAppUsed $appDisplayName $resourceDisplayName $failureReason $additionalDetails $policySummary"
        $deviceCodeEvidence = $false

        if ($combined -match "deviceCode|device code|device_code|Microsoft Graph PowerShell|Graph Command Line|PowerShell") {
            $deviceCodeEvidence = $true
        }

        $blocked = $false

        if ($blockPolicyApplied -or $caStatus -match "failure|notApplied|blocked" -or $failureReason -match "blocked|Conditional Access|access has been blocked") {
            if ($success -ne $true) {
                $blocked = $true
            }
        }

        $tokenLikelyIssued = $false

        if ($success -eq $true -and $blocked -ne $true) {
            $tokenLikelyIssued = $true
        }

        $rows += [PSCustomObject]@{
            CreatedDateTime = $createdRaw
            WithinLookback = $withinLookback
            EvidenceType = $evidenceType
            IsInteractive = $isInteractive
            UserPrincipalName = Get-ZTVPValue -Object $signIn -Name "userPrincipalName"
            UserId = Get-ZTVPValue -Object $signIn -Name "userId"
            SignInId = $signInId
            RequestId = $requestId
            AppDisplayName = $appDisplayName
            ResourceDisplayName = $resourceDisplayName
            AuthenticationProtocol = $authProtocol
            ClientAppUsed = $clientAppUsed
            DeviceCodeEvidence = $deviceCodeEvidence
            ConditionalAccessStatus = $caStatus
            BlockPolicyApplied = $blockPolicyApplied
            BlockPolicyNames = @($blockPolicyNames | Sort-Object -Unique)
            ReportOnlyBlockPolicyNames = @($reportOnlyBlockNames | Sort-Object -Unique)
            AppliedConditionalAccess = $policySummary
            ConditionalAccessPolicies = @($policyObjects)
            StatusCode = $statusCode
            Status = if ($success) { "Success" } else { "Failure" }
            FailureReason = $failureReason
            AdditionalDetails = $additionalDetails
            Success = $success
            Blocked = $blocked
            TokenLikelyIssuedFromLogs = $tokenLikelyIssued
            IpAddress = Get-ZTVPValue -Object $signIn -Name "ipAddress"
            Location = $locationSummary
        }
    }

    return $rows
}

function Select-ZTVPDeviceCodeMatchingRows {
    param(
        [object[]]$EvidenceRows,
        [string]$TargetUpn,
        [string]$TargetUserId
    )

    $allMatches = @(
        $EvidenceRows | Where-Object {
            $logUpn = [string]$_.UserPrincipalName
            $logUserId = [string]$_.UserId
            $app = [string]$_.AppDisplayName
            $resource = [string]$_.ResourceDisplayName
            $_.WithinLookback -eq $true -and (
                Test-ZTVPDeviceCodeUserMatch -LogUpn $logUpn -LogUserId $logUserId -TargetUpn $TargetUpn -TargetUserId $TargetUserId
            ) -and (
                $app -match "Microsoft Graph Command Line Tools" -or
                $resource -match "Microsoft Graph"
            )
        }
    )

    $interactiveMatches = @($allMatches | Where-Object { $_.IsInteractive -eq $true })
    $selectedMatches = if ($interactiveMatches.Count -gt 0) { $interactiveMatches } else { $allMatches }

    return @(
        $selectedMatches | Sort-Object -Property @{ Expression = {
            try { [DateTimeOffset]::Parse([string]$_.CreatedDateTime).UtcDateTime } catch { [DateTime]::MinValue }
        }; Descending = $true }
    )
}

function Get-ZTVPFailureBlockPolicyRows {
    param([object]$EvidenceRow)

    if ($null -eq $EvidenceRow) { return @() }

    return @(
        @(ConvertTo-ZTVPArray $EvidenceRow.ConditionalAccessPolicies) | Where-Object {
            $result = ([string]$_.result).Trim().ToLower()
            $grantText = "$($_.grantControlsText) $($_.enforcedGrantControls -join ',')"
            $result -eq "failure" -and $grantText -match "block"
        }
    )
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-002"
$statePath = Join-Path $stateDir "decoy-state.json"
$privatePath = Join-Path $stateDir "device-code-challenge-private.json"
$reportPath = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-002-result.json"

if (-not (Test-Path $statePath)) {
    throw "No active ID-C-002 decoy state was found."
}

if (-not (Test-Path $privatePath)) {
    throw "No ID-C-002 device-code challenge was found. Start the device-code challenge first."
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json
$challenge = Get-Content $privatePath -Raw | ConvertFrom-Json

$targetUpn = [string]$state.decoy_user.user_principal_name
$targetUserId = [string]$state.decoy_user.id
$tenantId = [string]$challenge.tenant_id
$clientId = [string]$challenge.client_id
$deviceCode = [string]$challenge.device_code
$startTime = ([DateTimeOffset]::Parse([string]$challenge.started_at)).UtcDateTime
$startUtcDate = (Get-Date).ToUniversalTime().AddMinutes(-1 * $LookbackMinutes)
$effectiveStartUtcDate = $startUtcDate

if (-not [string]::IsNullOrWhiteSpace($EvidenceStartUtc)) {
    try {
        $effectiveStartUtcDate = ([DateTimeOffset]::Parse($EvidenceStartUtc)).UtcDateTime
    }
    catch {
        Write-Host "EvidenceStartUtc could not be parsed. Falling back to LookbackMinutes."
        $effectiveStartUtcDate = $startUtcDate
    }
}

Write-Host ""
Write-Host "========================================="
Write-Host "ZTVP ID-C-002 - Device Code Flow Block Validation"
Write-Host "========================================="
Write-Host ""
Write-Host "Target user: $targetUpn"
Write-Host "Client ID: $clientId"
Write-Host "Evidence search starts at UTC: $($effectiveStartUtcDate.ToString('o'))"
Write-Host "Polling token endpoint for result..."

$tokenResult = Poll-ZTVPDeviceCodeToken `
    -TenantId $tenantId `
    -ClientId $clientId `
    -DeviceCode $deviceCode `
    -InitialIntervalSeconds ([int]$challenge.interval_seconds) `
    -PollMinutes $PollMinutes `
    -TargetUpn $targetUpn `
    -TargetUserId $targetUserId `
    -EvidenceStartUtcDate $effectiveStartUtcDate `
    -EvidenceClientId $clientId

Write-Host "Token outcome: $($tokenResult.token_outcome)"
Write-Host "Token issued: $($tokenResult.token_issued)"
Write-Host "Reading Conditional Access device-code block policies..."

$configuredPolicies = @(Get-ZTVPDeviceCodeBlockPolicies)
$enabledBlockPolicies = @($configuredPolicies | Where-Object { $_.enforces -eq $true })
$reportOnlyBlockPolicies = @($configuredPolicies | Where-Object { $_.reportOnly -eq $true })

Write-Host "Configured device-code block policies: $($configuredPolicies.Count)"
Write-Host "Enabled device-code block policies: $($enabledBlockPolicies.Count)"
Write-Host "Report-only device-code block policies: $($reportOnlyBlockPolicies.Count)"

Write-Host "Collecting Microsoft Entra sign-in evidence..."

$evidencePollSeconds = 15
$evidenceDeadline = (Get-Date).AddMinutes($PollMinutes)
$evidencePollCount = 0
$maxEvidencePollAttempts = [Math]::Max(1, [int][Math]::Ceiling(($PollMinutes * 60) / $evidencePollSeconds))
$evidenceStoppedEarly = $false
$rawSignIns = @()
$evidenceAll = @()
$evidenceRows = @()
$deviceCodeRows = @()
$blockedRows = @()
$blockPolicyNames = @()
$latestMatchingSignIn = $null
$failureBlockPolicyRows = @()

do {
    $evidencePollCount++
    Write-Host "Evidence poll $evidencePollCount/$maxEvidencePollAttempts - querying Entra sign-in logs from $($effectiveStartUtcDate.ToString('o'))..."

    $rawSignIns = @(Get-ZTVPSignInsForUser -TargetUpn $targetUpn -TargetUserId $targetUserId -StartUtcDate $effectiveStartUtcDate)
    $evidenceAll = @(Convert-ZTVPDeviceCodeEvidence -SignIns $rawSignIns -StartUtcDate $effectiveStartUtcDate -ClientId $clientId)

    $evidenceRows = @(
        $evidenceAll | Where-Object {
            $_.WithinLookback -eq $true
        }
    )

    $deviceCodeRows = @(Select-ZTVPDeviceCodeMatchingRows -EvidenceRows $evidenceRows -TargetUpn $targetUpn -TargetUserId $targetUserId)
    $latestMatchingSignIn = if ($deviceCodeRows.Count -gt 0) { $deviceCodeRows[0] } else { $null }
    $failureBlockPolicyRows = @(Get-ZTVPFailureBlockPolicyRows -EvidenceRow $latestMatchingSignIn)

    Write-Host "Raw sign-ins retrieved: $($rawSignIns.Count)"
    Write-Host "Matching Microsoft Graph device-code rows: $($deviceCodeRows.Count)"
    if ($latestMatchingSignIn) {
        Write-Host "Latest matching row: $($latestMatchingSignIn.CreatedDateTime) | $($latestMatchingSignIn.UserPrincipalName) | $($latestMatchingSignIn.AppDisplayName) | $($latestMatchingSignIn.ResourceDisplayName) | $($latestMatchingSignIn.Status) | CA=$($latestMatchingSignIn.ConditionalAccessStatus)"
        Write-Host "Failure+Block policy rows: $($failureBlockPolicyRows.Count)"
    }

    $blockedRows = @(
        $deviceCodeRows | Where-Object {
            $_.Blocked -eq $true -or $_.BlockPolicyApplied -eq $true -or (
                [string]$_.Status -eq "Failure" -and [string]$_.ConditionalAccessStatus -match "failure"
            )
        }
    )

    $blockPolicyNames = @()

    foreach ($row in $deviceCodeRows) {
        if ($row.BlockPolicyNames) {
            $blockPolicyNames += @($row.BlockPolicyNames)
        }
    }

    $blockPolicyNames = @($blockPolicyNames | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_)
    } | Sort-Object -Unique)

    $latestFailureCa = ($latestMatchingSignIn -and [string]$latestMatchingSignIn.Status -eq "Failure" -and [string]$latestMatchingSignIn.ConditionalAccessStatus -match "failure")
    $logTokenIssued = ($latestMatchingSignIn -and $latestMatchingSignIn.TokenLikelyIssuedFromLogs -eq $true)
    $blockingPolicyFound = ($failureBlockPolicyRows.Count -gt 0)

    if ($tokenResult.token_issued -eq $true -or $logTokenIssued -or ($latestFailureCa -and $blockingPolicyFound)) {
        $evidenceStoppedEarly = $true
        if ($tokenResult.token_issued -eq $true) {
            Write-Host "Token endpoint returned a token. Stopping evidence polling early."
        }
        elseif ($logTokenIssued) {
            Write-Host "Matching device-code sign-in shows token issuance in tenant logs. Stopping evidence polling early."
        }
        else {
            Write-Host "Matching device-code sign-in with blocking Conditional Access policy found. Stopping evidence polling early."
        }
        break
    }

    if ((Get-Date).AddSeconds($evidencePollSeconds) -lt $evidenceDeadline) {
        Start-Sleep -Seconds $evidencePollSeconds
    }
}
while ((Get-Date) -lt $evidenceDeadline -and $evidencePollCount -lt $maxEvidencePollAttempts)

$warnings = @()
$finalClaim = ""
$evidenceQuality = "Unknown"

if ($tokenResult.token_issued -eq $true) {
    $status = "FAIL_DEVICE_CODE_ALLOWED"
    $risk = "HIGH"
    $evidenceQuality = "High Risk"
    $summary = "The device-code flow completed and a token was issued for the decoy user."
    $finalClaim = "The tenant allowed the controlled device-code authentication flow. Device-code phishing resistance is not proven."
}
elseif ($latestMatchingSignIn -and [string]$latestMatchingSignIn.Status -eq "Failure" -and [string]$latestMatchingSignIn.ConditionalAccessStatus -match "failure" -and $failureBlockPolicyRows.Count -gt 0) {
    $status = "PASS_DEVICE_CODE_BLOCKED_STRONG"
    $risk = "LOW"
    $evidenceQuality = "Strong"
    $summary = "The tenant blocked the controlled device-code authentication attempt and the blocking Conditional Access policy was identified."
    $finalClaim = "The tenant resisted the controlled device-code authentication attempt. No token was issued."
}
elseif ($latestMatchingSignIn -and $latestMatchingSignIn.TokenLikelyIssuedFromLogs -eq $true) {
    $status = "FAIL_DEVICE_CODE_ALLOWED"
    $risk = "HIGH"
    $evidenceQuality = "High Risk"
    $summary = "The latest matching Microsoft Graph device-code sign-in succeeded."
    $finalClaim = "The tenant allowed the controlled device-code authentication flow. Device-code phishing resistance is not proven."
}
elseif ($latestMatchingSignIn) {
    $status = "PARTIAL_DEVICE_CODE_EVIDENCE"
    $risk = "MEDIUM"
    $evidenceQuality = "Partial"
    $summary = "A matching Microsoft Graph device-code sign-in was found, but no Conditional Access policy row with Result=Failure and Grant control=Block was attributed before timeout."
    $finalClaim = "The run found matching tenant sign-in evidence, but enforcement attribution is incomplete."
}
else {
    $status = "PARTIAL_NO_MATCHING_SIGNIN"
    $risk = "MEDIUM"
    $evidenceQuality = "None"
    $summary = "No matching Microsoft Graph device-code sign-in was found for the current decoy user before timeout."
    $finalClaim = "The validation could not prove whether device-code authentication is blocked because no matching sign-in was found."
}

if ($reportOnlyBlockPolicies.Count -gt 0) {
    $warnings += "Report-only device-code block policy configuration was detected. ZTVP does not treat report-only data as enforcement."
}

if ($tokenResult.token_issued -eq $true) {
    $warnings += "A token was issued during this controlled test. ZTVP did not store the token. Cleanup should revoke sessions and delete the decoy user."
}

$mainBlockingPolicy = $null
if ($failureBlockPolicyRows.Count -gt 0) {
    $mainBlockingPolicy = $failureBlockPolicyRows[0]
    $blockPolicyNames = @(
        $failureBlockPolicyRows | ForEach-Object {
            [string]$_.displayName
        } | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        } | Sort-Object -Unique
    )
}

$policyAttribution = [PSCustomObject]@{
    device_code_block_policy_applied = ($failureBlockPolicyRows.Count -gt 0)
    matching_signin_found = ($null -ne $latestMatchingSignIn)
    tenant_evidence_found = ($null -ne $latestMatchingSignIn)
    main_blocking_policy_name = if ($mainBlockingPolicy) { [string]$mainBlockingPolicy.displayName } else { $null }
    block_policy_names = @($blockPolicyNames)
    blocking_policy_rows = @($failureBlockPolicyRows)
    matched_policy_rows = if ($latestMatchingSignIn) { @($latestMatchingSignIn.ConditionalAccessPolicies) } else { @() }
    configured_enabled_block_policy_count = $enabledBlockPolicies.Count
    configured_report_only_block_policy_count = $reportOnlyBlockPolicies.Count
    token_outcome = $tokenResult.token_outcome
    token_issued = $tokenResult.token_issued
    interpretation = if ($blockPolicyNames.Count -gt 0) {
        "A Conditional Access device-code block policy was observed in the sign-in evidence."
    }
    elseif ($tokenResult.token_issued -eq $true) {
        "The token endpoint issued a token, so the device-code flow was allowed."
    }
    elseif ($enabledBlockPolicies.Count -gt 0) {
        "A device-code block policy exists, but this run did not find matching sign-in evidence."
    }
    else {
        "Policy attribution could not be determined from this run."
    }
}

$result = [PSCustomObject]@{
    scenario_id = "ID-C-002"
    scenario_name = "Device Code Flow Block Validation"
    pillar = "Identity"
    scope = "Cloud"
    generated_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    connected_account = $ctx.Account

    control_tested = "OAuth device-code authentication should be blocked for users in this tenant."
    expected_result = "The device-code flow should be blocked or denied before a token is issued."
    failure_condition = "The decoy user completes the device-code flow and the token endpoint returns an access token."
    test_method = "Fresh decoy identity, controlled OAuth device-code challenge, token endpoint polling, Microsoft Entra sign-in telemetry, Conditional Access attribution."
    final_claim = $finalClaim

    status = $status
    risk = $risk
    evidence_quality = $evidenceQuality
    executive_summary = $summary
    warnings = @($warnings)

    decoy_user = [PSCustomObject]@{
        id = $targetUserId
        user_principal_name = $targetUpn
    }

    device_code_challenge = [PSCustomObject]@{
        client_id = $clientId
        scope = [string]$challenge.scope
        started_at = [string]$challenge.started_at
        expires_at = [string]$challenge.expires_at
        verification_uri = [string]$challenge.verification_uri
        user_code = [string]$challenge.user_code
    }

    token_polling = $tokenResult
    policy_attribution = $policyAttribution
    configured_device_code_block_policies = @($configuredPolicies)
    matched_sign_in = $latestMatchingSignIn

    metrics = [PSCustomObject]@{
        token_issued = $tokenResult.token_issued
        tenant_evidence_found = ($null -ne $latestMatchingSignIn)
        matching_signin_found = ($null -ne $latestMatchingSignIn)
        latest_matching_signin_time_utc = if ($latestMatchingSignIn) { [string]$latestMatchingSignIn.CreatedDateTime } else { $null }
        main_blocking_policy_name = if ($mainBlockingPolicy) { [string]$mainBlockingPolicy.displayName } else { $null }
        poll_count = $tokenResult.poll_count
        poll_attempts = $evidencePollCount
        max_poll_attempts = $maxEvidencePollAttempts
        token_poll_attempts = $tokenResult.poll_count
        evidence_poll_attempts = $evidencePollCount
        evidence_max_poll_attempts = $maxEvidencePollAttempts
        evidence_poll_interval_seconds = $evidencePollSeconds
        polling_stopped_early = ($tokenResult.token_outcome -ne "TimeoutPending" -or $evidenceStoppedEarly)
        early_tenant_evidence_found = $tokenResult.early_tenant_evidence_found
        early_tenant_evidence_count = $tokenResult.early_tenant_evidence_count
        evidence_stopped_early = $evidenceStoppedEarly
        evidence_start_utc = $effectiveStartUtcDate.ToString("o")
        target_signins_total_retrieved = $evidenceAll.Count
        target_signins_inside_lookback = $deviceCodeRows.Count
        device_code_evidence_count = $deviceCodeRows.Count
        blocked_evidence_count = $blockedRows.Count
        block_policy_applied_count = $failureBlockPolicyRows.Count
        configured_enabled_block_policy_count = $enabledBlockPolicies.Count
        configured_report_only_block_policy_count = $reportOnlyBlockPolicies.Count
    }

    evidence = @($deviceCodeRows)
}

$result |
    ConvertTo-Json -Depth 100 |
    Set-Content -Path $reportPath -Encoding UTF8

try {
    if ($tokenResult.token_issued -eq $true -and -not [string]::IsNullOrWhiteSpace($targetUserId)) {
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$targetUserId/invalidateAllRefreshTokens" | Out-Null
    }
}
catch {}

Write-Host ""
Write-Host "========================================="
Write-Host "ID-C-002 COMPLETED"
Write-Host "========================================="
Write-Host ""
Write-Host "Status: $status"
Write-Host "Risk: $risk"
Write-Host "Evidence quality: $evidenceQuality"
Write-Host "Token outcome: $($tokenResult.token_outcome)"
Write-Host "Token issued: $($tokenResult.token_issued)"
Write-Host "Device-code evidence count: $($deviceCodeRows.Count)"
Write-Host "Blocked evidence count: $($blockedRows.Count)"
Write-Host "Block policy names: $($blockPolicyNames -join ', ')"
Write-Host "Report saved to: $reportPath"
Write-Host ""
