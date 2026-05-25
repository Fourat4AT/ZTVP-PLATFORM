param(
    [int]$PollMinutes = 8,
    [int]$LookbackMinutes = 240
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
        [int]$PollMinutes
    )

    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $deadline = (Get-Date).AddMinutes($PollMinutes)
    $interval = [Math]::Max(3, $InitialIntervalSeconds)

    $events = @()
    $tokenIssued = $false
    $tokenOutcome = "TimeoutPending"
    $lastError = $null
    $pollCount = 0

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

function Get-ZTVPSignInsForUser {
    param(
        [string]$TargetUpn,
        [string]$TargetUserId,
        [datetime]$StartUtcDate
    )

    $all = @()
    $startUtc = $StartUtcDate.ToString("o")
    $targetLower = $TargetUpn.Trim().ToLower()
    $safeOriginal = $TargetUpn.Replace("'", "''")
    $safeLower = $targetLower.Replace("'", "''")

    $queries = @()

    $filter1 = "createdDateTime ge $startUtc and userPrincipalName eq '$safeOriginal'"
    $queries += "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$([System.Uri]::EscapeDataString($filter1))"

    if ($safeLower -ne $safeOriginal) {
        $filter2 = "createdDateTime ge $startUtc and userPrincipalName eq '$safeLower'"
        $queries += "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$([System.Uri]::EscapeDataString($filter2))"
    }

    if (-not [string]::IsNullOrWhiteSpace($TargetUserId)) {
        $filter3 = "createdDateTime ge $startUtc and userId eq '$TargetUserId'"
        $queries += "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$([System.Uri]::EscapeDataString($filter3))"
    }

    foreach ($uri in $queries) {
        try {
            $all += @(Invoke-ZTVPPagedGraphQuery -Uri $uri -MaxPages 10)
        }
        catch {}
    }

    try {
        $recent = @(Invoke-ZTVPPagedGraphQuery -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000" -MaxPages 20)

        $all += @(
            $recent | Where-Object {
                $logUpn = ([string](Get-ZTVPValue -Object $_ -Name "userPrincipalName")).Trim().ToLower()
                $logUserId = [string](Get-ZTVPValue -Object $_ -Name "userId")

                (
                    $logUpn -eq $targetLower -or
                    (
                        -not [string]::IsNullOrWhiteSpace($TargetUserId) -and
                        $logUserId -eq $TargetUserId
                    )
                )
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

        try {
            $createdUtc = ([DateTimeOffset]::Parse($createdRaw)).UtcDateTime
            if ($createdUtc -ge $StartUtcDate) { $withinLookback = $true }
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

            if ($hasBlock -and $looksDeviceCode -and $isApplied) {
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
                deviceCodeDetected = $looksDeviceCode
                blockGrantDetected = $hasBlock
                blockPolicyApplied = ($hasBlock -and $looksDeviceCode -and $isApplied)
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

Write-Host ""
Write-Host "========================================="
Write-Host "ZTVP ID-C-002 - Device Code Flow Block Validation"
Write-Host "========================================="
Write-Host ""
Write-Host "Target user: $targetUpn"
Write-Host "Client ID: $clientId"
Write-Host "Polling token endpoint for result..."

$tokenResult = Poll-ZTVPDeviceCodeToken `
    -TenantId $tenantId `
    -ClientId $clientId `
    -DeviceCode $deviceCode `
    -InitialIntervalSeconds ([int]$challenge.interval_seconds) `
    -PollMinutes $PollMinutes

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

$rawSignIns = @(Get-ZTVPSignInsForUser -TargetUpn $targetUpn -TargetUserId $targetUserId -StartUtcDate $startUtcDate)
$evidenceAll = @(Convert-ZTVPDeviceCodeEvidence -SignIns $rawSignIns -StartUtcDate $startUtcDate -ClientId $clientId)

$evidenceRows = @(
    $evidenceAll | Where-Object {
        $_.WithinLookback -eq $true
    }
)

$deviceCodeRows = @(
    $evidenceRows | Where-Object {
        $_.DeviceCodeEvidence -eq $true -or $_.AppDisplayName -match "Graph|PowerShell|Command Line|ZTVP"
    }
)

$blockedRows = @(
    $evidenceRows | Where-Object {
        $_.Blocked -eq $true -or $_.BlockPolicyApplied -eq $true
    }
)

$blockPolicyNames = @()

foreach ($row in $evidenceRows) {
    if ($row.BlockPolicyNames) {
        $blockPolicyNames += @($row.BlockPolicyNames)
    }
}

$blockPolicyNames = @($blockPolicyNames | Where-Object {
    -not [string]::IsNullOrWhiteSpace([string]$_)
} | Sort-Object -Unique)

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
elseif ($blockedRows.Count -gt 0 -and $blockPolicyNames.Count -gt 0) {
    $status = "PASS_DEVICE_CODE_BLOCKED_STRONG"
    $risk = "LOW"
    $evidenceQuality = "Strong"
    $summary = "The tenant blocked the controlled device-code authentication attempt and the blocking Conditional Access policy was identified."
    $finalClaim = "The tenant resisted the controlled device-code authentication attempt. No token was issued."
}
elseif ($blockedRows.Count -gt 0) {
    $status = "PASS_DEVICE_CODE_BLOCKED"
    $risk = "LOW"
    $evidenceQuality = "Strong"
    $summary = "The tenant blocked or denied the controlled device-code authentication attempt."
    $finalClaim = "The tenant resisted the controlled device-code authentication attempt. No token was issued."
}
elseif ($tokenResult.token_outcome -eq "BlockedOrDenied") {
    $status = "PASS_BLOCKED_TOKEN_ENDPOINT"
    $risk = "LOW"
    $evidenceQuality = "Medium"
    $summary = "The token endpoint reported the device-code flow was blocked or denied, but Conditional Access sign-in attribution was not clearly found yet."
    $finalClaim = "The tenant did not issue a token for the controlled device-code attempt."
}
elseif ($deviceCodeRows.Count -gt 0 -and $tokenResult.token_issued -ne $true) {
    $status = "PARTIAL_DEVICE_CODE_EVIDENCE"
    $risk = "MEDIUM"
    $evidenceQuality = "Partial"
    $summary = "Device-code-related sign-in evidence was found, but a blocking policy was not clearly attributed."
    $finalClaim = "The run produced device-code telemetry, but enforcement attribution is incomplete."
}
elseif ($enabledBlockPolicies.Count -gt 0) {
    $status = "CONFIGURED_NOT_VALIDATED"
    $risk = "MEDIUM"
    $evidenceQuality = "Configuration Only"
    $summary = "An enabled device-code block policy was found, but no matching sign-in evidence was found for this exact decoy run."
    $finalClaim = "The tenant appears configured to block device-code flow, but this run did not prove enforcement."
}
elseif ($reportOnlyBlockPolicies.Count -gt 0) {
    $status = "REPORT_ONLY_NOT_ENFORCED"
    $risk = "MEDIUM"
    $evidenceQuality = "Configuration Only"
    $summary = "A report-only device-code block policy was found. Report-only policies do not prove enforcement."
    $finalClaim = "The tenant has report-only device-code blocking configuration, but enforcement was not proven."
}
else {
    $status = "NO_EVIDENCE"
    $risk = "MEDIUM"
    $evidenceQuality = "None"
    $summary = "No device-code sign-in evidence or enabled device-code block policy was found by this validation."
    $finalClaim = "The validation could not prove whether device-code authentication is blocked."
}

if ($reportOnlyBlockPolicies.Count -gt 0) {
    $warnings += "Report-only device-code block policy configuration was detected. ZTVP does not treat report-only data as enforcement."
}

if ($tokenResult.token_issued -eq $true) {
    $warnings += "A token was issued during this controlled test. ZTVP did not store the token. Cleanup should revoke sessions and delete the decoy user."
}

$policyAttribution = [PSCustomObject]@{
    device_code_block_policy_applied = ($blockPolicyNames.Count -gt 0)
    block_policy_names = @($blockPolicyNames)
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

    metrics = [PSCustomObject]@{
        token_issued = $tokenResult.token_issued
        poll_count = $tokenResult.poll_count
        target_signins_total_retrieved = $evidenceAll.Count
        target_signins_inside_lookback = $evidenceRows.Count
        device_code_evidence_count = $deviceCodeRows.Count
        blocked_evidence_count = $blockedRows.Count
        block_policy_applied_count = $blockPolicyNames.Count
        configured_enabled_block_policy_count = $enabledBlockPolicies.Count
        configured_report_only_block_policy_count = $reportOnlyBlockPolicies.Count
    }

    evidence = @($evidenceRows)
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
