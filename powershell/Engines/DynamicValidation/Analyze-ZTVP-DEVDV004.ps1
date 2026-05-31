param(
    [int]$WaitMinutes = 15,
    [int]$PollSeconds = 30,
    [string]$RunId = "",
    [switch]$WaitUntilEvidence
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "Directory.Read.All",
    "AuditLog.Read.All"
)

function Ensure-ZTVPGraphConnection {
    param([string[]]$Scopes)

    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    $needReconnect = $false

    if (-not $ctx) { $needReconnect = $true }
    else {
        $currentScopes = @()
        if ($ctx.Scopes) { $currentScopes = @($ctx.Scopes | ForEach-Object { $_.ToLower() }) }
        foreach ($scope in $Scopes) {
            if ($currentScopes -notcontains $scope.ToLower()) { $needReconnect = $true }
        }
    }

    if ($needReconnect) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
        Connect-MgGraph -Scopes $Scopes -ContextScope CurrentUser -NoWelcome | Out-Null
        $ctx = Get-MgContext
    }

    return $ctx
}

function Write-ZTVPJson {
    param([string]$Path, [object]$Object)
    $Object | ConvertTo-Json -Depth 100 | Set-Content -Path $Path -Encoding UTF8
}

function Invoke-ZTVPSafeGraphGet {
    param([string]$Uri)
    try { return Invoke-MgGraphRequest -Method GET -Uri $Uri }
    catch { return $null }
}

function Invoke-ZTVPGraphCollection {
    param([string]$Uri, [int]$MaxPages = 5)
    $items = @()
    $next = $Uri
    $pages = 0
    $errorText = $null
    while (-not [string]::IsNullOrWhiteSpace($next) -and $pages -lt $MaxPages) {
        try {
            $res = Invoke-MgGraphRequest -Method GET -Uri $next
            $pages++
            if ($res -and $res.value) { $items += @($res.value) }
            $next = [string]$res.'@odata.nextLink'
        }
        catch {
            $errorText = $_.Exception.Message
            break
        }
    }
    return [PSCustomObject]@{
        items = @($items)
        pages = $pages
        error = $errorText
        uri = $Uri
    }
}

function Convert-ZTVPDateString {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
    catch { return [string]$Value }
}

function Get-ZTVPUserRegisteredDevices {
    param([string]$UserId)
    $uri = "https://graph.microsoft.com/v1.0/users/$UserId/registeredDevices"
    try {
        $res = Invoke-MgGraphRequest -Method GET -Uri $uri
        $devices = @()
        if ($res -and $res.value) { $devices = @($res.value) }
        return [PSCustomObject]@{
            checked = $true
            error = $null
            devices = $devices
        }
    }
    catch {
        return [PSCustomObject]@{
            checked = $false
            error = $_.Exception.Message
            devices = @()
        }
    }
}

function Get-ZTVPDeviceById {
    param([string]$DeviceObjectId)
    if ([string]::IsNullOrWhiteSpace($DeviceObjectId)) {
        return [PSCustomObject]@{
            checked = $false
            exists = $false
            error = "Missing device object ID."
            device = $null
        }
    }
    $safeId = $DeviceObjectId.Replace("'", "''")
    $uri = "https://graph.microsoft.com/v1.0/devices/$safeId"
    try {
        $device = Invoke-MgGraphRequest -Method GET -Uri $uri
        return [PSCustomObject]@{
            checked = $true
            exists = $true
            error = $null
            device = $device
        }
    }
    catch {
        return [PSCustomObject]@{
            checked = $true
            exists = $false
            error = $_.Exception.Message
            device = $null
        }
    }
}

function Invoke-ZTVPFinalDeviceVerification {
    param([string]$UserId)
    $reg = Get-ZTVPUserRegisteredDevices -UserId $UserId
    $devices = @($reg.devices)
    $checks = @()
    foreach ($device in $devices) {
        $deviceId = [string]$device.id
        $exists = Get-ZTVPDeviceById -DeviceObjectId $deviceId
        $checks += [PSCustomObject]@{
            id = $deviceId
            display_name = $device.displayName
            device_id = $device.deviceId
            registeredDevices_returned = $true
            device_exists = [bool]$exists.exists
            device_check_error = $exists.error
            operating_system = $(if ($exists.device) { $exists.device.operatingSystem } else { $device.operatingSystem })
            trust_type = $(if ($exists.device) { $exists.device.trustType } else { $device.trustType })
            is_managed = $(if ($exists.device) { $exists.device.isManaged } else { $device.isManaged })
            is_compliant = $(if ($exists.device) { $exists.device.isCompliant } else { $device.isCompliant })
            account_enabled = $(if ($exists.device) { $exists.device.accountEnabled } else { $device.accountEnabled })
        }
    }
    return [PSCustomObject]@{
        registeredDevices_checked = [bool]$reg.checked
        registeredDevices_error = $reg.error
        registeredDevices_count = $devices.Count
        existing_linked_devices_count = @($checks | Where-Object { $_.device_exists }).Count
        device_checks = @($checks)
    }
}

function Get-ZTVPUserSignIns {
    param([string]$Upn, [datetime]$WindowStart)

    $startUtc = $WindowStart.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $safeUser = $Upn.Replace("'", "''")
    $filter = [uri]::EscapeDataString("userPrincipalName eq '$safeUser' and createdDateTime ge $startUtc")
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter&`$top=50"

    $res = Invoke-ZTVPSafeGraphGet -Uri $uri
    if ($res -and $res.value) { return @($res.value | Sort-Object createdDateTime -Descending) }
    return @()
}

function Get-ZTVPAuditEvents {
    param([datetime]$WindowStart)

    $startUtc = $WindowStart.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $filterText = "activityDateTime ge $startUtc"
    $filter = [uri]::EscapeDataString($filterText)
    $select = [uri]::EscapeDataString("id,activityDateTime,activityDisplayName,category,loggedByService,result,resultReason,initiatedBy,targetResources,additionalDetails")
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$filter&`$select=$select&`$top=200"

    $res = Invoke-ZTVPGraphCollection -Uri $uri -MaxPages 8
    $usedUri = $uri
    if (($res.items.Count -eq 0) -and $res.error) {
        $fallbackUri = "https://graph.microsoft.com/beta/auditLogs/directoryAudits?`$filter=$filter&`$select=$select&`$top=200"
        $fallback = Invoke-ZTVPGraphCollection -Uri $fallbackUri -MaxPages 8
        if ($fallback.items.Count -gt 0 -or -not $fallback.error) {
            $res = $fallback
            $usedUri = $fallbackUri
        }
    }
    return [PSCustomObject]@{
        events = @($res.items | Sort-Object activityDateTime -Descending)
        query_start_utc = $startUtc
        filter = $filterText
        uri = $usedUri
        raw_count = @($res.items).Count
        pages = $res.pages
        error = $res.error
    }
}

function Get-ZTVPAuditText {
    param([object]$Event)
    return (
        ([string]$Event.activityDisplayName) + " " +
        ([string]$Event.result) + " " +
        ([string]$Event.category) + " " +
        ([string]$Event.loggedByService) + " " +
        ([string]$Event.initiatedBy.user.userPrincipalName) + " " +
        ([string]$Event.initiatedBy.user.id) + " " +
        ($Event.targetResources | ConvertTo-Json -Depth 20 -Compress) + " " +
        ($Event.additionalDetails | ConvertTo-Json -Depth 20 -Compress)
    )
}

function Get-ZTVPAuditActivityKind {
    param([object]$Event)
    $activity = ([string]$Event.activityDisplayName).ToLowerInvariant()
    if ($activity -match "add\s+registered\s+owner" -or $activity -match "registered\s+owner") { return "add_owner" }
    if ($activity -match "add\s+registered\s+users" -or $activity -match "registered\s+users") { return "add_user" }
    if ($activity -match "unregister\s+device" -or $activity -match "unregistered\s+device") { return "unregister_device" }
    if ($activity -match "delete\s+device" -or $activity -match "deleted\s+device") { return "delete_device" }
    if ($activity -match "register\s+device" -or $activity -match "registered\s+device") { return "register_device" }
    if ($activity -match "update\s+device" -or $activity -match "updated\s+device") { return "update_device" }
    if ($activity -match "add\s+device" -or $activity -match "added\s+device") { return "add_device" }
    return ""
}

function Test-ZTVPAuditForDecoy {
    param([object]$Event, [string]$DecoyUpn, [string]$DecoyId)
    $text = (Get-ZTVPAuditText -Event $Event).ToLowerInvariant()
    return ($text.Contains($DecoyUpn.ToLowerInvariant()) -or $text.Contains($DecoyId.ToLowerInvariant()))
}

function Test-ZTVPDeviceAuditActivity {
    param([object]$Event)
    return -not [string]::IsNullOrWhiteSpace((Get-ZTVPAuditActivityKind -Event $Event))
}

function Get-ZTVPAuditTargetSummary {
    param([object]$Event)
    $targets = @()
    try {
        $targets = @($Event.targetResources | ForEach-Object {
            $parts = @()
            if ($_.displayName) { $parts += [string]$_.displayName }
            if ($_.userPrincipalName) { $parts += [string]$_.userPrincipalName }
            if ($_.id) { $parts += [string]$_.id }
            if ($_.type) { $parts += "type=$($_.type)" }
            ($parts -join " | ")
        } | Where-Object { $_ })
    } catch {}
    return ($targets -join "; ")
}

function Get-ZTVPAuditDeviceIds {
    param([object[]]$Events)
    $ids = @()
    foreach ($event in @($Events)) {
        try {
            foreach ($target in @($event.targetResources)) {
                $type = [string]$target.type
                if ($type -match "Device" -and $target.id) { $ids += [string]$target.id }
                foreach ($prop in @($target.modifiedProperties)) {
                    if ([string]$prop.displayName -match "device" -and $prop.newValue) { $ids += ([string]$prop.newValue).Trim('"') }
                }
            }
        } catch {}
    }
    return @($ids | Where-Object { $_ } | Select-Object -Unique)
}

function Get-ZTVPAuditDeviceNames {
    param([object[]]$Events)
    $names = @()
    foreach ($event in @($Events)) {
        try {
            foreach ($target in @($event.targetResources)) {
                $type = [string]$target.type
                if ($type -match "Device" -and $target.displayName) { $names += [string]$target.displayName }
            }
        } catch {}
    }
    return @($names | Where-Object { $_ } | Select-Object -Unique)
}

function Get-ZTVPInitiatedByValues {
    param([object[]]$Events)
    return @($Events | ForEach-Object {
        $upn = [string]$_.initiatedBy.user.userPrincipalName
        $app = [string]$_.initiatedBy.app.displayName
        if ($upn) { $upn } elseif ($app) { $app }
    } | Where-Object { $_ } | Select-Object -Unique)
}

function New-ZTVPAuditDebugRows {
    param([object[]]$Events, [string]$DecoyUpn, [string]$DecoyId, [datetime]$WindowStart)
    return @($Events | Select-Object -First 40 | ForEach-Object {
        $activityOk = Test-ZTVPDeviceAuditActivity -Event $_
        $timeOk = $true
        try { $timeOk = ([datetime]$_.activityDateTime).ToUniversalTime() -ge $WindowStart } catch {}
        $decoyOk = Test-ZTVPAuditForDecoy -Event $_ -DecoyUpn $DecoyUpn -DecoyId $DecoyId
        $reason = @()
        if (-not $timeOk) { $reason += "wrong time" }
        if (-not $activityOk) { $reason += "wrong activity" }
        if ($activityOk -and -not $decoyOk) { $reason += "no explicit decoy user/id in row" }
        if ($reason.Count -eq 0) { $reason += "accepted" }
        [PSCustomObject]@{
            time = Convert-ZTVPDateString -Value $_.activityDateTime
            service = [string]$_.loggedByService
            activity = [string]$_.activityDisplayName
            initiated_by = [string]$_.initiatedBy.user.userPrincipalName
            target = Get-ZTVPAuditTargetSummary -Event $_
            activity_match = [bool]$activityOk
            decoy_match = [bool]$decoyOk
            rejection_reason = ($reason -join "; ")
        }
    })
}

function Convert-ZTVPAuditRow {
    param([object]$Event)
    $target = Get-ZTVPAuditTargetSummary -Event $Event
    [PSCustomObject]@{
        time = Convert-ZTVPDateString -Value $Event.activityDateTime
        service = [string]$Event.loggedByService
        activity = [string]$Event.activityDisplayName
        status = [string]$Event.result
        target = $target
        initiated_by = [string]$Event.initiatedBy.user.userPrincipalName
        meaning = Get-ZTVPAuditMeaning -Activity ([string]$Event.activityDisplayName)
        why_it_matters = Get-ZTVPAuditMeaning -Activity ([string]$Event.activityDisplayName)
    }
}

function Get-ZTVPAuditMeaning {
    param([string]$Activity)
    if ($Activity -match "Add device") { return "A temporary device object was created." }
    if ($Activity -match "Register device") { return "Device Registration Service recorded device registration." }
    if ($Activity -match "Add registered owner|Add registered users") { return "Ownership or user linkage was attempted or created for the device." }
    if ($Activity -match "Delete device") { return "The device object was removed." }
    if ($Activity -match "Unregister device") { return "The device registration was removed." }
    if ($Activity -match "Update device") { return "The device object was updated during the lifecycle." }
    return "Device lifecycle activity near the validation window."
}

function New-ZTVPRecommendations {
    param([string]$Verdict)
    if ($Verdict -like "PASS*") {
        return @(
            "Keep device registration restrictions enabled.",
            "Continue monitoring device registration audit events.",
            "Review allowed users/groups for device registration.",
            "Periodically rerun DEV-DV-004."
        )
    }
    if ($Verdict -like "FAIL*") {
        return @(
            "Restrict normal users from registering or joining devices.",
            "Review Entra device settings: Users may register devices and Users may join devices.",
            "Use Conditional Access user action Register or join devices with MFA or trusted conditions.",
            "Reduce maximum devices per user.",
            "Remove the registered test device.",
            "Rerun after remediation."
        )
    }
    return @(
        "Increase the monitoring window.",
        "Check Entra Audit Logs manually.",
        "Confirm the decoy user was used.",
        "Check Entra Devices manually.",
        "Rerun with a fresh validation window."
    )
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "DEV-DV-004"
$statePath = Join-Path $scenarioDir "devdv004-state.json"
$reportPath = Join-Path $reportRoot "DEV-DV-004-result.json"

if (-not (Test-Path $statePath)) {
    throw "No DEV-DV-004 state file found. Prepare and launch first."
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json
$decoyUserId = [string]$state.decoy_user.id
$decoyUpn = [string]$state.decoy_user.user_principal_name
$windowStartUtc = [string]$state.validation_window_start_utc

if ([string]::IsNullOrWhiteSpace($windowStartUtc)) {
    throw "No validation window found. Start a fresh validation window first."
}

$windowStart = ([datetime]$windowStartUtc).ToUniversalTime()
$maxPollAttempts = [Math]::Max(1, [Math]::Ceiling((([Math]::Max(1, $WaitMinutes)) * 60) / ([Math]::Max(1, $PollSeconds))))
$pollCount = 0
$startedUtc = (Get-Date).ToUniversalTime()
$lastPollUtc = $null
$registeredDevices = @()
$registeredDevicesResult = $null
$registeredDevicesQueryCompleted = $false
$registeredDevicesError = $null
$linkedDevices = @()
$temporaryDeviceObserved = $false
$temporaryDevices = @()
$finalVerification = $null
$signIns = @()
$auditEvents = @()
$auditQueryInfo = $null
$deviceLifecycleAudits = @()
$registrationLikeAudits = @()
$unclearRegistrationLikeAudits = @()
$auditDebugRows = @()
$blockingSignIns = @()
$stopReason = ""
$stoppedEarly = $false

do {
    $pollCount++
    $lastPollUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    Write-Host "Checking registeredDevices for the DEV-DV-004 decoy user."
    $registeredDevicesResult = Get-ZTVPUserRegisteredDevices -UserId $decoyUserId
    $registeredDevicesQueryCompleted = [bool]$registeredDevicesResult.checked
    $registeredDevicesError = $registeredDevicesResult.error
    $registeredDevices = @($registeredDevicesResult.devices)
    $linkedDevices = @($registeredDevices)

    if ($linkedDevices.Count -gt 0) {
        $temporaryDeviceObserved = $true
        $temporaryDevices = @($linkedDevices)
        Write-Host "Temporary device observed. Checking lifecycle and final linked state."
    }
    elseif ($registeredDevicesQueryCompleted) {
        Write-Host "No device is currently linked to the decoy user."
    }

    Write-Host "Checking Entra audit logs for device registration lifecycle events."
    $auditQueryInfo = Get-ZTVPAuditEvents -WindowStart $windowStart
    $auditEvents = @($auditQueryInfo.events)
    $deviceLifecycleAudits = @(
        $auditEvents | Where-Object { Test-ZTVPDeviceAuditActivity -Event $_ }
    )
    $registrationLikeAudits = @(
        $deviceLifecycleAudits | Where-Object { Test-ZTVPAuditForDecoy -Event $_ -DecoyUpn $decoyUpn -DecoyId $decoyUserId }
    )
    $unclearRegistrationLikeAudits = @(
        $deviceLifecycleAudits | Where-Object { -not (Test-ZTVPAuditForDecoy -Event $_ -DecoyUpn $decoyUpn -DecoyId $decoyUserId) }
    )
    if ($registrationLikeAudits.Count -gt 0 -or $unclearRegistrationLikeAudits.Count -gt 0) {
        Write-Host "Device registration audit activity found. Lifecycle events: $($deviceLifecycleAudits.Count). Exact decoy matches: $($registrationLikeAudits.Count)."
    }

    Write-Host "Checking sign-in logs as optional supporting evidence."
    $signIns = Get-ZTVPUserSignIns -Upn $decoyUpn -WindowStart $windowStart
    $blockingSignIns = @(
        $signIns | Where-Object {
            ([int]$_.status.errorCode -ne 0) -or
            ([string]$_.conditionalAccessStatus -match "failure")
        }
    )

    $removedAuditCount = @($deviceLifecycleAudits | Where-Object { (Get-ZTVPAuditActivityKind -Event $_) -in @("unregister_device", "delete_device") }).Count
    $addRegisterAuditCount = @($deviceLifecycleAudits | Where-Object { (Get-ZTVPAuditActivityKind -Event $_) -in @("add_device", "register_device", "add_owner", "add_user") }).Count
    if ($removedAuditCount -gt 0) {
        Write-Host "Delete/Unregister lifecycle event found. Verifying final registeredDevices state."
    }
    if ($deviceLifecycleAudits.Count -gt 0 -and $removedAuditCount -gt 0 -and $addRegisterAuditCount -gt 0 -and $linkedDevices.Count -eq 0 -and $registeredDevicesQueryCompleted) {
        Write-Host "Final device state: Removed / Not linked."
        Write-Host "Evidence is sufficient. Stopping early and generating report."
        $stopReason = "audit lifecycle shows registration activity followed by unregister/delete and registeredDevices shows no linked device."
        $stoppedEarly = $true
        break
    }
    if ($deviceLifecycleAudits.Count -gt 0 -and $addRegisterAuditCount -gt 0 -and $removedAuditCount -eq 0 -and $linkedDevices.Count -eq 0 -and $registeredDevicesQueryCompleted) {
        Write-Host "Device registration audit activity found."
        Write-Host "Evidence is sufficient. Stopping early and generating report."
        $stopReason = "device registration activity was found, but registeredDevices shows no current linked device and removal was not proven."
        $stoppedEarly = $true
        break
    }

    if ($registrationLikeAudits.Count -gt 0) {
        Write-Host "Poll $pollCount/${maxPollAttempts}: exact-user audit events found. Checking final registered device state on next retry."
    }
    else {
        Write-Host "Poll $pollCount/${maxPollAttempts}: no linked device found yet. Retrying in $PollSeconds seconds."
    }

    if ($pollCount -lt $maxPollAttempts -or $WaitUntilEvidence) {
        Start-Sleep -Seconds $PollSeconds
    }
}
while ($WaitUntilEvidence -or $pollCount -lt $maxPollAttempts)

if ([string]::IsNullOrWhiteSpace($stopReason)) {
    $stopReason = "monitoring window ended."
}

$finalVerification = Invoke-ZTVPFinalDeviceVerification -UserId $decoyUserId
$finalLinkedDeviceChecks = @($finalVerification.device_checks | Where-Object { $_.device_exists })
$finalLinkedDevices = @($finalLinkedDeviceChecks)
$finalRegisteredDevicesCount = [int]$finalVerification.registeredDevices_count
$finalExistingLinkedDeviceCount = [int]$finalVerification.existing_linked_devices_count
$linkedDevices = @($finalLinkedDevices)
$registeredDevicesQueryCompleted = [bool]$finalVerification.registeredDevices_checked
$registeredDevicesError = $finalVerification.registeredDevices_error

$completedUtc = (Get-Date).ToUniversalTime()
$elapsedSeconds = [int][Math]::Max(0, ($completedUtc - $startedUtc).TotalSeconds)

$registerDeviceFound = @($deviceLifecycleAudits | Where-Object { (Get-ZTVPAuditActivityKind -Event $_) -eq "register_device" }).Count -gt 0
$addDeviceFound = @($deviceLifecycleAudits | Where-Object { (Get-ZTVPAuditActivityKind -Event $_) -eq "add_device" }).Count -gt 0
$addOwnerFound = @($deviceLifecycleAudits | Where-Object { (Get-ZTVPAuditActivityKind -Event $_) -eq "add_owner" }).Count -gt 0
$addUserFound = @($deviceLifecycleAudits | Where-Object { (Get-ZTVPAuditActivityKind -Event $_) -eq "add_user" }).Count -gt 0
$ownerUserFound = ($addOwnerFound -or $addUserFound)
$updateDeviceFound = @($deviceLifecycleAudits | Where-Object { (Get-ZTVPAuditActivityKind -Event $_) -eq "update_device" }).Count -gt 0
$deleteDeviceFound = @($deviceLifecycleAudits | Where-Object { (Get-ZTVPAuditActivityKind -Event $_) -eq "delete_device" }).Count -gt 0
$unregisterDeviceFound = @($deviceLifecycleAudits | Where-Object { (Get-ZTVPAuditActivityKind -Event $_) -eq "unregister_device" }).Count -gt 0
$removedFound = ($deleteDeviceFound -or $unregisterDeviceFound)
$addOrRegisterFound = ($registerDeviceFound -or $addDeviceFound -or $ownerUserFound)
$auditFound = $deviceLifecycleAudits.Count -gt 0
$unclearAuditFound = $unclearRegistrationLikeAudits.Count -gt 0
$signinFound = $signIns.Count -gt 0
$explicitDecoyAuditFound = $registrationLikeAudits.Count -gt 0
$detectedDeviceIds = @(Get-ZTVPAuditDeviceIds -Events $deviceLifecycleAudits)
$detectedDeviceNames = @(Get-ZTVPAuditDeviceNames -Events $deviceLifecycleAudits)
$initiatedByValues = @(Get-ZTVPInitiatedByValues -Events $deviceLifecycleAudits)
$auditDebugRows = @(New-ZTVPAuditDebugRows -Events $auditEvents -DecoyUpn $decoyUpn -DecoyId $decoyUserId -WindowStart $windowStart)
$auditConfidence = $(if ($explicitDecoyAuditFound) { "Strong" } elseif ($auditFound) { "Medium" } else { "Low" })

$status = "PASS_TENANT_BLOCKED_NORMAL_USER_DEVICE_REGISTRATION"
$risk = "LOW"
$finalDeviceState = "Not linked"
$evidenceConfidence = "Medium"
$summary = "No device was created or linked to the decoy user after the validation window."
$whatHappened = "Microsoft Graph registeredDevices shows no device currently linked to the DEV-DV-004 decoy user, and no strong registration lifecycle event was linked to that exact user."

if (-not $registeredDevicesQueryCompleted) {
    $status = "PARTIAL_EVIDENCE_FOUND_UNCLASSIFIED"
    $risk = "MEDIUM"
    $finalDeviceState = "Unknown"
    $evidenceConfidence = "Low"
    $summary = "ZTVP could not complete the registeredDevices primary evidence check."
    $whatHappened = "Microsoft Graph registeredDevices could not be confirmed for the DEV-DV-004 decoy user. Device lifecycle evidence is incomplete, so the result is PARTIAL."
}
elseif ($finalExistingLinkedDeviceCount -gt 0 -and -not $removedFound) {
    $status = "FAIL_NORMAL_USER_REGISTERED_DEVICE"
    $risk = "HIGH"
    $finalDeviceState = "Linked"
    $evidenceConfidence = "Strong"
    $summary = "A current device remains linked to the normal decoy user."
    $whatHappened = "A current device remains linked to the normal decoy user."
}
elseif ($auditFound -and $addOrRegisterFound -and $removedFound -and $finalExistingLinkedDeviceCount -eq 0) {
    if ($explicitDecoyAuditFound) {
        $status = "PASS_TENANT_BLOCKED_NORMAL_USER_DEVICE_REGISTRATION"
        $risk = "LOW"
    }
    else {
        $status = "PARTIAL_EVIDENCE_FOUND_UNCLASSIFIED"
        $risk = "MEDIUM"
    }
    $finalDeviceState = "Removed / Not linked"
    $evidenceConfidence = $auditConfidence
    $summary = "Device registration activity was observed, but the device was later unregistered/deleted. No device remains linked to the decoy user."
    $whatHappened = "ZTVP found device lifecycle audit events during the validation window. The audit trail shows device add/register activity followed by unregister/delete activity. Microsoft Graph registeredDevices shows 0 devices currently linked to the DEV-DV-004 decoy user. Final device state: Removed / Not linked."
}
elseif ($auditFound) {
    $status = "PARTIAL_EVIDENCE_FOUND_UNCLASSIFIED"
    $risk = "MEDIUM"
    $finalDeviceState = $(if ($finalExistingLinkedDeviceCount -eq 0) { "Not linked" } else { "Unknown" })
    $evidenceConfidence = $auditConfidence
    $summary = "Device registration-related audit events were found, but the lifecycle did not clearly prove the final ownership/link state."
    $whatHappened = "Device registration lifecycle activity was observed during the validation window, but registeredDevices currently shows no linked device and the lifecycle is incomplete or not explicitly tied to the decoy user."
}
elseif ($finalRegisteredDevicesCount -gt 0 -and $finalExistingLinkedDeviceCount -eq 0) {
    $status = "PARTIAL_EVIDENCE_FOUND_UNCLASSIFIED"
    $risk = "MEDIUM"
    $finalDeviceState = "Not linked"
    $evidenceConfidence = "Medium"
    $summary = "registeredDevices returned a device reference, but /devices did not confirm a current device object."
    $whatHappened = "Microsoft Graph registeredDevices returned a temporary or stale device reference, but the final /devices verification did not confirm a current Entra device object linked to the DEV-DV-004 decoy user."
}
elseif (-not $auditFound -and -not $signinFound -and $pollCount -ge $maxPollAttempts) {
    $status = "PARTIAL_EVIDENCE_FOUND_UNCLASSIFIED"
    $risk = "MEDIUM"
    $finalDeviceState = "Not linked"
    $evidenceConfidence = "Low"
    $summary = "No evidence arrived before timeout. registeredDevices shows no linked device, but audit evidence did not confirm the attempted lifecycle."
    $whatHappened = "No device remains linked to the decoy user, but no device lifecycle evidence arrived before timeout. Wait longer or check Entra logs manually if the Sandbox attempt was definitely performed."
}
elseif ($finalExistingLinkedDeviceCount -eq 0 -and -not $auditFound) {
    $status = "PASS_TENANT_BLOCKED_NORMAL_USER_DEVICE_REGISTRATION"
    $risk = "LOW"
    $finalDeviceState = "Not linked"
    $evidenceConfidence = "Medium"
    $summary = "No device was created or linked to the decoy user after the validation window."
    $whatHappened = "No device was created or linked to the decoy user after the validation window."
}

$selectedDevice = $null
if ($linkedDevices.Count -gt 0) { $selectedDevice = $linkedDevices | Select-Object -First 1 }

$found = [PSCustomObject]@{
    registered_devices_query_completed = [bool]$registeredDevicesQueryCompleted
    temporary_device_observed = [bool]$temporaryDeviceObserved
    current_registered_devices_linked = $finalExistingLinkedDeviceCount
    final_graph_registered_devices_count = $finalRegisteredDevicesCount
    registered_devices_linked_to_decoy_user = $finalExistingLinkedDeviceCount
    device_still_exists_in_devices = $(if ($finalVerification.device_checks.Count -gt 0) { if ($finalExistingLinkedDeviceCount -gt 0) { "Yes" } else { "No" } } else { "Unknown" })
    device_linked_to_decoy_user = $(if ($finalExistingLinkedDeviceCount -gt 0) { "Yes" } elseif (-not $registeredDevicesQueryCompleted) { "Unknown" } else { "No" })
    audit_events_found = [bool]$auditFound
    lifecycle_events_count = $deviceLifecycleAudits.Count
    exact_decoy_audit_events_count = $registrationLikeAudits.Count
    unclear_lifecycle_events_count = $unclearRegistrationLikeAudits.Count
    register_device_event_found = [bool]$registerDeviceFound
    add_device_event_found = [bool]$addDeviceFound
    add_owner_event_found = [bool]$addOwnerFound
    add_user_event_found = [bool]$addUserFound
    add_owner_or_user_event_found = [bool]$ownerUserFound
    update_device_event_found = [bool]$updateDeviceFound
    unregister_device_event_found = [bool]$unregisterDeviceFound
    delete_device_event_found = [bool]$deleteDeviceFound
    unregister_or_delete_event_found = [bool]$removedFound
    unclear_audit_events_found = [bool]$unclearAuditFound
    detected_device_id = $(if ($finalLinkedDevices.Count -gt 0) { ($finalLinkedDevices | Select-Object -First 1).id } else { ($detectedDeviceIds | Select-Object -First 1) })
    detected_device_name = $(if ($finalLinkedDevices.Count -gt 0) { ($finalLinkedDevices | Select-Object -First 1).display_name } else { ($detectedDeviceNames | Select-Object -First 1) })
    initiated_by_values = @($initiatedByValues)
    sign_in_evidence_found = [bool]$signinFound
    final_device_state = $finalDeviceState
    evidence_confidence = $evidenceConfidence
}

$auditTrail = @($deviceLifecycleAudits | Sort-Object activityDateTime | Select-Object -First 50 | ForEach-Object { Convert-ZTVPAuditRow -Event $_ })
$unclearAuditTrail = @($unclearRegistrationLikeAudits | Sort-Object activityDateTime | Select-Object -First 25 | ForEach-Object { Convert-ZTVPAuditRow -Event $_ })
$auditDebug = [PSCustomObject]@{
    query_start_utc = $(if ($auditQueryInfo) { $auditQueryInfo.query_start_utc } else { $windowStartUtc })
    filter = $(if ($auditQueryInfo) { $auditQueryInfo.filter } else { "activityDateTime ge $windowStartUtc" })
    uri = $(if ($auditQueryInfo) { $auditQueryInfo.uri } else { "" })
    pages_read = $(if ($auditQueryInfo) { $auditQueryInfo.pages } else { 0 })
    raw_audit_rows_returned = $(if ($auditQueryInfo) { $auditQueryInfo.raw_count } else { 0 })
    lifecycle_rows_after_filtering = $deviceLifecycleAudits.Count
    exact_decoy_rows_after_filtering = $registrationLikeAudits.Count
    unclear_lifecycle_rows_after_filtering = $unclearRegistrationLikeAudits.Count
    query_error = $(if ($auditQueryInfo) { $auditQueryInfo.error } else { $null })
        sample_row_diagnostics = @($auditDebugRows)
        decoy_user_id = $decoyUserId
        decoy_user_principal_name = $decoyUpn
        temporary_device_ids_checked = @($temporaryDevices | ForEach-Object { $_.id } | Where-Object { $_ } | Select-Object -Unique)
        final_device_ids_checked = @($finalVerification.device_checks | ForEach-Object { $_.id } | Where-Object { $_ } | Select-Object -Unique)
    }

$result = [PSCustomObject]@{
    scenario_id = "DEV-DV-004"
    display_id = "DEV-DV-004"
    scenario_name = "Sandbox Device Registration Abuse Probe"
    pillar = "Devices"
    scope = "Identity Device Trust"
    mode = "Windows Sandbox Device Registration Validation"
    run_id = $RunId
    started_utc = $windowStartUtc
    validation_start_utc = $windowStartUtc
    completed_utc = $completedUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
    generated_at = (Get-Date).ToString("s")
    tenant_id = $state.tenant_id
    operator_account = $ctx.Account
    status = $status
    risk = $risk
    executive_summary = $summary
    final_claim = $whatHappened
    evidence_quality = $evidenceConfidence
    what_ztvp_found = $found
    what_ztvp_thinks_happened = $whatHappened
    timer = [PSCustomObject]@{
        monitoring_window_minutes = $WaitMinutes
        retry_interval_seconds = $PollSeconds
        poll_attempts = $pollCount
        max_poll_attempts = $maxPollAttempts
        elapsed_seconds = $elapsedSeconds
        stopped_early = $stoppedEarly
        stop_reason = $stopReason
        last_poll_utc = $lastPollUtc
    }
    decoy_user = [PSCustomObject]@{
        id = $decoyUserId
        user_principal_name = $decoyUpn
        display_name = $state.decoy_user.display_name
        password_stored_in_report = $false
    }
    detected_device = $(if ($selectedDevice) {
        [PSCustomObject]@{
            id = $selectedDevice.id
            display_name = $selectedDevice.display_name
            device_id = $selectedDevice.device_id
            operating_system = $selectedDevice.operating_system
            trust_type = $selectedDevice.trust_type
            is_managed = $selectedDevice.is_managed
            is_compliant = $selectedDevice.is_compliant
            account_enabled = $selectedDevice.account_enabled
            source = "Final registeredDevices + /devices verification"
        }
    } elseif ($detectedDeviceIds.Count -gt 0 -or $detectedDeviceNames.Count -gt 0) {
        [PSCustomObject]@{
            id = ($detectedDeviceIds | Select-Object -First 1)
            display_name = ($detectedDeviceNames | Select-Object -First 1)
            source = "Entra audit lifecycle"
        }
    } else { $null })
    final_device_state = [PSCustomObject]@{
        device_linked_to_decoy = $(if ($finalExistingLinkedDeviceCount -gt 0) { "Yes" } elseif (-not $registeredDevicesQueryCompleted -or $finalDeviceState -eq "Unknown") { "Unknown" } else { "No" })
        temporary_device_observed = [bool]$temporaryDeviceObserved
        current_registered_device_count = $finalExistingLinkedDeviceCount
        final_graph_registered_devices_count = $finalRegisteredDevicesCount
        registered_device_count = $finalExistingLinkedDeviceCount
        linked_device_ids = @($finalLinkedDevices | ForEach-Object { $_.id })
        temporary_device_ids = @($temporaryDevices | ForEach-Object { $_.id })
        device_still_exists_in_devices = $(if ($finalVerification.device_checks.Count -gt 0) { if ($finalExistingLinkedDeviceCount -gt 0) { "Yes" } else { "No" } } else { "Unknown" })
        decoy_user_devices_tab_equivalent = $finalExistingLinkedDeviceCount
        removed_or_unregistered_evidence = [bool]$removedFound
        state = $finalDeviceState
        final_verification = $finalVerification
    }
    evidence_sources = [PSCustomObject]@{
        registeredDevices = [PSCustomObject]@{
            checked = [bool]$registeredDevicesQueryCompleted
            found = ($finalExistingLinkedDeviceCount -gt 0)
            count = $finalExistingLinkedDeviceCount
            final_graph_count = $finalRegisteredDevicesCount
            error = $registeredDevicesError
        }
        audit_logs = [PSCustomObject]@{
            checked = $true
            found = [bool]$auditFound
            count = $deviceLifecycleAudits.Count
            exact_decoy_count = $registrationLikeAudits.Count
            unclear_count = $unclearRegistrationLikeAudits.Count
            raw_count = $(if ($auditQueryInfo) { $auditQueryInfo.raw_count } else { 0 })
            query_error = $(if ($auditQueryInfo) { $auditQueryInfo.error } else { $null })
        }
        sign_in_logs = [PSCustomObject]@{
            checked = $true
            found = [bool]$signinFound
            count = $signIns.Count
            blocking_or_failed_count = $blockingSignIns.Count
        }
    }
    audit_trail = @($auditTrail)
    unclear_audit_trail = @($unclearAuditTrail)
    audit_debug = $auditDebug
    evidence = [PSCustomObject]@{
        tenant_registration_decision = [PSCustomObject]@{
            decision = $(if ($linkedDevices.Count -gt 0) { "Allowed" } elseif ($finalDeviceState -match "Removed") { "Removed / not linked" } elseif ($status -like "PASS*") { "Not linked" } else { "Unclear" })
            tested_user = $decoyUpn
            graph_check = "GET /users/{decoyUserId}/registeredDevices"
            devices_linked_to_decoy = $linkedDevices.Count
            meaning = $(if ($linkedDevices.Count -gt 0) { "The decoy user introduced a device identity." } elseif ($finalDeviceState -match "Removed") { "The registration lifecycle ended with no linked device." } else { "The decoy user did not introduce a final linked device identity." })
        }
        registered_device_count_after_window = $linkedDevices.Count
        current_registered_devices_linked = $finalExistingLinkedDeviceCount
        final_graph_registered_devices_count = $finalRegisteredDevicesCount
        temporary_device_observed = [bool]$temporaryDeviceObserved
        device_still_exists_in_devices = $(if ($finalVerification.device_checks.Count -gt 0) { if ($finalExistingLinkedDeviceCount -gt 0) { "Yes" } else { "No" } } else { "Unknown" })
        decoy_user_devices_tab_equivalent = $finalExistingLinkedDeviceCount
        device_linked_to_decoy_user = $(if ($finalExistingLinkedDeviceCount -gt 0) { "Yes" } elseif (-not $registeredDevicesQueryCompleted -or $finalDeviceState -eq "Unknown") { "Unknown" } else { "No" })
        sign_in_count_after_window = $signIns.Count
        blocking_sign_in_count_after_window = $blockingSignIns.Count
        registration_like_audit_count_after_window = $deviceLifecycleAudits.Count
        exact_decoy_registration_like_audit_count_after_window = $registrationLikeAudits.Count
        unclear_registration_like_audit_count_after_window = $unclearRegistrationLikeAudits.Count
        lifecycle_summary = [PSCustomObject]@{
            add_device_found = [bool]$addDeviceFound
            register_device_found = [bool]$registerDeviceFound
            add_owner_found = [bool]$addOwnerFound
            add_user_found = [bool]$addUserFound
            unregister_device_found = [bool]$unregisterDeviceFound
            delete_device_found = [bool]$deleteDeviceFound
            update_device_found = [bool]$updateDeviceFound
            lifecycle_events_count = $deviceLifecycleAudits.Count
            exact_decoy_events_count = $registrationLikeAudits.Count
            detected_device_id = ($detectedDeviceIds | Select-Object -First 1)
            detected_device_name = ($detectedDeviceNames | Select-Object -First 1)
            initiated_by_values = @($initiatedByValues)
            target_values = @($auditTrail | ForEach-Object { $_.target } | Where-Object { $_ } | Select-Object -Unique)
        }
        registered_devices = @($linkedDevices | ForEach-Object {
            [PSCustomObject]@{
                id = $_.id
                display_name = $_.display_name
                device_id = $_.device_id
                operating_system = $_.operating_system
                trust_type = $_.trust_type
                is_managed = $_.is_managed
                is_compliant = $_.is_compliant
                device_exists = $_.device_exists
            }
        })
        temporary_registered_devices = @($temporaryDevices | ForEach-Object {
            [PSCustomObject]@{
                id = $_.id
                display_name = $_.displayName
                device_id = $_.deviceId
                operating_system = $_.operatingSystem
                trust_type = $_.trustType
                is_managed = $_.isManaged
                is_compliant = $_.isCompliant
            }
        })
        final_device_existence_checks = @($finalVerification.device_checks)
        sign_ins = @($signIns | Select-Object -First 10 | ForEach-Object {
            [PSCustomObject]@{
                created_date_time = Convert-ZTVPDateString -Value $_.createdDateTime
                app = $_.appDisplayName
                resource = $_.resourceDisplayName
                error_code = $_.status.errorCode
                failure_reason = $_.status.failureReason
                ca_status = $_.conditionalAccessStatus
            }
        })
        audit_events = @($auditTrail)
        unclear_audit_events = @($unclearAuditTrail)
        audit_debug = $auditDebug
    }
    metrics = [PSCustomObject]@{
        decoy_user_created = $true
        sandbox_launched = $state.sandbox.launched
        evidence_found = ($linkedDevices.Count -gt 0 -or $auditFound -or $unclearAuditFound -or $signinFound)
        temporary_device_observed = [bool]$temporaryDeviceObserved
        device_registered_or_linked = ($finalExistingLinkedDeviceCount -gt 0)
        registered_devices_query_completed = [bool]$registeredDevicesQueryCompleted
        registered_devices_linked_count = $finalExistingLinkedDeviceCount
        final_graph_registered_devices_count = $finalRegisteredDevicesCount
        device_still_exists_in_devices = $(if ($finalVerification.device_checks.Count -gt 0) { if ($finalExistingLinkedDeviceCount -gt 0) { "Yes" } else { "No" } } else { "Unknown" })
        audit_events_found = [bool]$auditFound
        unclear_audit_events_found = [bool]$unclearAuditFound
        audit_event_count = $deviceLifecycleAudits.Count
        exact_decoy_audit_event_count = $registrationLikeAudits.Count
        audit_raw_row_count = $(if ($auditQueryInfo) { $auditQueryInfo.raw_count } else { 0 })
        sign_in_evidence_found = [bool]$signinFound
        final_device_state = $finalDeviceState
        poll_attempts = $pollCount
        max_poll_attempts = $maxPollAttempts
        poll_interval_seconds = $PollSeconds
        elapsed_seconds = $elapsedSeconds
        stopped_early = $stoppedEarly
        stop_reason = $stopReason
        cleanup_required = $true
    }
    cleanup = [PSCustomObject]@{
        decoy_user_cleanup_required = $true
        cleanup_completed = $false
        status = "Pending"
    }
    recommendations = New-ZTVPRecommendations -Verdict $status
    limitations = @(
        "This scenario validates the Windows Sandbox registration path, not every possible platform.",
        "Entra audit and device data can be delayed.",
        "If a device is created, cleanup may require deleting the device object manually if Graph delete permissions are missing."
    )
}

$state.detected_device = $result.detected_device
Write-ZTVPJson -Path $statePath -Object $state
Write-ZTVPJson -Path $reportPath -Object $result

Write-Host ""
Write-Host "DEV-DV-004 sandbox device registration analysis completed."
Write-Host "Status: $status"
Write-Host "Risk: $risk"
Write-Host "Polls used: $pollCount / $maxPollAttempts"
Write-Host "Stop reason: $stopReason"
Write-Host "Registered devices linked to decoy user: $($linkedDevices.Count)"
Write-Host "Device linked to decoy user: $($found.device_linked_to_decoy_user)"
Write-Host "Registration lifecycle audits linked to decoy user: $($registrationLikeAudits.Count)"
Write-Host "Unclear registration lifecycle audits: $($unclearRegistrationLikeAudits.Count)"
Write-Host "Final device state: $finalDeviceState"
Write-Host "Evidence confidence: $evidenceConfidence"
Write-Host "Supporting sign-ins: $($signIns.Count)"
Write-Host "Report: $reportPath"
Write-Host ""
