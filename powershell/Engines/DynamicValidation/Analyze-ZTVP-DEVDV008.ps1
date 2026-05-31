param(
    [int]$WaitMinutes = 5,
    [int]$PollSeconds = 30
)

$ErrorActionPreference = "Stop"

if ($WaitMinutes -lt 0 -or $WaitMinutes -gt 30) {
    throw "WaitMinutes must be between 0 and 30."
}
if ($PollSeconds -lt 5 -or $PollSeconds -gt 300) {
    throw "PollSeconds must be between 5 and 300."
}

function Write-ZTVPJson {
    param([string]$Path, [object]$Object)
    $Object | ConvertTo-Json -Depth 100 | Set-Content -Path $Path -Encoding UTF8
}

function ConvertTo-ZTVPArray {
    param([object]$Value)
    if ($null -eq $Value) { return @() }
    return @($Value)
}

function ConvertTo-ZTVPUtcDate {
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { return ([datetimeoffset]::Parse([string]$Value)).UtcDateTime } catch { return $null }
}

function Set-ZTVPObjectProperty {
    param([object]$Object, [string]$Name, [object]$Value)
    if ($Object.PSObject.Properties[$Name]) { $Object.$Name = $Value }
    else { $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value }
}

function Get-ZTVPHttpErrorDetail {
    param([object]$ErrorRecord)
    $reason = $ErrorRecord.Exception.Message
    try {
        $response = $ErrorRecord.Exception.Response
        if ($response) {
            $statusCode = [int]$response.StatusCode
            $statusDescription = [string]$response.StatusDescription
            if ($statusCode) { $reason = "$reason HTTP $statusCode $statusDescription".Trim() }
            $stream = $response.GetResponseStream()
            if ($stream) {
                $reader = [System.IO.StreamReader]::new($stream)
                $responseBody = $reader.ReadToEnd()
                if (-not [string]::IsNullOrWhiteSpace($responseBody)) {
                    $reason = "$reason Response: $responseBody"
                }
            }
        }
    }
    catch {}
    return $reason
}

function Get-ZTVPMdeToken {
    $tokenCachePath = Join-Path (Get-Location) "powershell\Auth\ztvp-defenderxdr-token-cache.json"
    if (-not (Test-Path $tokenCachePath)) {
        throw "Defender XDR API connection required. Connect Defender XDR API before running tenant evidence analysis."
    }

    $cache = Get-Content $tokenCachePath -Raw | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace([string]$cache.access_token)) {
        throw "Defender XDR API connection required. Token cache does not contain an access token."
    }
    if ($cache.resource -and $cache.resource -ne "https://api.security.microsoft.com") {
        throw "Defender XDR token cache was created for the wrong resource: $($cache.resource)."
    }
    if ($cache.scope -ne "https://api.security.microsoft.com/AdvancedHunting.Read") {
        throw "Defender XDR token cache was created for the wrong scope: $($cache.scope)."
    }
    if ($cache.expires_on) {
        $expiresUtc = ConvertTo-ZTVPUtcDate -Value $cache.expires_on
        if ($expiresUtc -and $expiresUtc -le (Get-Date).ToUniversalTime().AddMinutes(5)) {
            throw "Defender XDR token is invalid or expired. Reconnect Defender XDR API."
        }
    }

    $accessToken = [string]$cache.access_token
    Invoke-ZTVPMdeAdvancedHunting -Query "DeviceInfo | take 1" -Token $accessToken | Out-Null
    return $accessToken
}

function Invoke-ZTVPMdeAdvancedHunting {
    param([string]$Query, [string]$Token)
    $body = @{ Query = $Query } | ConvertTo-Json -Depth 10
    $headers = @{
        Authorization = "Bearer $Token"
        "Content-Type" = "application/json"
    }
    try {
        $response = Invoke-RestMethod -Method POST -Uri "https://api.security.microsoft.com/api/advancedhunting/run" -Headers $headers -Body $body -ErrorAction Stop
        return @(ConvertTo-ZTVPArray -Value $response.Results)
    }
    catch {
        $reason = Get-ZTVPHttpErrorDetail -ErrorRecord $_
        throw "Defender XDR Advanced Hunting query failed. Query: $Query Reason: $reason"
    }
}

function New-ZTVPKqlString {
    param([string]$Value)
    return ($Value -replace '"', '\"')
}

function Get-ZTVPFirstValue {
    param([object[]]$Rows, [string[]]$Names)
    foreach ($row in @($Rows)) {
        if ($null -eq $row) { continue }
        foreach ($name in $Names) {
            if ($row.PSObject.Properties[$name] -and -not [string]::IsNullOrWhiteSpace([string]$row.$name)) {
                return [string]$row.$name
            }
        }
    }
    return ""
}

function Test-ZTVPDevDv008AlertRow {
    param([object]$Row)

    if ($null -eq $Row) { return $false }

    $title = [string]$Row.Title
    if ([string]::IsNullOrWhiteSpace($title) -and $Row.PSObject.Properties["AlertTitle"]) { $title = [string]$Row.AlertTitle }
    $category = [string]$Row.Category
    if ([string]::IsNullOrWhiteSpace($category) -and $Row.PSObject.Properties["AlertCategory"]) { $category = [string]$Row.AlertCategory }
    $detectionSource = [string]$Row.DetectionSource
    if ([string]::IsNullOrWhiteSpace($detectionSource) -and $Row.PSObject.Properties["AlertDetectionSource"]) { $detectionSource = [string]$Row.AlertDetectionSource }
    if ([string]::IsNullOrWhiteSpace($detectionSource) -and $Row.PSObject.Properties["EvidenceDetectionSource"]) { $detectionSource = [string]$Row.EvidenceDetectionSource }
    $serviceSource = [string]$Row.ServiceSource

    $combined = "$title $category $detectionSource $serviceSource"
    if ($combined -match "EICAR|EICAR_Test_File|Virus:DOS/EICAR|malware was prevented") { return $false }
    if ($category -match "^Malware$" -and $title -match "EICAR|malware") { return $false }

    if ($title -match "Microsoft Defender Antivirus tampering|Defender Antivirus tampering|Antivirus tampering|Defender tampering|tampering") { return $true }
    if ($category -match "DefenseEvasion|Defense Evasion") { return $true }
    if ($detectionSource -match "EDR") { return $true }
    if ($combined -match "T1562\.001|Disable or Modify Tools|Set-MpPreference|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableBlockAtFirstSeen|TamperProtectionConfigChangeAttempt|TamperingAttempt") { return $true }

    return $false
}

function Test-ZTVPTamperTimelineEvent {
    param([object]$Row)

    if ($null -eq $Row) { return $false }

    $actionType = [string]$Row.ActionType
    $commandLine = [string]$Row.InitiatingProcessCommandLine
    $additionalFields = ""
    try { $additionalFields = $Row.AdditionalFields | ConvertTo-Json -Depth 20 -Compress } catch { $additionalFields = [string]$Row.AdditionalFields }
    $eventText = "$actionType $commandLine $additionalFields"

    if ($actionType -in @("TamperingAttempt", "TamperProtectionConfigChangeAttempt")) { return $true }
    if ($actionType -eq "PowerShellCommand" -and $commandLine -match "Invoke-ZTVPTamperAttempt|Set-MpPreference|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableBlockAtFirstSeen") { return $true }
    if ($commandLine -match "Invoke-ZTVPTamperAttempt|Set-MpPreference|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableBlockAtFirstSeen") { return $true }
    if ($eventText -match "Tamper|TamperingAttempt|TamperProtection|blocked the modification|disableblockatfirstseen|disableioavprotection|disablebehaviormonitoring|disablerealtimemonitoring|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableBlockAtFirstSeen") { return $true }

    return $false
}

function Get-ZTVPParsedTimelineEvidence {
    param([object[]]$Rows)

    $items = @()
    foreach ($row in @($Rows)) {
        if ($null -eq $row) { continue }

        $additionalRaw = [string]$row.AdditionalFields
        $additionalObject = $null
        if (-not [string]::IsNullOrWhiteSpace($additionalRaw)) {
            try {
                $additionalObject = $additionalRaw | ConvertFrom-Json
            }
            catch {}
        }

        $status = ""
        $tamperingAction = ""
        $target = ""
        $tamperProtectionStatus = ""
        if ($additionalObject) {
            if ($additionalObject.PSObject.Properties["Status"]) { $status = [string]$additionalObject.Status }
            if ($additionalObject.PSObject.Properties["TamperingAction"]) { $tamperingAction = [string]$additionalObject.TamperingAction }
            if ($additionalObject.PSObject.Properties["Target"]) { $target = [string]$additionalObject.Target }
            if ($additionalObject.PSObject.Properties["TamperProtectionStatus"]) { $tamperProtectionStatus = [string]$additionalObject.TamperProtectionStatus }
        }

        $text = "$($row.ActionType) $($row.InitiatingProcessCommandLine) $additionalRaw $status $tamperingAction $target $tamperProtectionStatus"
        $blockedSetting = "Protected Defender setting"
        if ($text -match "disableblockatfirstseen") { $blockedSetting = "DisableBlockAtFirstSeen" }
        elseif ($text -match "disableioavprotection") { $blockedSetting = "DisableIOAVProtection" }
        elseif ($text -match "disablebehaviormonitoring") { $blockedSetting = "DisableBehaviorMonitoring" }
        elseif ($text -match "disablerealtimemonitoring") { $blockedSetting = "DisableRealtimeMonitoring" }

        $blocked = (
            ([string]$row.ActionType -eq "TamperProtectionConfigChangeAttempt") -or
            ([string]$row.ActionType -eq "TamperingAttempt" -and $status -eq "Blocked") -or
            ($status -eq "Blocked") -or
            ($text -match "blocked") -or
            ($text -match "disableblockatfirstseen|disableioavprotection|disablebehaviormonitoring|disablerealtimemonitoring")
        )

        $summary = if ($blocked -and $tamperingAction -match "RegistryModification") {
            "Registry modification blocked"
        }
        elseif ($blocked) {
            "Protected Defender setting blocked"
        }
        else {
            ""
        }

        $items += [PSCustomObject]@{
            Timestamp = $row.Timestamp
            DeviceName = $row.DeviceName
            ActionType = $row.ActionType
            Status = $status
            TamperingAction = $tamperingAction
            Target = $target
            BlockedSetting = $blockedSetting
            TamperProtectionStatus = $tamperProtectionStatus
            Blocked = [bool]$blocked
            BlockedModificationSummary = $summary
            InitiatingProcessFileName = $row.InitiatingProcessFileName
            InitiatingProcessCommandLine = $row.InitiatingProcessCommandLine
        }
    }

    return @($items)
}

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "DEV-DV-008"
$htmlDir = Join-Path $reportRoot "Html"
$statePath = Join-Path $scenarioDir "devdv008-state.json"
$localEvidencePath = Join-Path $scenarioDir "devdv008-local-evidence.json"
$reportPath = Join-Path $reportRoot "DEV-DV-008-result.json"
$htmlPath = Join-Path $htmlDir "DEV-DV-008-result.html"

if (-not (Test-Path $statePath)) {
    throw "No DEV-DV-008 state file found. Start a fresh validation window first."
}
New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null

$state = Get-Content $statePath -Raw | ConvertFrom-Json
$windowStartUtc = [string]$state.validation_window_start_utc
$windowStartDateUtc = ConvertTo-ZTVPUtcDate -Value $windowStartUtc
if ($null -eq $windowStartDateUtc) { throw "State validation_window_start_utc is invalid. Start a fresh validation window again." }

$runId = [string]$state.run_id
$testDeviceName = [string]$state.test_device_name
$cloudEvidenceMode = if ($state.cloud_evidence_mode) { [string]$state.cloud_evidence_mode } else { "Tenant + Local Evidence" }
$tenantId = [string]$state.tenant_id
$clientId = [string]$state.client_id
$tenantDisplayName = [string]$state.tenant_display_name
$analysisStartedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Set-ZTVPObjectProperty -Object $state -Name "tenant_analysis_started_utc" -Value $analysisStartedUtc

$local = $null
$localEvidencePresent = Test-Path $localEvidencePath
$localEvidenceAccepted = $false
$localEvidenceStale = $false
$localEvidenceInvalidReason = $null
$localEvidenceTimestampUtc = $null
$localEvidenceDriftSeconds = $null
$stateSaysLocalImported = $false
if ($state.PSObject.Properties["local_evidence_imported"]) { $stateSaysLocalImported = [bool]$state.local_evidence_imported }
$vmScriptGenerated = $false
if ($state.PSObject.Properties["vm_script_generated"]) { $vmScriptGenerated = [bool]$state.vm_script_generated }

if ($localEvidencePresent) {
    $local = Get-Content $localEvidencePath -Raw | ConvertFrom-Json
    $localEvidenceTimestampUtc = ConvertTo-ZTVPUtcDate -Value $local.timestamp_utc
}

if (-not $localEvidencePresent -or -not $stateSaysLocalImported) {
    $localEvidenceInvalidReason = "No VM test evidence was imported for the current run."
    $local = $null
    $localEvidencePresent = $false
}
elseif ($local.scenario_id -ne "DEV-DV-008") {
    $localEvidenceInvalidReason = "Imported VM evidence is not for DEV-DV-008 and was not used."
    $local = $null
    $localEvidencePresent = $false
}
elseif ($local.PSObject.Properties["run_id"] -and -not [string]::IsNullOrWhiteSpace([string]$local.run_id) -and [string]$local.run_id -ne $runId) {
    $localEvidenceInvalidReason = "Imported VM evidence belongs to a different DEV-DV-008 run and was not used."
    $local = $null
    $localEvidencePresent = $false
}
elseif ($null -eq $localEvidenceTimestampUtc) {
    $localEvidenceInvalidReason = "Imported VM evidence has no valid timestamp_utc and was not used."
    $local = $null
    $localEvidencePresent = $false
}
elseif ($localEvidenceTimestampUtc -and $windowStartDateUtc) {
    $localEvidenceDriftSeconds = [int][Math]::Round(($localEvidenceTimestampUtc - $windowStartDateUtc).TotalSeconds)
    $hasMatchingRunId = ($local.PSObject.Properties["run_id"] -and -not [string]::IsNullOrWhiteSpace([string]$local.run_id) -and [string]$local.run_id -eq $runId)
    if ((-not $hasMatchingRunId) -and $localEvidenceTimestampUtc -lt $windowStartDateUtc.AddMinutes(-5)) {
        $localEvidenceStale = $true
        $localEvidenceInvalidReason = "Imported VM evidence is older than the current validation window tolerance and was not used."
        $local = $null
        $localEvidencePresent = $false
    }
    else {
        $localEvidenceAccepted = $true
    }
}
elseif ($localEvidenceTimestampUtc -lt $windowStartDateUtc) {
    $localEvidenceStale = $true
    $localEvidenceInvalidReason = "Imported VM evidence is older than the current validation window and was not used."
    $local = $null
    $localEvidencePresent = $false
}

if ([string]::IsNullOrWhiteSpace($testDeviceName) -and $local -and $local.computer_name) {
    $testDeviceName = [string]$local.computer_name
}

$localSummaryObject = if ($local -and $local.local_summary) { $local.local_summary } else { $null }
$tamperEnabled = $false
$settingsProtected = $false
$settingsWeakened = $false
$tamperBlockedOrIgnored = $false
if ($localSummaryObject) {
    $tamperEnabled = ([bool]$localSummaryObject.tamper_protection_enabled_before) -or ([bool]$localSummaryObject.tamper_protection_enabled_after)
    $settingsProtected = [bool]$localSummaryObject.defender_settings_remained_protected
    $settingsWeakened = [bool]$localSummaryObject.settings_weakened
    $tamperBlockedOrIgnored = [bool]$localSummaryObject.tamper_attempt_blocked_or_ignored
}
$localProtected = $localEvidenceAccepted -and $tamperEnabled -and $settingsProtected -and $tamperBlockedOrIgnored -and (-not $settingsWeakened)
$localFailed = $localEvidenceAccepted -and ((-not $tamperEnabled) -or $settingsWeakened)

$mdeStatus = "Not found"
$mdeError = $null
$mdeTimelineEvents = @()
$mdeTamperTimelineEvents = @()
$parsedTamperTimelineEvidence = @()
$mdeRegistryEvents = @()
$mdeAlerts = @()
$mdeAlertEvidence = @()
$mdeJoinedAlertEvidence = @()
$mdePollAttempts = 0
$timelineEventsFound = $false
$tamperActionType = ""
$blockedModificationFound = $false
$scriptCommandEvidenceFound = $false
$tenantQueryStartedUtc = $null
$tenantQueryCompletedUtc = $null
$tenantEvidenceFoundAtUtc = $null
$tenantWaitSeconds = 0
$effectiveSearchStartDateUtc = $windowStartDateUtc
if ($localEvidenceTimestampUtc -and $localEvidenceTimestampUtc -lt $effectiveSearchStartDateUtc) {
    $effectiveSearchStartDateUtc = $localEvidenceTimestampUtc
}
$effectiveSearchStartDateUtc = $effectiveSearchStartDateUtc.AddMinutes(-5)
$effectiveSearchStartUtc = $effectiveSearchStartDateUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")

if ($cloudEvidenceMode -eq "Local Evidence Only") {
    $mdeStatus = "Skipped by operator"
}
elseif ($localFailed) {
    $mdeStatus = "Skipped after local FAIL"
    $mdeError = "Defender settings were weakened during the tamper attempt. Tenant polling was skipped because the local endpoint result is already FAIL."
}
elseif ([string]::IsNullOrWhiteSpace($testDeviceName)) {
    $mdeStatus = "Unavailable"
    $mdeError = "Test device name is missing. ZTVP could not use state.test_device_name or local evidence computer_name."
}
else {
    $pollStarted = Get-Date
    $tenantQueryStartedUtc = $pollStarted.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $deadline = if ($WaitMinutes -le 0) { $pollStarted } else { $pollStarted.AddMinutes($WaitMinutes) }
    try {
        $token = Get-ZTVPMdeToken
    }
    catch {
        $mdeError = $_.Exception.Message
        if ($mdeError -match "401|Unauthorized|invalid or expired") { $mdeStatus = "Unauthorized" }
        elseif ($mdeError -match "Defender XDR API connection required") { $mdeStatus = "Defender XDR API connection required" }
        else { $mdeStatus = "Unavailable" }
    }

    while ($token) {
        $mdePollAttempts++
        try {
            $device = New-ZTVPKqlString -Value $testDeviceName
            $shortDeviceName = $testDeviceName
            if ($shortDeviceName -match "\.") { $shortDeviceName = ($shortDeviceName -split "\.")[0] }
            $shortDevice = New-ZTVPKqlString -Value $shortDeviceName
            $window = $effectiveSearchStartUtc

            $queryDeviceEvents = @"
DeviceEvents
| where Timestamp >= datetime($window)
| where DeviceName contains "$device" or DeviceName contains "$shortDevice"
| where ActionType has_any ("TamperingAttempt", "TamperProtectionConfigChangeAttempt", "PowerShellCommand")
   or AdditionalFields has_any ("Tamper", "TamperProtection", "Blocked", "RegistryModification", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableBlockAtFirstSeen")
   or InitiatingProcessCommandLine has_any ("Invoke-ZTVPTamperAttempt", "Set-MpPreference", "reg add", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableBlockAtFirstSeen")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| order by Timestamp desc
"@

            $queryAlertEvidence = @"
AlertEvidence
| where Timestamp >= datetime($window)
| where DeviceName contains "$device" or DeviceName contains "$shortDevice"
| project Timestamp, AlertId, DeviceName, EntityType, EvidenceRole, DetectionSource, AccountName, AccountDomain
"@

            $queryAlerts = @"
AlertInfo
| where Timestamp >= datetime($window)
| where not(Title has_any ("EICAR", "EICAR_Test_File", "Virus:DOS/EICAR", "malware was prevented"))
| where not(Category =~ "Malware" and Title has_any ("EICAR", "malware"))
| where Title has_any ("Microsoft Defender Antivirus tampering", "tampering", "Defender Antivirus tampering", "Antivirus tampering", "Defender tampering")
   or Category has_any ("DefenseEvasion", "Defense Evasion")
   or DetectionSource has "EDR"
| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, DetectionSource
"@

            $queryJoinedAlerts = @"
AlertEvidence
| where Timestamp >= datetime($window)
| where DeviceName contains "$device" or DeviceName contains "$shortDevice"
| join kind=leftouter (
    AlertInfo
    | where Timestamp >= datetime($window)
    | where not(Title has_any ("EICAR", "EICAR_Test_File", "Virus:DOS/EICAR", "malware was prevented"))
    | where not(Category =~ "Malware" and Title has_any ("EICAR", "malware"))
    | project AlertId, AlertTimestamp=Timestamp, Title, Severity, Category, ServiceSource, AlertDetectionSource=DetectionSource
) on AlertId
| where Title has_any ("Microsoft Defender Antivirus tampering", "tampering", "Defender tampering", "Antivirus tampering")
   or Category has_any ("DefenseEvasion", "Defense Evasion")
   or AlertDetectionSource has "EDR"
| project Timestamp, AlertTimestamp, AlertId, Title, Severity, Category, EvidenceDetectionSource=DetectionSource, AlertDetectionSource, ServiceSource, DeviceName, EntityType, EvidenceRole, AccountName, AccountDomain
"@

            $queryRegistry = @"
DeviceRegistryEvents
| where Timestamp >= datetime($window)
| where DeviceName contains "$device" or DeviceName contains "$shortDevice"
| where RegistryKey has_any ("Windows Defender", "Defender", "Real-Time Protection")
   or RegistryValueName has_any ("DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableAntiSpyware")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
"@

            $mdeTimelineEvents = @(Invoke-ZTVPMdeAdvancedHunting -Query $queryDeviceEvents -Token $token)
            $timelineEventsFound = ($mdeTimelineEvents.Count -gt 0)
            $mdeTamperTimelineEvents = @($mdeTimelineEvents | Where-Object { Test-ZTVPTamperTimelineEvent -Row $_ })
            $parsedTamperTimelineEvidence = @(Get-ZTVPParsedTimelineEvidence -Rows $mdeTamperTimelineEvents)
            $mdeAlertEvidence = @(Invoke-ZTVPMdeAdvancedHunting -Query $queryAlertEvidence -Token $token)
            $mdeRegistryEvents = @(Invoke-ZTVPMdeAdvancedHunting -Query $queryRegistry -Token $token)
            $mdeAlerts = @(Invoke-ZTVPMdeAdvancedHunting -Query $queryAlerts -Token $token | Where-Object { Test-ZTVPDevDv008AlertRow -Row $_ })
            $mdeJoinedAlertEvidence = @(Invoke-ZTVPMdeAdvancedHunting -Query $queryJoinedAlerts -Token $token | Where-Object { Test-ZTVPDevDv008AlertRow -Row $_ })

            $linkedAlertIds = @($mdeAlertEvidence | ForEach-Object { [string]$_.AlertId } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
            $linkedAlerts = @($mdeAlerts | Where-Object { $linkedAlertIds -contains [string]$_.AlertId -and (Test-ZTVPDevDv008AlertRow -Row $_) })
            if ($linkedAlertIds.Count -gt 0) {
                $mdeAlerts = @($linkedAlerts)
            }
            else {
                $mdeAlerts = @()
            }
            $strongAlertEvidenceThisPoll = (@($mdeAlertEvidence | Where-Object { [string]$_.DetectionSource -match "EDR" }).Count -gt 0)
            $alertEvidenceFoundThisPoll = (($mdeJoinedAlertEvidence.Count -gt 0) -or $strongAlertEvidenceThisPoll)
            $mdeCount = $mdeTamperTimelineEvents.Count + $mdeJoinedAlertEvidence.Count + $mdeRegistryEvents.Count + $mdeAlerts.Count

            if ($mdeTamperTimelineEvents.Count -gt 0 -or $alertEvidenceFoundThisPoll) {
                $mdeStatus = "Found"
                $tamperActionType = Get-ZTVPFirstValue -Rows $mdeTamperTimelineEvents -Names @("ActionType")
                $scriptCommandEvidenceFound = (@($mdeTamperTimelineEvents | Where-Object { [string]$_.InitiatingProcessCommandLine -match "Invoke-ZTVPTamperAttempt|Set-MpPreference|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableBlockAtFirstSeen" }).Count -gt 0)
                $blockedModificationFound = (@($parsedTamperTimelineEvidence | Where-Object { $_.Blocked }).Count -gt 0)
                $tenantEvidenceFoundAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                break
            }

            $mdeAlerts = @()
            $mdeStatus = "Not found"
            if ($WaitMinutes -le 0) { break }
            if ((Get-Date).AddSeconds($PollSeconds) -le $deadline) {
                Start-Sleep -Seconds ([Math]::Max(5, $PollSeconds))
            }
            else { break }
        }
        catch {
            $mdeError = $_.Exception.Message
            if ($mdeError -match "401|Unauthorized") {
                $mdeStatus = "Unauthorized"
                $mdeError = "Defender XDR token is invalid or expired. Reconnect Defender XDR API. Raw error: $mdeError"
                break
            }
            $mdeStatus = "Unavailable"
            if ($WaitMinutes -le 0) { break }
            if ((Get-Date).AddSeconds($PollSeconds) -le $deadline) {
                Start-Sleep -Seconds ([Math]::Max(5, $PollSeconds))
            }
            else { break }
        }
    }
    $pollCompleted = Get-Date
    $tenantQueryCompletedUtc = $pollCompleted.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $tenantWaitSeconds = [int][Math]::Round(($pollCompleted - $pollStarted).TotalSeconds)
}

$tenantTamperTimelineEvidenceFound = (@($mdeTamperTimelineEvents | Where-Object { [string]$_.ActionType -in @("TamperingAttempt", "TamperProtectionConfigChangeAttempt") }).Count -gt 0)
$tenantTimelineEvidenceFound = ($mdeTamperTimelineEvents.Count -gt 0)
$mdeEvidenceCount = $mdeTamperTimelineEvents.Count + $mdeRegistryEvents.Count + $mdeAlertEvidence.Count + $mdeJoinedAlertEvidence.Count + $mdeAlerts.Count
$alertDeviceEvidenceFound = ($mdeAlertEvidence.Count -gt 0)
$mdeAlertFound = ($alertDeviceEvidenceFound -or ($mdeAlerts.Count -gt 0))
$alertRows = @($mdeJoinedAlertEvidence + $mdeAlerts)
$alertTitle = Get-ZTVPFirstValue -Rows $alertRows -Names @("Title")
$alertCategory = Get-ZTVPFirstValue -Rows $alertRows -Names @("Category")
$alertServiceSource = Get-ZTVPFirstValue -Rows $alertRows -Names @("ServiceSource")
$alertDetectionSource = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence + $mdeAlerts) -Names @("AlertDetectionSource", "EvidenceDetectionSource", "DetectionSource")
$invalidDevDv008Alert = (
    "$alertTitle $alertCategory" -match "EICAR|EICAR_Test_File|Virus:DOS/EICAR|malware was prevented" -or
    ($alertCategory -match "^Malware$" -and $alertTitle -match "EICAR|malware")
)
$tenantAlertEvidenceFound = (-not $invalidDevDv008Alert) -and $alertDeviceEvidenceFound -and (
    $alertTitle -match "tamper|Microsoft Defender Antivirus tampering|Defender Antivirus tampering|Antivirus tampering|Defender tampering" -or
    $alertCategory -match "DefenseEvasion|Defense Evasion" -or
    $alertDetectionSource -match "EDR" -or
    ("$alertTitle $alertCategory $alertDetectionSource $alertServiceSource" -match "T1562\.001|Disable or Modify Tools|Set-MpPreference|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableBlockAtFirstSeen")
)
$mdeEvidenceFound = ($mdeStatus -eq "Found") -and ($tenantTimelineEvidenceFound -or $tenantAlertEvidenceFound)
$blockedResult = Get-ZTVPFirstValue -Rows $parsedTamperTimelineEvidence -Names @("Status")
$tamperingAction = Get-ZTVPFirstValue -Rows $parsedTamperTimelineEvidence -Names @("TamperingAction")
$blockedSetting = Get-ZTVPFirstValue -Rows $parsedTamperTimelineEvidence -Names @("BlockedSetting")
$blockedModificationSummary = Get-ZTVPFirstValue -Rows $parsedTamperTimelineEvidence -Names @("BlockedModificationSummary")
$blockedModificationFound = (@($parsedTamperTimelineEvidence | Where-Object { $_.Blocked }).Count -gt 0)
$scriptCommandEvidenceFound = (@($mdeTamperTimelineEvents | Where-Object { [string]$_.ActionType -eq "PowerShellCommand" -and [string]$_.InitiatingProcessCommandLine -match "Invoke-ZTVPTamperAttempt|Set-MpPreference" }).Count -gt 0)
if ([string]::IsNullOrWhiteSpace($blockedResult) -and $blockedModificationFound) { $blockedResult = "Blocked" }
if ([string]::IsNullOrWhiteSpace($blockedModificationSummary) -and $blockedModificationFound) { $blockedModificationSummary = "Protected Defender setting blocked" }
if ([string]::IsNullOrWhiteSpace($blockedSetting) -and $blockedModificationFound) { $blockedSetting = "Protected Defender setting" }
$scriptCommandEvidenceStatus = if ($scriptCommandEvidenceFound) { "Found" } elseif ($tenantTamperTimelineEvidenceFound) { "Not returned by API" } else { "Not found" }

$status = "NOT_RUN_CONTROLLED_ACTION_NOT_EXECUTED"
$risk = "NOT ASSESSED"
$conclusion = "NOT RUN - Controlled tamper attempt was not executed for this validation window."
$outcomeTitle = "Validation not completed"
$outcomeText = "The validation window was armed, but no fresh endpoint evidence was imported and no tenant-side evidence was found for this run."
if (-not $vmScriptGenerated -and -not $stateSaysLocalImported) {
    $outcomeText = "The controlled tamper attempt was not executed for this validation window."
}
$recommendations = @(
    "Generate the controlled tamper attempt.",
    "Run it inside the controlled VM as Administrator.",
    "Import the VM JSON evidence.",
    "Rerun analysis."
)

if ($localProtected -and (($tenantTamperTimelineEvidenceFound -and $blockedModificationFound) -or $tenantAlertEvidenceFound)) {
    $status = "PASS_TAMPER_PROTECTION_VALIDATED"
    $risk = "LOW"
    if ($tenantAlertEvidenceFound) {
        $conclusion = "PASS - Defender settings stayed protected, and the tenant captured the tampering activity as a Defender XDR alert."
    }
    else {
        $conclusion = "PASS - Defender settings stayed protected, and the tenant recorded the blocked tamper attempt in the device timeline."
    }
    $outcomeTitle = "Validation successful"
    $outcomeText = "Tamper Protection blocked or ignored the attempt to weaken Defender settings, and Microsoft Defender XDR recorded tenant evidence for the tampering activity."
    $recommendations = @(
        "Keep Tamper Protection enabled.",
        "Keep MDE onboarding healthy.",
        "Keep monitoring Defender XDR device timeline and endpoint telemetry.",
        "Use this result as evidence that both endpoint enforcement and tenant visibility worked."
    )
}
elseif ($localFailed) {
    $status = "FAIL_TAMPER_PROTECTION_NOT_EFFECTIVE"
    $risk = "HIGH"
    $conclusion = "FAIL - Tamper Protection did not protect the endpoint as expected."
    $outcomeTitle = "Validation failed"
    $outcomeText = "The tamper attempt changed or weakened Defender settings, or Tamper Protection was not enabled."
    $recommendations = @(
        "Enable Tamper Protection in Microsoft Defender portal: Settings -> Endpoints -> General -> Advanced features -> Tamper protection.",
        "Or enable Tamper Protection through Intune Endpoint Security policy if Intune manages the device.",
        "Confirm Defender Antivirus is active and not passive.",
        "Confirm Real-time protection is enabled.",
        "Confirm cloud-delivered protection is enabled.",
        "Confirm MDE onboarding and Sense service.",
        "Review Defender policy conflicts and exclusions.",
        "Rerun validation after correction."
    )
}
elseif ($localProtected) {
    $status = "PARTIAL_TAMPER_PROTECTION_LOCAL_ONLY"
    $risk = "MEDIUM"
    $conclusion = "PARTIAL - local protection worked, but tenant-side visibility was not proven within the wait window."
    $outcomeTitle = "Validation partially successful"
    $outcomeText = "Tamper Protection protected the endpoint locally, but ZTVP did not find tamper-specific tenant evidence within the selected wait window."
    $recommendations = @(
        "Check Defender portal -> Assets -> Devices -> $testDeviceName -> Timeline.",
        "Search for Tamper.",
        "Confirm Defender XDR API connection is ready.",
        "Confirm Sense service is running.",
        "Rerun tenant analysis with a longer wait window if needed.",
        "Confirm Advanced Hunting DeviceEvents query includes TamperingAttempt and TamperProtectionConfigChangeAttempt."
    )
}
elseif ($tenantTimelineEvidenceFound -or $tenantAlertEvidenceFound) {
    $status = "PARTIAL_TAMPER_TENANT_ONLY"
    $risk = "MEDIUM"
    $conclusion = "PARTIAL - Tenant-side evidence was found, but endpoint evidence is incomplete."
    $outcomeTitle = "Validation partially successful"
    $outcomeText = "Microsoft Defender XDR recorded tamper-specific tenant evidence, but endpoint local evidence was missing or incomplete."
    $recommendations = @(
        "Import the VM JSON evidence for this run.",
        "Confirm the VM script was run inside the controlled endpoint as Administrator.",
        "Check device timeline and alerts manually."
    )
}

$localEvidence = [PSCustomObject]@{
    imported_local_evidence_present = $localEvidencePresent
    local_evidence_accepted_for_current_run = $localEvidenceAccepted
    local_evidence_stale = $localEvidenceStale
    local_evidence_invalid_reason = $localEvidenceInvalidReason
    local_evidence_timestamp_utc = if ($localEvidenceTimestampUtc) { $localEvidenceTimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
    local_evidence_time_difference_seconds = $localEvidenceDriftSeconds
    local_evidence_status = if ($localEvidenceStale) { "Stale" } elseif ($localEvidenceAccepted) { "Found" } else { "Missing" }
    test_device_name_from_vm = if ($local) { $local.computer_name } else { $null }
    tamper_protection_enabled = $tamperEnabled
    defender_settings_remained_protected = $settingsProtected
    tamper_attempt_blocked_or_ignored = $tamperBlockedOrIgnored
    settings_weakened = $settingsWeakened
    before_status = if ($local) { $local.before_status } else { $null }
    before_preference = if ($local) { $local.before_preference } else { $null }
    after_status = if ($local) { $local.after_status } else { $null }
    after_preference = if ($local) { $local.after_preference } else { $null }
    tamper_attempts = if ($local) { @($local.tamper_attempts) } else { @() }
    restore_attempts = if ($local) { @($local.restore_attempts) } else { @() }
    raw = $local
}

$tenantApiEvidence = [PSCustomObject]@{
    cloud_evidence_mode = $cloudEvidenceMode
    tenant_id = $tenantId
    tenant_display_name = $tenantDisplayName
    client_id = $clientId
    token_cache_path = "powershell\Auth\ztvp-defenderxdr-token-cache.json"
    test_device_name_requested = $testDeviceName
    validation_window_start_utc = $windowStartUtc
    effective_search_start_utc = $effectiveSearchStartUtc
    mde_cloud_query_status = $mdeStatus
    mde_cloud_evidence_found = $mdeEvidenceFound
    mde_cloud_evidence_count = $mdeEvidenceCount
    mde_cloud_error = $mdeError
    mde_cloud_poll_attempts = $mdePollAttempts
    mde_cloud_wait_minutes = $WaitMinutes
    mde_cloud_poll_seconds = $PollSeconds
    tenant_query_started_utc = $tenantQueryStartedUtc
    tenant_query_completed_utc = $tenantQueryCompletedUtc
    tenant_evidence_found_at_utc = $tenantEvidenceFoundAtUtc
    tenant_time_spent_waiting_seconds = $tenantWaitSeconds
    tenant_timeline_evidence = [PSCustomObject]@{
        timeline_events_found = $timelineEventsFound
        tenant_timeline_evidence_found = $tenantTimelineEvidenceFound
        tamper_specific_evidence_found = $tenantTamperTimelineEvidenceFound
        tenant_tamper_evidence_found = $tenantTamperTimelineEvidenceFound
        tenant_alert_evidence_found = $tenantAlertEvidenceFound
        tenant_block_evidence_found = $blockedModificationFound
        powershell_attempt_evidence_found = $scriptCommandEvidenceFound
        tamper_timeline_event_count = $mdeTamperTimelineEvents.Count
        total_timeline_event_count = $mdeTimelineEvents.Count
        tamper_action_type = $tamperActionType
        blocked_modification_found = $blockedModificationFound
        blocked_modification_summary = $blockedModificationSummary
        blocked_result = $blockedResult
        tampering_action = $tamperingAction
        blocked_setting = $blockedSetting
        script_command_evidence_found = $scriptCommandEvidenceFound
        script_command_evidence_status = $scriptCommandEvidenceStatus
        wait_window_minutes = $WaitMinutes
        poll_interval_seconds = $PollSeconds
        effective_search_start_utc = $effectiveSearchStartUtc
        poll_attempts = $mdePollAttempts
        evidence_found_at_utc = $tenantEvidenceFoundAtUtc
        time_spent_waiting_seconds = $tenantWaitSeconds
        verdict_impact = if (($tenantTamperTimelineEvidenceFound -and $blockedModificationFound) -or $tenantAlertEvidenceFound) { "Can support PASS when local protection worked" } elseif ($timelineEventsFound) { "Partial, not Pass" } elseif ($mdeEvidenceFound) { "Tenant evidence found outside DeviceEvents timeline; Partial, not Pass" } else { "No tenant timeline evidence found" }
    }
    tenant_defender_alert = [PSCustomObject]@{
        alert_found = $mdeAlertFound
        alert_evidence_found = $tenantAlertEvidenceFound
        alert_title = $alertTitle
        alert_id = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence + $mdeAlerts) -Names @("AlertId")
        alert_timestamp = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence + $mdeAlerts) -Names @("AlertTimestamp", "Timestamp")
        alert_severity = Get-ZTVPFirstValue -Rows $alertRows -Names @("Severity")
        alert_category = $alertCategory
        service_source = $alertServiceSource
        detection_source = $alertDetectionSource
        product_name = $alertServiceSource
        impacted_asset = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence) -Names @("DeviceName")
        user = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence) -Names @("AccountName", "AccountDomain")
        linked_to_test_device = $alertDeviceEvidenceFound
        entity_type = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence) -Names @("EntityType")
        evidence_role = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence) -Names @("EvidenceRole")
        evidence_source = "AlertInfo/AlertEvidence"
    }
    mde_cloud_device_events = @($mdeTimelineEvents)
    mde_cloud_tamper_timeline_events = @($mdeTamperTimelineEvents)
    mde_cloud_parsed_tamper_timeline_evidence = @($parsedTamperTimelineEvidence)
    mde_cloud_registry_events = @($mdeRegistryEvents)
    mde_cloud_alerts = @($mdeAlerts)
    mde_cloud_alert_evidence = @($mdeAlertEvidence)
    mde_cloud_joined_alert_evidence = @($mdeJoinedAlertEvidence)
}

$analysisCompletedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$result = [PSCustomObject]@{
    scenario_id = "DEV-DV-008"
    display_id = "DEV-DV-008"
    run_id = $runId
    scenario_name = "Hybrid Tamper Protection Validation"
    pillar = "Devices"
    scope = "Cloud"
    generated_at = (Get-Date).ToString("s")
    tenant_id = $tenantId
    tenant_display_name = $tenantDisplayName
    client_id = $clientId
    status = $status
    risk = $risk
    test_device = if ($local -and $local.computer_name) { $local.computer_name } else { $testDeviceName }
    validation_method = "Hybrid endpoint + tenant validation"
    validation_window_start_utc = $windowStartUtc
    tenant_analysis_started_utc = $analysisStartedUtc
    tenant_analysis_completed_utc = $analysisCompletedUtc
    vm_script_generated = $vmScriptGenerated
    local_evidence_imported = $stateSaysLocalImported
    local_evidence_accepted_for_current_run = $localEvidenceAccepted
    clean_conclusion = $conclusion
    outcome_title = $outcomeTitle
    outcome_text = $outcomeText
    controlled_action = "Attempt controlled Set-MpPreference changes that try to weaken Defender security settings on a test endpoint."
    expected_result = "Tamper Protection blocks, ignores, or reverses the attempts, protected Defender settings remain enabled, and Defender XDR captures tenant-side evidence."
    evidence = [PSCustomObject]@{
        local = $localEvidence
        tenant = [PSCustomObject]@{ api = $tenantApiEvidence }
    }
    metrics = [PSCustomObject]@{
        tamper_protection_enabled = $tamperEnabled
        defender_settings_remained_protected = $settingsProtected
        tamper_attempt_blocked_or_ignored = $tamperBlockedOrIgnored
        settings_weakened = $settingsWeakened
        mde_cloud_query_status = $mdeStatus
        mde_cloud_evidence_found = $mdeEvidenceFound
        mde_cloud_evidence_count = $mdeEvidenceCount
        mde_timeline_events_found = $timelineEventsFound
        mde_tamper_timeline_event_count = $mdeTamperTimelineEvents.Count
        mde_cloud_alert_found = $mdeAlertFound
    }
    recommendations = @($recommendations)
    limitations = @(
        "This scenario uses manual VM script mode because the test endpoint is separate from the ZTVP host.",
        "Tenant-side Defender evidence requires Defender XDR Advanced Hunting API access.",
        "Cloud evidence can be delayed and should be rechecked if the result is PARTIAL."
    )
}

Write-ZTVPJson -Path $reportPath -Object $result
Set-ZTVPObjectProperty -Object $state -Name "tenant_analysis_completed_utc" -Value $analysisCompletedUtc
Set-ZTVPObjectProperty -Object $state -Name "analysis_completed" -Value $true
Set-ZTVPObjectProperty -Object $state -Name "current_run_report_path" -Value $reportPath
Set-ZTVPObjectProperty -Object $state -Name "current_run_status" -Value $status
Write-ZTVPJson -Path $statePath -Object $state

$jsonHtml = [System.Net.WebUtility]::HtmlEncode(($result | ConvertTo-Json -Depth 100))
$html = @"
<!doctype html>
<html>
<head><meta charset="utf-8"><title>DEV-DV-008 - Hybrid Tamper Protection Validation</title></head>
<body style="font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#0f172a;background:#f8fafc;">
<h1>DEV-DV-008 - Hybrid Tamper Protection Validation</h1>
<p><strong>Status:</strong> $status</p>
<p><strong>Risk:</strong> $risk</p>
<p><strong>Conclusion:</strong> $conclusion</p>
<pre style="white-space:pre-wrap;background:#0f172a;color:#e2e8f0;padding:16px;border-radius:12px;">$jsonHtml</pre>
</body>
</html>
"@
Set-Content -Path $htmlPath -Value $html -Encoding UTF8

Write-Host ""
Write-Host "DEV-DV-008 analysis completed."
Write-Host "Status: $status"
Write-Host "Risk: $risk"
Write-Host "Local evidence accepted: $localEvidenceAccepted"
Write-Host "MDE cloud query status: $mdeStatus"
Write-Host "MDE cloud evidence count: $mdeEvidenceCount"
Write-Host "Report: $reportPath"
Write-Host "HTML: $htmlPath"
Write-Host ""
