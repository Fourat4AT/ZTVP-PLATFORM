param(
    [int]$WaitMinutes = 10,
    [int]$PollSeconds = 30
)

$ErrorActionPreference = "Stop"

function Write-ZTVPJson {
    param([string]$Path, [object]$Object)
    $Object | ConvertTo-Json -Depth 100 | Set-Content -Path $Path -Encoding UTF8
}

function ConvertTo-ZTVPHtmlSafe {
    param([object]$Value)
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Test-ZTVPEicarText {
    param([object]$Value)
    if ($null -eq $Value) { return $false }
    $text = $Value | ConvertTo-Json -Depth 100 -Compress
    return ($text -match "EICAR|ANTIVIRUS-TEST|Virus:DOS/EICAR|TestFile")
}

function Test-ZTVPDefenderLikeError {
    param([object[]]$Values)
    $joined = (@($Values) | Where-Object { $_ } | ForEach-Object { [string]$_ }) -join " "
    return ($joined -match "virus|threat|malware|potentially unwanted|operation did not complete|blocked|quarantine|Defender")
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
    param(
        [object]$Object,
        [string]$Name,
        [object]$Value
    )

    if ($Object.PSObject.Properties[$Name]) {
        $Object.$Name = $Value
    }
    else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
}

function Get-ZTVPHttpErrorDetail {
    param([object]$ErrorRecord)

    $reason = $ErrorRecord.Exception.Message
    try {
        $response = $ErrorRecord.Exception.Response
        if ($response) {
            $statusCode = [int]$response.StatusCode
            $statusDescription = [string]$response.StatusDescription
            if ($statusCode) {
                $reason = "$reason HTTP $statusCode $statusDescription".Trim()
            }

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
        throw "Defender XDR API connection required. Connect Defender XDR API from DEV-DV-006 before running tenant evidence analysis."
    }

    $cache = Get-Content $tokenCachePath -Raw | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace([string]$cache.access_token)) {
        throw "Defender XDR API connection required. Connect Defender XDR API from DEV-DV-006 before running tenant evidence analysis."
    }

    if ($cache.resource -and $cache.resource -ne "https://api.security.microsoft.com") {
        throw "Defender XDR token cache was created for the wrong resource: $($cache.resource). Expected https://api.security.microsoft.com."
    }

    if ($cache.scope -ne "https://api.security.microsoft.com/AdvancedHunting.Read") {
        throw "Defender XDR token cache was created for the wrong scope: $($cache.scope). Expected https://api.security.microsoft.com/AdvancedHunting.Read."
    }

    if ($cache.expires_on) {
        $expiresUtc = [datetime]$cache.expires_on
        if ($expiresUtc.ToUniversalTime() -le (Get-Date).ToUniversalTime().AddMinutes(5)) {
            throw "Defender XDR token is invalid or expired. Reconnect Defender XDR API."
        }
    }

    $accessToken = [string]$cache.access_token
    Test-ZTVPMdeTokenCache -Token $accessToken

    return $accessToken
}

function Invoke-ZTVPMdeAdvancedHunting {
    param(
        [string]$Query,
        [string]$Token
    )

    $body = @{ Query = $Query } | ConvertTo-Json -Depth 10
    $headers = @{
        Authorization = "Bearer $Token"
        "Content-Type" = "application/json"
    }

    try {
        $response = Invoke-RestMethod `
            -Method POST `
            -Uri "https://api.security.microsoft.com/api/advancedhunting/run" `
            -Headers $headers `
            -Body $body `
            -ErrorAction Stop
    }
    catch {
        $reason = Get-ZTVPHttpErrorDetail -ErrorRecord $_
        throw "Defender XDR Advanced Hunting query failed. Endpoint: https://api.security.microsoft.com/api/advancedhunting/run Query: $Query Reason: $reason"
    }

    return @(ConvertTo-ZTVPArray -Value $response.Results)
}

function Test-ZTVPMdeTokenCache {
    param([string]$Token)

    try {
        Invoke-ZTVPMdeAdvancedHunting -Query "DeviceInfo | take 1" -Token $Token | Out-Null
    }
    catch {
        throw "Defender XDR token cache validation failed. Query: DeviceInfo | take 1. Reason: $($_.Exception.Message)"
    }
}

function New-ZTVPKqlString {
    param([string]$Value)
    return ($Value -replace '"', '\"')
}

function New-ZTVPKqlDynamicStringArray {
    param([string[]]$Values)

    $items = @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique | ForEach-Object {
        '"' + (([string]$_) -replace '\\', '\\' -replace '"', '\"') + '"'
    })

    return "dynamic([$($items -join ',')])"
}

function Get-ZTVPFirstValue {
    param(
        [object[]]$Rows,
        [string[]]$Names
    )

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

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "DEV-DV-006"
$htmlDir = Join-Path $reportRoot "Html"

$statePath = Join-Path $scenarioDir "devdv006-state.json"
$localEvidencePath = Join-Path $scenarioDir "devdv006-local-evidence.json"
$manualTenantEvidencePath = Join-Path $scenarioDir "devdv006-tenant-manual-evidence.json"
$reportPath = Join-Path $reportRoot "DEV-DV-006-result.json"
$htmlPath = Join-Path $htmlDir "DEV-DV-006-result.html"

if (-not (Test-Path $statePath)) {
    throw "No DEV-DV-006 state file found. Start a fresh validation window first."
}

New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null

$state = Get-Content $statePath -Raw | ConvertFrom-Json
$windowStartUtc = [string]$state.validation_window_start_utc
$testDeviceName = [string]$state.test_device_name
$cloudEvidenceMode = [string]$state.cloud_evidence_mode
$tenantId = [string]$state.tenant_id
$clientId = [string]$state.client_id
$tenantDisplayName = [string]$state.tenant_display_name
$runId = [string]$state.run_id
$analysisStartedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Set-ZTVPObjectProperty -Object $state -Name "tenant_analysis_started_utc" -Value $analysisStartedUtc

if ([string]::IsNullOrWhiteSpace($cloudEvidenceMode)) {
    $cloudEvidenceMode = "Tenant + Local Evidence"
}

if ([string]::IsNullOrWhiteSpace($windowStartUtc)) {
    throw "State is missing validation_window_start_utc. Start a fresh validation window again."
}

$windowStartDateUtc = ConvertTo-ZTVPUtcDate -Value $windowStartUtc
if ($null -eq $windowStartDateUtc) {
    throw "State validation_window_start_utc is not a valid UTC timestamp. Start a fresh validation window again."
}

$localEvidencePresent = Test-Path $localEvidencePath
$local = $null
$localEvidenceAccepted = $false
$localEvidenceStale = $false
$localEvidenceInvalidReason = $null
$localEvidenceTimestampUtc = $null

if ($localEvidencePresent) {
    $local = Get-Content $localEvidencePath -Raw | ConvertFrom-Json
}

if ($local) {
    $localEvidenceTimestampUtc = ConvertTo-ZTVPUtcDate -Value $local.timestamp_utc
}

$stateSaysLocalImported = $false
if ($state.PSObject.Properties["local_evidence_imported"]) {
    $stateSaysLocalImported = [bool]$state.local_evidence_imported
}

if (-not $localEvidencePresent -or -not $stateSaysLocalImported) {
    $localEvidenceInvalidReason = "No VM test evidence was imported for the current run."
    $local = $null
    $localEvidencePresent = $false
}
elseif ($local.scenario_id -ne "DEV-DV-006") {
    $localEvidenceInvalidReason = "Imported VM evidence is not for DEV-DV-006 and was not used."
    $local = $null
    $localEvidencePresent = $false
}
elseif ($null -eq $localEvidenceTimestampUtc) {
    $localEvidenceInvalidReason = "Imported VM evidence has no valid timestamp_utc and was not used."
    $local = $null
    $localEvidencePresent = $false
}
elseif ($localEvidenceTimestampUtc -lt $windowStartDateUtc) {
    $localEvidenceStale = $true
    $localEvidenceInvalidReason = "Imported VM evidence is older than the current validation window and was not used."
    $local = $null
    $localEvidencePresent = $false
}
else {
    $localEvidenceAccepted = $true
}

if ([string]::IsNullOrWhiteSpace($testDeviceName) -and $local -and $local.computer_name) {
    $testDeviceName = [string]$local.computer_name
}

$manualTenantEvidencePresent = Test-Path $manualTenantEvidencePath
$manualTenantEvidence = $null
if ($manualTenantEvidencePresent) {
    $manualTenantEvidence = Get-Content $manualTenantEvidencePath -Raw | ConvertFrom-Json
}

$manualTenantEvidenceFound = $false
$manualTenantEvidenceFresh = $false
if ($manualTenantEvidence -and $manualTenantEvidence.PSObject.Properties["tenant_portal_evidence_found"]) {
    $manualTenantEvidenceFound = [bool]$manualTenantEvidence.tenant_portal_evidence_found
}
if (-not $manualTenantEvidenceFound -and $manualTenantEvidence -and -not [string]::IsNullOrWhiteSpace([string]$manualTenantEvidence.alert_title)) {
    $manualTenantEvidenceFound = $true
}
if ($manualTenantEvidenceFound) {
    $manualSavedUtc = ConvertTo-ZTVPUtcDate -Value $manualTenantEvidence.saved_utc
    $manualTenantEvidenceFresh = ($manualSavedUtc -and $manualSavedUtc -ge $windowStartDateUtc)
    $manualTenantEvidenceFound = $manualTenantEvidenceFresh
}

$mpStatus = if ($local -and $local.mp_computer_status_slim) { $local.mp_computer_status_slim } elseif ($local) { $local.mp_computer_status } else { $null }
$detections = if ($local -and $local.mp_threat_detection_slim) { @(ConvertTo-ZTVPArray -Value $local.mp_threat_detection_slim) } elseif ($local) { @(ConvertTo-ZTVPArray -Value $local.mp_threat_detection) } else { @() }
$threats = if ($local -and $local.mp_threat_slim) { @(ConvertTo-ZTVPArray -Value $local.mp_threat_slim) } elseif ($local) { @(ConvertTo-ZTVPArray -Value $local.mp_threat) } else { @() }
$errors = if ($local) { @(ConvertTo-ZTVPArray -Value $local.errors) } else { @() }
$localSummaryObject = if ($local -and $local.local_summary) { $local.local_summary } else { $null }

$realTimeEnabled = $null
if ($mpStatus -and $mpStatus.PSObject.Properties["RealTimeProtectionEnabled"]) {
    $realTimeEnabled = [bool]$mpStatus.RealTimeProtectionEnabled
}

$localDetectionFound = (Test-ZTVPEicarText -Value $detections) -or (Test-ZTVPEicarText -Value $threats)
if ($localSummaryObject -and $localSummaryObject.PSObject.Properties["local_detection_found"]) {
    $localDetectionFound = $localDetectionFound -or [bool]$localSummaryObject.local_detection_found
}
$fileStillExists = if ($local -and $null -ne $local.file_still_exists) { [bool]$local.file_still_exists } else { $null }
$fileRemovedOrQuarantined = ($fileStillExists -eq $false) -and ($local -and (($local.file_write_attempted -eq $true) -or ($local.file_read_attempted -eq $true)))
$fileWriteError = $null
$fileReadError = $null
if ($local) {
    $fileWriteError = $local.file_write_error
    $fileReadError = $local.file_read_error
}
$defenderBlockingError = Test-ZTVPDefenderLikeError -Values @($fileWriteError, $fileReadError, $errors)
if ($localSummaryObject -and $localSummaryObject.PSObject.Properties["eicar_read_blocked"]) {
    $defenderBlockingError = $defenderBlockingError -or [bool]$localSummaryObject.eicar_read_blocked
}

$threatNames = @()
if ($localSummaryObject -and $localSummaryObject.threat_names) {
    $threatNames = @(ConvertTo-ZTVPArray -Value $localSummaryObject.threat_names)
}
elseif ($threats.Count -gt 0) {
    $threatNames = @($threats | ForEach-Object { $_.ThreatName } | Where-Object { $_ })
}

$localPositive = $localDetectionFound -or ($fileRemovedOrQuarantined -and $realTimeEnabled -eq $true) -or $defenderBlockingError
$localPartial = (-not $localPositive) -and (
    ($fileRemovedOrQuarantined -and $null -eq $realTimeEnabled) -or
    ($detections.Count -gt 0) -or
    ($threats.Count -gt 0) -or
    ($errors.Count -gt 0 -and $fileStillExists -eq $false)
)

$localEvidenceStatus = if ($localEvidenceStale) {
    "Stale"
}
elseif (-not $localEvidencePresent) {
    "Missing"
}
elseif ($localPositive) {
    "Found"
}
elseif ($localPartial) {
    "Incomplete"
}
else {
    "Not found"
}

$localSummary = if ($localEvidenceStale) {
    "Imported VM evidence is older than the current validation window and was not used."
}
elseif (-not $localEvidencePresent) {
    "No local VM evidence JSON was imported."
}
elseif ($localPositive) {
    "Local endpoint evidence shows Defender detected, blocked, removed, or quarantined the EICAR test file."
}
elseif ($localPartial) {
    "Local endpoint evidence suggests Defender may have reacted, but the details are incomplete."
}
else {
    "Local endpoint evidence did not show Defender detection, blocking, removal, or quarantine."
}

$mdeStatus = "Not found"
$mdeError = $null
$mdeEvents = @()
$mdeFileEvents = @()
$mdeAlerts = @()
$mdeAlertEvidence = @()
$mdeJoinedAlertEvidence = @()
$mdePollAttempts = 0

if ($cloudEvidenceMode -eq "Local Evidence Only") {
    $mdeStatus = "Skipped by operator"
}
else {
    if ([string]::IsNullOrWhiteSpace($testDeviceName)) {
        $mdeStatus = "Unavailable"
        $mdeError = "Test device name is missing. ZTVP could not use state.test_device_name or local evidence computer_name."
    }
    else {
        $deadline = (Get-Date).AddMinutes([Math]::Max(1, $WaitMinutes))
        $mdeStatus = "Not found"

        try {
            $token = Get-ZTVPMdeToken
        }
        catch {
            $mdeError = $_.Exception.Message
            $statusCode = $null
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
            if ($mdeError -match "Defender XDR API connection required") {
                $mdeStatus = "Defender XDR API connection required"
            }
            elseif ($statusCode -eq 401 -or $mdeError -match "401|Unauthorized|invalid or expired") {
                $mdeStatus = "Unauthorized"
                $mdeError = "Defender XDR token is invalid or expired. Reconnect Defender XDR API."
            }
            else {
                $mdeStatus = "Unavailable"
            }
        }

        while ($token -and (Get-Date) -le $deadline) {
            $mdePollAttempts++
            try {
                $device = New-ZTVPKqlString -Value $testDeviceName
                $shortDeviceName = $testDeviceName
                if ($shortDeviceName -match "\.") {
                    $shortDeviceName = ($shortDeviceName -split "\.")[0]
                }
                $shortDevice = New-ZTVPKqlString -Value $shortDeviceName
                $window = $windowStartUtc

$queryAlertEvidence = @"
AlertEvidence
| where Timestamp >= datetime($window)
| where DeviceName has "$device" or DeviceName =~ "$device" or DeviceName has "$shortDevice"
| project Timestamp, AlertId, DeviceName, EntityType, EvidenceRole, FileName, FolderPath, DetectionSource
"@

                $mdeAlertEvidence = @(Invoke-ZTVPMdeAdvancedHunting -Query $queryAlertEvidence -Token $token)
                $alertIds = @($mdeAlertEvidence | ForEach-Object { [string]$_.AlertId } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
                $alertIdsDynamic = New-ZTVPKqlDynamicStringArray -Values $alertIds

                if ($alertIds.Count -gt 0) {
                    $queryAlertsById = @"
let alertIds = $alertIdsDynamic;
AlertInfo
| where AlertId in (alertIds)
| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, DetectionSource
"@
                    $mdeAlerts = @(Invoke-ZTVPMdeAdvancedHunting -Query $queryAlertsById -Token $token)
                }
                else {
                    $mdeAlerts = @()
                }

                if ($mdeAlerts.Count -eq 0) {
                    $queryAlertsFallback = @"
AlertInfo
| where Timestamp >= datetime($window)
| where Timestamp <= now()
| where Title has_any ("EICAR", "EICAR_Test_File", "malware was prevented", "Malware", "Antivirus", "Defender", "Virus")
| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, DetectionSource
"@
                    $mdeAlerts = @(Invoke-ZTVPMdeAdvancedHunting -Query $queryAlertsFallback -Token $token)
                }

$queryJoinedAlertEvidence = @"
AlertEvidence
| where Timestamp >= datetime($window)
| where DeviceName has "$device" or DeviceName =~ "$device" or DeviceName has "$shortDevice"
| join kind=leftouter (
    AlertInfo
    | where Timestamp >= datetime($window) - 1h
    | project AlertId, AlertTitle=Title, AlertSeverity=Severity, AlertCategory=Category, ServiceSource
) on AlertId
| project Timestamp, AlertId, AlertTitle, AlertSeverity, AlertCategory, ServiceSource, DeviceName, EntityType, EvidenceRole, FileName, FolderPath, DetectionSource
"@

                $queryFileEvents = @"
DeviceFileEvents
| where Timestamp >= datetime($window)
| where DeviceName has "$device" or DeviceName =~ "$device" or DeviceName has "$shortDevice"
| where FileName has_any ("eicar", "eicar.com.txt")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
"@

                $queryDeviceEvents = @"
DeviceEvents
| where Timestamp >= datetime($window)
| where DeviceName has "$device" or DeviceName =~ "$device" or DeviceName has "$shortDevice"
| where ActionType has_any ("Antivirus", "Malware", "Threat", "Quarantine", "ExploitGuard")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, AdditionalFields
"@

                $mdeJoinedAlertEvidence = @(Invoke-ZTVPMdeAdvancedHunting -Query $queryJoinedAlertEvidence -Token $token)
                $mdeFileEvents = @(Invoke-ZTVPMdeAdvancedHunting -Query $queryFileEvents -Token $token)
                $mdeEvents = @(Invoke-ZTVPMdeAdvancedHunting -Query $queryDeviceEvents -Token $token)

                $currentDeviceEvidenceCount = $mdeEvents.Count + $mdeFileEvents.Count + $mdeAlertEvidence.Count + $mdeJoinedAlertEvidence.Count
                $currentAlertInfoCount = if ($alertIds.Count -gt 0 -or $currentDeviceEvidenceCount -gt 0) { $mdeAlerts.Count } else { 0 }
                $mdeCount = $currentDeviceEvidenceCount + $currentAlertInfoCount
                if ($mdeCount -gt 0) {
                    $mdeStatus = "Found"
                    break
                }

                $mdeStatus = "Not found"
                if ((Get-Date).AddSeconds($PollSeconds) -le $deadline) {
                    Start-Sleep -Seconds ([Math]::Max(10, $PollSeconds))
                }
                else {
                    break
                }
            }
            catch {
                $mdeError = $_.Exception.Message
                $statusCode = $null
                try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
                if ($statusCode -eq 401 -or $mdeError -match "401|Unauthorized") {
                    $mdeStatus = "Unauthorized"
                    $mdeError = "Token exists but Defender XDR rejected the request. Reconnect Defender XDR API and ensure AdvancedHunting.Read consent was granted. Raw error: $mdeError"
                    break
                }

                $mdeStatus = "Unavailable"
                if ((Get-Date).AddSeconds($PollSeconds) -le $deadline) {
                    Start-Sleep -Seconds ([Math]::Max(10, $PollSeconds))
                }
                else {
                    break
                }
            }
        }
    }
}

$mdeEvidenceFound = ($mdeStatus -eq "Found")
$mdeLinkedEvidenceCount = $mdeEvents.Count + $mdeFileEvents.Count + $mdeAlertEvidence.Count + $mdeJoinedAlertEvidence.Count
$mdeCountableAlertInfoCount = if ($mdeLinkedEvidenceCount -gt 0) { $mdeAlerts.Count } else { 0 }
$mdeEvidenceCount = $mdeLinkedEvidenceCount + $mdeCountableAlertInfoCount
$mdeAlertInfoTitleFound = (@($mdeAlerts | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Title) }).Count -gt 0) -or (@($mdeJoinedAlertEvidence | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.AlertTitle) }).Count -gt 0)
$mdeAlertEvidenceWithIdFound = (@($mdeAlertEvidence | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.AlertId) }).Count -gt 0) -or (@($mdeJoinedAlertEvidence | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.AlertId) }).Count -gt 0)
$mdeAlertFound = $mdeAlertEvidenceWithIdFound
$mdeDeviceEvidenceFound = ($mdeAlertEvidence.Count -gt 0) -or ($mdeJoinedAlertEvidence.Count -gt 0) -or ($mdeFileEvents.Count -gt 0) -or ($mdeEvents.Count -gt 0)
$resolvedAlertTitle = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlerts) -Names @("AlertTitle", "Title")
if ([string]::IsNullOrWhiteSpace($resolvedAlertTitle) -and $mdeAlertEvidenceWithIdFound) {
    $resolvedAlertTitle = "Alert title not returned by AlertInfo lookup"
}

$tenantAlertSummary = [PSCustomObject]@{
    alert_found = $mdeAlertFound
    alert_info_title_found = $mdeAlertInfoTitleFound
    alert_evidence_found = $mdeAlertEvidenceWithIdFound
    alert_title = $resolvedAlertTitle
    alert_severity = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlerts) -Names @("AlertSeverity", "Severity")
    alert_category = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlerts) -Names @("AlertCategory", "Category")
    service_source = if ($mdeAlertEvidenceWithIdFound -and [string]::IsNullOrWhiteSpace((Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlerts) -Names @("ServiceSource")))) { "Microsoft Defender for Endpoint" } else { Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlerts) -Names @("ServiceSource") }
    alert_id = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence + $mdeAlerts) -Names @("AlertId")
    alert_timestamp = Get-ZTVPFirstValue -Rows @($mdeAlerts + $mdeJoinedAlertEvidence + $mdeAlertEvidence) -Names @("Timestamp")
    detection_source = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence) -Names @("DetectionSource")
}

$tenantDeviceSummary = [PSCustomObject]@{
    device_evidence_found = $mdeDeviceEvidenceFound
    device_name = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence + $mdeFileEvents + $mdeEvents) -Names @("DeviceName")
    entity_type = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence) -Names @("EntityType")
    evidence_role = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence) -Names @("EvidenceRole")
    file_name = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence + $mdeFileEvents + $mdeEvents) -Names @("FileName")
    folder_path = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence + $mdeFileEvents + $mdeEvents) -Names @("FolderPath")
    detection_source = Get-ZTVPFirstValue -Rows @($mdeJoinedAlertEvidence + $mdeAlertEvidence) -Names @("DetectionSource")
}

$apiPermissionGuidance = $null
if ($mdeStatus -eq "Unauthorized" -or $mdeStatus -eq "Unavailable") {
    $apiPermissionGuidance = [PSCustomObject]@{
        message = "ZTVP could not query Advanced Hunting because the token/account lacks permission. This does not mean the tenant failed to capture the alert."
        required_api_permission = @(
            "Delegated: AdvancedHunting.Read",
            "Application: AdvancedHunting.Read.All"
        )
        api_endpoint = "POST https://api.security.microsoft.com/api/advancedhunting/run"
        token_audience = "https://api.security.microsoft.com"
        token_scope = "https://api.security.microsoft.com/AdvancedHunting.Read"
        defender_access_note = "The user/app must have Defender XDR permissions to view data and run Advanced Hunting, and must have access to the device group containing the test device."
    }
}

$status = "FAIL_DEFENDER_EICAR_NOT_DETECTED"
$risk = "HIGH"
$conclusion = "FAIL - No local Defender reaction and no tenant-side Defender evidence were found."
$evidenceQuality = "No local or tenant Defender evidence was found."
$outcomeTitle = "Control gap"
$outcomeText = "The EICAR test file remained on disk and no Defender detection evidence was found."
$recommendations = @(
    "Enable Defender Antivirus real-time protection.",
    "Review AV policy deployment.",
    "Check exclusions for the test path.",
    "Confirm Sense and WinDefend services are running.",
    "Confirm the endpoint is onboarded to MDE.",
    "Investigate why EICAR was not detected."
)

if ($localPositive -or $mdeEvidenceFound -or $manualTenantEvidenceFound) {
    $status = "PASS_DEFENDER_EICAR_DETECTED"
    $risk = "LOW"

    if ($localPositive -and $mdeEvidenceFound) {
        if ($mdeAlertInfoTitleFound) {
            $conclusion = "PASS - Defender reacted locally and a tenant-side Defender alert was found."
        }
        elseif ($mdeAlertEvidenceWithIdFound) {
            $conclusion = "PASS - Defender reacted locally and tenant-side Defender alert evidence was found."
        }
        else {
            $conclusion = "PASS - Defender reacted locally and tenant-side Defender API evidence was found."
        }
        $outcomeTitle = "Validated outcome"
        $outcomeText = "Defender reacted during the controlled EICAR validation and tenant-side evidence was captured."
        $recommendations = @(
            "Keep Defender real-time protection enabled.",
            "Keep MDE onboarding healthy.",
            "Keep monitoring Defender alerts and endpoint telemetry.",
            "Use this result as evidence that endpoint malware protection reacted and tenant telemetry was captured."
        )
    }
    elseif ($localPositive -and $manualTenantEvidenceFound) {
        $conclusion = "PASS - Defender reacted locally and tenant-side Defender portal evidence was recorded."
        $outcomeTitle = "Validated outcome"
        $outcomeText = "Defender reacted during the controlled EICAR validation. Tenant-side Defender portal evidence was recorded by the operator."
        $recommendations = @(
            "Keep Defender real-time protection enabled.",
            "Keep MDE onboarding healthy.",
            "Keep monitoring Defender alerts and endpoint telemetry.",
            "Tenant portal evidence was recorded manually. API automation still needs authorization."
        )
    }
    elseif ($localPositive) {
        if ($mdeStatus -eq "Unauthorized") {
            $conclusion = "PASS - Defender reacted locally. ZTVP could not query tenant evidence because the Advanced Hunting API returned 401 Unauthorized."
            $recommendations = @(
                "Grant ZTVP the Defender XDR delegated permission AdvancedHunting.Read, or application permission AdvancedHunting.Read.All.",
                "Verify the signed-in user/app has permission to run Advanced Hunting.",
                "Confirm device group scoping allows access to the test device.",
                "Keep the manually recorded Defender portal alert as tenant evidence for this run."
            )
        }
        elseif ($mdeStatus -eq "Defender XDR API connection required" -or $mdeError -match "Defender XDR API connection required") {
            $conclusion = "PASS - Defender reacted locally. ZTVP could not query tenant evidence because Defender XDR API is not connected."
            $recommendations = @(
                "Connect Defender XDR API from DEV-DV-006 Step 4.",
                "Rerun Step 4 to collect tenant-side Defender evidence.",
                "Keep Defender real-time protection enabled."
            )
        }
        else {
            $conclusion = "PASS - Defender reacted locally. Tenant-side API evidence was unavailable or unauthorized."
            if ($mdeStatus -eq "Not found") {
                $conclusion = "PASS - Defender reacted locally. Tenant-side evidence was not found within the selected wait window."
            }
            $recommendations = @(
                "Keep Defender real-time protection enabled.",
                "Confirm the device appears in Defender portal and Sense service is running.",
                "Rerun tenant API evidence analysis after permissions and telemetry are ready."
            )
        }
        $outcomeTitle = "Validated outcome"
        $outcomeText = "Defender detected, blocked, quarantined, or removed the EICAR test file. Endpoint malware protection worked during this validation."
    }
    elseif ($mdeEvidenceFound) {
        if ($mdeAlertInfoTitleFound) {
            $conclusion = "PASS - Tenant-side Defender alert was found, but local VM evidence was not imported."
        }
        elseif ($mdeAlertEvidenceWithIdFound) {
            $conclusion = "PASS - Tenant-side Defender alert evidence was found, but local VM evidence was not imported."
        }
        else {
            $conclusion = "PASS - Tenant-side Defender API evidence was found, but local VM evidence was not imported."
        }
        $outcomeTitle = "Validated outcome"
        $outcomeText = "Tenant-side Defender evidence was captured for the controlled EICAR validation."
        $recommendations = @(
            "Keep Defender real-time protection enabled.",
            "Keep MDE onboarding healthy.",
            "Import the local VM evidence JSON on future runs to preserve endpoint-side proof."
        )
    }
    else {
        $conclusion = "PASS - Tenant-side Defender portal evidence was recorded, but local VM evidence was not imported."
        $outcomeTitle = "Validated outcome"
        $outcomeText = "Tenant-side Defender portal evidence was recorded by the operator."
        $recommendations = @(
            "Keep Defender real-time protection enabled.",
            "Tenant portal evidence was recorded manually. API automation still needs authorization.",
            "Import the local VM evidence JSON on future runs to preserve endpoint-side proof."
        )
    }

    $evidenceQuality = "Defender reaction evidence was found."
}
elseif ($localPartial -or $mdeStatus -eq "Unavailable" -or $mdeStatus -eq "Unauthorized" -or $mdeStatus -eq "Defender XDR API connection required") {
    $status = "PARTIAL_DEFENDER_REACTION_INCOMPLETE"
    $risk = "MEDIUM"
    $conclusion = "PARTIAL - Defender reaction evidence is incomplete or cloud evidence is unavailable."
    $evidenceQuality = "Local evidence is incomplete or tenant-side Defender evidence could not be queried."
    $outcomeTitle = "Evidence incomplete"
    $outcomeText = "Local evidence suggests Defender reacted, but evidence is incomplete or cloud evidence is unavailable/delayed."
    $recommendations = @(
        "Rerun tenant evidence analysis after a few minutes.",
        "Confirm the VM evidence JSON is complete.",
        "Confirm the test device name matches Defender portal.",
        "Confirm Defender XDR / Advanced Hunting permissions."
    )
    if ($mdeStatus -eq "Unauthorized") {
        $recommendations = @(
            "Grant ZTVP the Defender XDR delegated permission AdvancedHunting.Read, or application permission AdvancedHunting.Read.All.",
            "Verify the signed-in user/app has permission to run Advanced Hunting.",
            "Confirm device group scoping allows access to the test device.",
            "Record manual Defender portal evidence if an alert is visible in the portal."
        )
    }
}

$freshLocalActionAttempted = $localEvidenceAccepted -and $local -and (($local.file_write_attempted -eq $true) -or ($local.file_read_attempted -eq $true))
$freshTenantEvidenceFound = $mdeEvidenceFound

if ($localPositive -and $freshTenantEvidenceFound) {
    $status = "PASS_DEFENDER_EICAR_DETECTED"
    $risk = "LOW"
    if ($mdeAlertInfoTitleFound) {
        $conclusion = "PASS - Defender reacted locally and Microsoft Defender XDR captured the EICAR alert."
    }
    elseif ($mdeAlertEvidenceWithIdFound) {
        $conclusion = "PASS - Defender reacted locally and tenant-side Defender alert evidence was found."
    }
    else {
        $conclusion = "PASS - Defender reacted locally and tenant-side Defender evidence was found."
    }
    $evidenceQuality = "Fresh local and tenant-side Defender evidence was found for the current run."
    $outcomeTitle = "Validated outcome"
    $outcomeText = "Defender reacted during the controlled EICAR validation and tenant-side evidence was captured after the current validation window."
    $recommendations = @(
        "Keep Defender real-time protection enabled.",
        "Keep MDE onboarding healthy.",
        "Keep monitoring Defender alerts and endpoint telemetry.",
        "Use this result as evidence that endpoint malware protection reacted and tenant telemetry was captured."
    )
}
elseif ($localPositive) {
    $status = "PARTIAL_DEFENDER_REACTION_INCOMPLETE"
    $risk = "MEDIUM"
    $evidenceQuality = "Fresh local Defender reaction was found, but tenant-side evidence is incomplete."
    $outcomeTitle = "Evidence incomplete"
    if ($mdeStatus -eq "Unauthorized" -or $mdeStatus -eq "Unavailable" -or $mdeStatus -eq "Defender XDR API connection required") {
        $conclusion = "PARTIAL - Defender reacted locally, but tenant-side API validation could not be completed."
        $outcomeText = "Defender reacted locally, but tenant-side evidence could not be queried because Defender XDR API connection is missing, unavailable, or unauthorized."
        $recommendations = @(
            "Connect Defender XDR API from DEV-DV-006.",
            "Sign in and consent to AdvancedHunting.Read.",
            "Rerun Step 4 after connection is ready.",
            "Confirm the token cache is valid.",
            "Use manual portal evidence only as fallback."
        )
    }
    else {
        $conclusion = "PARTIAL - Defender reacted locally, but tenant-side evidence was not found."
        $outcomeText = "Defender reacted locally, but ZTVP did not find tenant-side Defender XDR evidence within the selected wait window."
        $recommendations = @(
            "Wait a few more minutes and rerun tenant evidence analysis.",
            "Confirm the device appears in Microsoft Defender portal -> Assets -> Devices.",
            "Confirm Sense service is running on the endpoint.",
            "Confirm the endpoint is onboarded to Microsoft Defender for Endpoint.",
            "Confirm Advanced Hunting permissions are valid.",
            "Confirm the device name in ZTVP matches the Defender portal device name.",
            "Check Incidents & alerts manually for EICAR."
        )
    }
}
elseif ($freshTenantEvidenceFound) {
    $status = "PARTIAL_DEFENDER_REACTION_INCOMPLETE"
    $risk = "MEDIUM"
    $conclusion = "PARTIAL - Tenant-side Defender evidence was found after the current validation window, but fresh VM evidence was not imported."
    $evidenceQuality = "Fresh tenant-side Defender evidence was found, but endpoint-side proof is missing."
    $outcomeTitle = "Evidence incomplete"
    $outcomeText = "Microsoft Defender XDR captured tenant-side evidence for the current validation window, but no fresh VM JSON evidence was imported for this run."
    $recommendations = @(
        "Import the VM JSON evidence for this run.",
        "Confirm the VM script was run inside the controlled endpoint.",
        "Keep MDE onboarding healthy.",
        "Use tenant-side evidence as partial validation until endpoint-side proof is imported."
    )
}
elseif ($localPartial) {
    $status = "PARTIAL_DEFENDER_REACTION_INCOMPLETE"
    $risk = "MEDIUM"
    $conclusion = "PARTIAL - Fresh local VM evidence is incomplete and tenant-side evidence was not found."
    $evidenceQuality = "Fresh local evidence exists for this run, but Defender reaction details are incomplete."
    $outcomeTitle = "Evidence incomplete"
    $outcomeText = "The controlled action appears to have run, but local Defender evidence is incomplete and tenant-side evidence was not found."
    $recommendations = @(
        "Rerun the VM script and import the fresh JSON evidence.",
        "Confirm Defender real-time protection is enabled.",
        "Confirm Sense service is running.",
        "Rerun tenant evidence analysis after a few minutes."
    )
}
elseif ($freshLocalActionAttempted -and -not $localPositive) {
    $status = "FAIL_DEFENDER_EICAR_NOT_DETECTED"
    $risk = "HIGH"
    $conclusion = "FAIL - Defender did not provide local or tenant-side evidence for the EICAR validation."
    $evidenceQuality = "Fresh VM evidence shows the test action was attempted, but no Defender reaction or tenant-side evidence was found."
    $outcomeTitle = "Control gap"
    $outcomeText = "The EICAR test action was executed for this run, but Defender did not show local or tenant-side evidence."
    $recommendations = @(
        "Confirm Microsoft Defender Antivirus is enabled.",
        "Confirm real-time protection is enabled.",
        "Confirm Defender is not running in passive mode.",
        "Review Defender AV policy deployment.",
        "Check whether the test folder or EICAR file is excluded.",
        "Confirm the WinDefend service is running.",
        "Confirm the endpoint is onboarded to MDE.",
        "Confirm Sense service is running.",
        "Rerun the validation after policy correction."
    )
}
else {
    $status = "NOT_RUN_CONTROLLED_ACTION_NOT_EXECUTED"
    $risk = "NOT ASSESSED"
    $conclusion = "Validation has not been completed. No VM test evidence was imported for this run, and no tenant-side evidence was found after the current validation window."
    $evidenceQuality = "No fresh endpoint or tenant-side evidence was found for the current run."
    $outcomeTitle = "Validation not completed"
    $outcomeText = "The validation window was armed, but no fresh endpoint evidence was imported and no tenant-side evidence was found for this run."
    $recommendations = @(
        "Generate the controlled EICAR action.",
        "Run it inside the controlled VM as Administrator.",
        "Import the VM JSON evidence.",
        "Rerun analysis."
    )
}

$localEvidence = [PSCustomObject]@{
    imported_local_evidence_present = $localEvidencePresent
    local_evidence_accepted_for_current_run = $localEvidenceAccepted
    local_evidence_stale = $localEvidenceStale
    local_evidence_invalid_reason = $localEvidenceInvalidReason
    local_evidence_timestamp_utc = if ($localEvidenceTimestampUtc) { $localEvidenceTimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
    test_device_name_from_vm = if ($local) { $local.computer_name } else { $null }
    file_path = if ($local) { $local.file_path } else { $null }
    file_still_exists = $fileStillExists
    real_time_protection_enabled = $realTimeEnabled
    eicar_read_blocked = $defenderBlockingError
    local_detection_found = $localDetectionFound
    threat_names = @($threatNames)
    defender_blocking_error_found = $defenderBlockingError
    file_removed_or_quarantined = $fileRemovedOrQuarantined
    local_evidence_status = $localEvidenceStatus
    local_summary = $localSummary
    raw = $local
}

$tenantApiEvidence = [PSCustomObject]@{
    cloud_evidence_mode = $cloudEvidenceMode
    tenant_id = $tenantId
    tenant_display_name = $tenantDisplayName
    client_id = $clientId
    token_cache_path = "powershell\Auth\ztvp-defenderxdr-token-cache.json"
    test_device_name_requested = $testDeviceName
    mde_cloud_query_status = $mdeStatus
    mde_cloud_evidence_found = $mdeEvidenceFound
    mde_cloud_evidence_count = $mdeEvidenceCount
    mde_cloud_error = $mdeError
    tenant_defender_alert = $tenantAlertSummary
    tenant_device_evidence = $tenantDeviceSummary
    mde_cloud_events = @($mdeEvents + $mdeAlertEvidence + $mdeJoinedAlertEvidence)
    mde_cloud_alerts = @($mdeAlerts)
    mde_cloud_alert_evidence = @($mdeAlertEvidence)
    mde_cloud_joined_alert_evidence = @($mdeJoinedAlertEvidence)
    mde_cloud_file_events = @($mdeFileEvents)
    mde_cloud_poll_attempts = $mdePollAttempts
    mde_cloud_wait_minutes = $WaitMinutes
    mde_cloud_poll_seconds = $PollSeconds
    validation_window_start_utc = $windowStartUtc
    api_permission_guidance = $apiPermissionGuidance
}

$tenantPortalManualEvidence = if ($manualTenantEvidence) {
    $manualTenantEvidence
}
else {
    [PSCustomObject]@{
        tenant_portal_evidence_found = $false
        alert_title = ""
        alert_severity = ""
        alert_status = ""
        alert_category = ""
        evidence_location = ""
        evidence_notes = ""
        screenshot_reference = ""
        saved_utc = ""
    }
}

if ($tenantPortalManualEvidence -and -not [string]::IsNullOrWhiteSpace([string]$tenantPortalManualEvidence.alert_title)) {
    $tenantPortalManualEvidence.tenant_portal_evidence_found = $true
}

$tenantEvidence = [PSCustomObject]@{
    api = $tenantApiEvidence
    portal_manual = $tenantPortalManualEvidence
}

$result = [PSCustomObject]@{
    scenario_id = "DEV-DV-006"
    display_id = "DEV-DV-006"
    run_id = $runId
    scenario_name = "Defender EICAR Detection Validation"
    pillar = "Devices"
    scope = "Cloud"
    generated_at = (Get-Date).ToString("s")
    tenant_id = $tenantId
    tenant_display_name = $tenantDisplayName
    client_id = $clientId
    status = $status
    risk = $risk
    test_device = if ($local -and $local.computer_name) { $local.computer_name } else { $testDeviceName }
    validation_method = "Manual VM Script"
    validation_window_start_utc = $windowStartUtc
    tenant_analysis_started_utc = $analysisStartedUtc
    tenant_analysis_completed_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    vm_script_generated = if ($state.PSObject.Properties["vm_script_generated"]) { [bool]$state.vm_script_generated } else { $false }
    local_evidence_imported = $stateSaysLocalImported
    local_evidence_accepted_for_current_run = $localEvidenceAccepted
    eicar_file_path = if ($local) { $local.file_path } else { $state.test_file }
    clean_conclusion = $conclusion
    outcome_title = $outcomeTitle
    outcome_text = $outcomeText
    evidence_quality = $evidenceQuality
    controlled_action = "Create the harmless EICAR antivirus test file inside a separate VM/test endpoint and collect local plus tenant-side Defender evidence."
    expected_result = "Microsoft Defender detects, blocks, quarantines, or removes the EICAR test file and Defender XDR/MDE captures tenant-side telemetry when available."
    evidence = [PSCustomObject]@{
        local = $localEvidence
        tenant = $tenantEvidence
    }
    local_evidence = $local
    mde_cloud_evidence = [PSCustomObject]@{
        status = $mdeStatus
        found = $mdeEvidenceFound
        count = $mdeEvidenceCount
        error = $mdeError
        alert_found = $mdeAlertFound
        alert_title = $tenantAlertSummary.alert_title
    }
    metrics = [PSCustomObject]@{
        real_time_protection_enabled = $realTimeEnabled
        file_still_exists = $fileStillExists
        local_defender_detection_found = $localDetectionFound
        file_removed_or_quarantined = $fileRemovedOrQuarantined
        defender_like_blocking_error_found = $defenderBlockingError
        mde_cloud_query_status = $mdeStatus
        mde_cloud_evidence_found = $mdeEvidenceFound
        mde_cloud_evidence_count = $mdeEvidenceCount
        mde_cloud_alert_found = $mdeAlertFound
        mde_cloud_poll_attempts = $mdePollAttempts
    }
    recommendations = @($recommendations)
    limitations = @(
        "This scenario uses manual VM script mode because the test endpoint is separate from the ZTVP host.",
        "Tenant-side Defender evidence requires Defender XDR Advanced Hunting API access.",
        "Cloud MDE alert evidence can be delayed or unavailable and should be rechecked if the result is PARTIAL."
    )
}

Write-ZTVPJson -Path $reportPath -Object $result

Set-ZTVPObjectProperty -Object $state -Name "tenant_analysis_completed_utc" -Value $result.tenant_analysis_completed_utc
Set-ZTVPObjectProperty -Object $state -Name "current_run_report_path" -Value $reportPath
Set-ZTVPObjectProperty -Object $state -Name "current_run_status" -Value $status
Write-ZTVPJson -Path $statePath -Object $state

$statusHtml = ConvertTo-ZTVPHtmlSafe $status
$riskHtml = ConvertTo-ZTVPHtmlSafe $risk
$deviceHtml = ConvertTo-ZTVPHtmlSafe $result.test_device
$windowHtml = ConvertTo-ZTVPHtmlSafe $windowStartUtc
$pathHtml = ConvertTo-ZTVPHtmlSafe $result.eicar_file_path
$localHtml = ConvertTo-ZTVPHtmlSafe $localEvidenceStatus
$mdeStatusHtml = ConvertTo-ZTVPHtmlSafe $mdeStatus
$mdeCountHtml = ConvertTo-ZTVPHtmlSafe $mdeEvidenceCount
$alertTitleHtml = ConvertTo-ZTVPHtmlSafe $tenantAlertSummary.alert_title
$conclusionHtml = ConvertTo-ZTVPHtmlSafe $conclusion
$jsonHtml = ConvertTo-ZTVPHtmlSafe ($result | ConvertTo-Json -Depth 100)

$html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>DEV-DV-006 - Defender EICAR Detection Validation</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #0f172a; background: #f8fafc; }
.card { background: #ffffff; border: 1px solid #dbe3ef; border-radius: 14px; padding: 18px; margin: 14px 0; }
.grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
.metric span { display:block; color:#64748b; font-size:12px; font-weight:700; }
.metric strong { display:block; margin-top:6px; font-size:16px; }
.conclusion { font-weight: 750; line-height: 1.55; }
pre { white-space: pre-wrap; background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 12px; overflow: auto; }
</style>
</head>
<body>
<h1>DEV-DV-006 - Defender EICAR Detection Validation</h1>
<div class="grid">
<div class="card metric"><span>Verdict</span><strong>$statusHtml</strong></div>
<div class="card metric"><span>Risk</span><strong>$riskHtml</strong></div>
<div class="card metric"><span>Test device</span><strong>$deviceHtml</strong></div>
<div class="card metric"><span>Method</span><strong>Manual VM Script</strong></div>
</div>
<div class="card conclusion">$conclusionHtml</div>
<div class="grid">
<div class="card metric"><span>Validation window</span><strong>$windowHtml</strong></div>
<div class="card metric"><span>EICAR file path</span><strong>$pathHtml</strong></div>
<div class="card metric"><span>Local evidence</span><strong>$localHtml</strong></div>
<div class="card metric"><span>MDE cloud evidence</span><strong>$mdeStatusHtml ($mdeCountHtml)</strong></div>
</div>
<div class="card metric"><span>Tenant Defender alert</span><strong>$alertTitleHtml</strong></div>
<h2>Full JSON Evidence</h2>
<pre>$jsonHtml</pre>
</body>
</html>
"@

Set-Content -Path $htmlPath -Value $html -Encoding UTF8

Write-Host ""
Write-Host "DEV-DV-006 analysis completed."
Write-Host "Status: $status"
Write-Host "Risk: $risk"
Write-Host "Local evidence: $localEvidenceStatus"
Write-Host "MDE cloud query status: $mdeStatus"
Write-Host "MDE cloud evidence count: $mdeEvidenceCount"
Write-Host "MDE cloud poll attempts: $mdePollAttempts"
Write-Host "Report: $reportPath"
Write-Host "HTML: $htmlPath"
Write-Host ""
