param(
    [ValidateSet("Root site","Custom site ID")]
    [string]$SiteMode = "Root site",

    [string]$SiteId = "",

    [ValidateSet("view")]
    [string]$RequestedLinkType = "view",

    [int]$MonitoringWindowMinutes = 15,

    [int]$PollIntervalSeconds = 60,

    [string]$MdcaApiBaseUrl = "",

    [string]$MdcaApiToken = "",

    [string]$MdcaPolicyName = "ZTVP - Detect Public SharePoint File Sharing"
)

$ErrorActionPreference = "Stop"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "Sites.ReadWrite.All",
    "Files.ReadWrite.All",
    "Directory.Read.All"
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
        Connect-MgGraph -Scopes $Scopes -ContextScope CurrentUser -NoWelcome | Out-Null
        $ctx = Get-MgContext
    }

    return $ctx
}

function Write-ZTVPJson {
    param([string]$Path, [object]$Object)

    $Object |
        ConvertTo-Json -Depth 100 |
        Set-Content -Path $Path -Encoding UTF8
}

function Test-ZTVPNotFound {
    param([string]$Message)

    return (
        $Message -match "404" -or
        $Message -match "not found" -or
        $Message -match "does not exist" -or
        $Message -match "itemNotFound" -or
        $Message -match "ResourceNotFound"
    )
}

function Get-ZTVPMdcaAlertsEndpoint {
    param([string]$BaseUrl)

    $base = $BaseUrl.Trim().TrimEnd("/")

    if ([string]::IsNullOrWhiteSpace($base)) {
        return ""
    }

    if ($base.ToLower().EndsWith("/api")) {
        return "$base/v1/alerts/"
    }

    return "$base/api/v1/alerts/"
}

function Invoke-ZTVPMdcaAlertQuery {
    param(
        [string]$Endpoint,
        [string]$Token
    )

    $headers = @{
        "Authorization" = "Token $Token"
        "Content-Type" = "application/json"
    }

    $body = @{
        skip = 0
        limit = 100
        sortField = "date"
        sortDirection = "desc"
    } | ConvertTo-Json -Depth 20

    try {
        return Invoke-RestMethod -Method POST -Uri $Endpoint -Headers $headers -Body $body -ContentType "application/json" -ErrorAction Stop
    }
    catch {
        try {
            return Invoke-RestMethod -Method GET -Uri $Endpoint -Headers $headers -ErrorAction Stop
        }
        catch {
            throw "MDCA alert API query failed: $($_.Exception.Message)"
        }
    }
}

function Find-ZTVPMatchingMdcaAlert {
    param(
        [object]$AlertResponse,
        [int64]$StartEpochMs,
        [string]$PolicyName,
        [string]$RunId,
        [string]$FileName,
        [string]$FolderName
    )

    $data = @(Get-ZTVPValue -Object $AlertResponse -Name "data")

    foreach ($alert in $data) {
        $timestamp = 0

        try {
            $timestamp = [int64](Get-ZTVPValue -Object $alert -Name "timestamp")
        }
        catch {
            $timestamp = 0
        }

        if ($timestamp -lt $StartEpochMs) {
            continue
        }

        $alertText = ($alert | ConvertTo-Json -Depth 50)

        $matched = $false
        $matchReason = ""

        if (-not [string]::IsNullOrWhiteSpace($PolicyName) -and $alertText -like "*$PolicyName*") {
            $matched = $true
            $matchReason = "Matched configured MDCA policy name."
        }
        elseif ($alertText -like "*$RunId*" -or $alertText -like "*$FileName*" -or $alertText -like "*$FolderName*" -or $alertText -like "*ZTVP*") {
            $matched = $true
            $matchReason = "Matched ZTVP run/file/folder marker in MDCA alert."
        }

        if ($matched) {
            return [PSCustomObject]@{
                matched = $true
                match_reason = $matchReason
                alert_id = Get-ZTVPValue -Object $alert -Name "_id"
                id_value = Get-ZTVPValue -Object $alert -Name "idValue"
                title = Get-ZTVPValue -Object $alert -Name "title"
                description = Get-ZTVPValue -Object $alert -Name "description"
                severity_value = Get-ZTVPValue -Object $alert -Name "severityValue"
                status_value = Get-ZTVPValue -Object $alert -Name "statusValue"
                resolution_status_value = Get-ZTVPValue -Object $alert -Name "resolutionStatusValue"
                timestamp = $timestamp
                url = Get-ZTVPValue -Object $alert -Name "URL"
                evidence = Get-ZTVPValue -Object $alert -Name "evidence"
            }
        }
    }

    return [PSCustomObject]@{
        matched = $false
        match_reason = "No matching MDCA alert found."
    }
}

function Test-ZTVPPermissionStillExists {
    param(
        [string]$DriveId,
        [string]$FileId,
        [string]$PermissionId
    )

    if ([string]::IsNullOrWhiteSpace($PermissionId)) {
        return $false
    }

    try {
        Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/drives/$DriveId/items/$FileId/permissions/$PermissionId" | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function New-ZTVPResult {
    param(
        [object]$State,
        [string]$Status,
        [string]$Risk,
        [string]$Summary,
        [string]$FinalClaim,
        [string]$EvidenceQuality,
        [object[]]$Warnings,
        [object]$MdcaEvidence,
        [object]$CleanupRecord,
        [object]$Metrics
    )

    return [PSCustomObject]@{
        scenario_id = "APP-C-003"
        display_id = "APP-DV-003"
        scenario_name = "MDCA Public File Sharing Detection Validation"
        pillar = "Applications"
        scope = "Cloud"
        generated_at = (Get-Date).ToString("s")
        tenant_id = $State.tenant_id
        connected_account = $State.connected_account

        control_tested = "Microsoft Defender for Cloud Apps should detect or remediate controlled public SharePoint file exposure."
        expected_result = "A controlled public file exposure should be detected by MDCA alerting and/or remediated by governance action."
        failure_condition = "The dummy file becomes publicly shared, but no MDCA alert or remediation evidence is found during the monitoring window."
        test_method = "Create a harmless dummy SharePoint file, create an anonymous public link, poll the MDCA Alerts API, check whether the permission is remediated, then remove the public link and delete the dummy object."

        status = $Status
        risk = $Risk
        executive_summary = $Summary
        final_claim = $FinalClaim
        evidence_quality = $EvidenceQuality
        warnings = @($Warnings)

        site = $State.site
        drive = $State.drive
        dummy_file = $State.test_object
        anonymous_public_link_attempt = $State.anonymous_public_link_attempt
        mdca_detection_evidence = $MdcaEvidence
        cleanup = $CleanupRecord
        metrics = $Metrics

        recommendations = @(
            "Keep anonymous/public sharing disabled unless required.",
            "If public sharing is allowed, restrict it to approved low-risk sites.",
            "Use MDCA file policies to detect public SharePoint files.",
            "Enable governance actions such as Make private or Remove external users after testing alert-only mode.",
            "Review MDCA alert routing and governance logs.",
            "Do not store public sharing URLs in reports."
        )

        limitations = @(
            "MDCA file policy detection may not be instant.",
            "The monitoring window may need to be 10 to 30 minutes depending on tenant latency.",
            "If SharePoint blocks anonymous link creation, the MDCA detection scenario cannot be triggered.",
            "This version uses the MDCA Alerts API and requires a valid MDCA API URL and token.",
            "The validation only uses a controlled dummy file and does not touch business files."
        )
    }
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "APP-C-003"
$historyDir = Join-Path $scenarioDir "history"

New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null
New-Item -ItemType Directory -Path $historyDir -Force | Out-Null

$statePath = Join-Path $scenarioDir "appc003-state.json"
$reportPath = Join-Path $reportRoot "APP-C-003-result.json"

if (Test-Path $statePath) {
    throw "An active APP-C-003 state file exists. Run emergency cleanup before starting a new run."
}

$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$folderName = "ZTVP-APPC003-MDCA-PublicFile-Test-$runId"
$fileName = "ztvp-appc003-mdca-public-file-test.txt"
$fileContent = "ZTVP controlled dummy file for MDCA public sharing detection. No business data. RunId=$runId"

$startEpochMs = [int64]([DateTimeOffset](Get-Date).ToUniversalTime()).ToUnixTimeMilliseconds()

$site = $null
$drive = $null
$folder = $null
$file = $null
$permission = $null

$publicLinkCreated = $false
$createLinkError = $null
$permissionId = $null
$warnings = @()

$cleanupActions = @()
$cleanupErrors = @()

try {
    if ($SiteMode -eq "Custom site ID") {
        if ([string]::IsNullOrWhiteSpace($SiteId)) {
            throw "Custom site ID mode was selected, but no SiteId was supplied."
        }

        $encodedSiteId = [System.Uri]::EscapeDataString($SiteId)
        $site = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$encodedSiteId?`$select=id,displayName,webUrl"
    }
    else {
        $site = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/root?`$select=id,displayName,webUrl"
    }

    $siteIdResolved = [string](Get-ZTVPValue -Object $site -Name "id")

    $drive = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$siteIdResolved/drive"
    $driveId = [string](Get-ZTVPValue -Object $drive -Name "id")

    $folderBody = @{
        name = $folderName
        folder = @{}
        "@microsoft.graph.conflictBehavior" = "fail"
    } | ConvertTo-Json -Depth 20

    $folder = Invoke-MgGraphRequest `
        -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/root/children" `
        -Body $folderBody `
        -ContentType "application/json"

    $folderId = [string](Get-ZTVPValue -Object $folder -Name "id")

    $fileUri = "https://graph.microsoft.com/v1.0/drives/$driveId/items/${folderId}:/$fileName`:/content"

    $file = Invoke-MgGraphRequest `
        -Method PUT `
        -Uri $fileUri `
        -Body $fileContent `
        -ContentType "text/plain"

    $fileId = [string](Get-ZTVPValue -Object $file -Name "id")

    try {
        $linkBody = @{
            type = $RequestedLinkType
            scope = "anonymous"
            retainInheritedPermissions = $false
        } | ConvertTo-Json -Depth 20

        $permission = Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/items/$fileId/createLink" `
            -Body $linkBody `
            -ContentType "application/json"

        $publicLinkCreated = $true
        $permissionId = [string](Get-ZTVPValue -Object $permission -Name "id")
    }
    catch {
        $createLinkError = $_.Exception.Message
    }

    $state = [PSCustomObject]@{
        scenario_id = "APP-C-003"
        display_id = "APP-DV-003"
        scenario_name = "MDCA Public File Sharing Detection Validation"
        run_id = $runId
        started_at = (Get-Date).ToString("s")
        tenant_id = $ctx.TenantId
        connected_account = $ctx.Account
        monitoring_window_minutes = $MonitoringWindowMinutes
        poll_interval_seconds = $PollIntervalSeconds
        mdca_policy_name = $MdcaPolicyName

        site = [PSCustomObject]@{
            id = Get-ZTVPValue -Object $site -Name "id"
            displayName = Get-ZTVPValue -Object $site -Name "displayName"
            webUrl = Get-ZTVPValue -Object $site -Name "webUrl"
        }

        drive = [PSCustomObject]@{
            id = Get-ZTVPValue -Object $drive -Name "id"
            name = Get-ZTVPValue -Object $drive -Name "name"
            webUrl = Get-ZTVPValue -Object $drive -Name "webUrl"
        }

        test_object = [PSCustomObject]@{
            folder_id = $folderId
            folder_name = $folderName
            file_id = $fileId
            file_name = $fileName
            contains_business_data = $false
        }

        anonymous_public_link_attempt = [PSCustomObject]@{
            attempted = $true
            requested_scope = "anonymous"
            requested_type = $RequestedLinkType
            public_link_created = $publicLinkCreated
            permission_id = $permissionId
            public_url_stored = $false
            public_url_note = "ZTVP does not store anonymous public sharing URLs in reports."
            error_message = $createLinkError
        }
    }

    Write-ZTVPJson -Path $statePath -Object $state

    if (-not $publicLinkCreated) {
        $warnings += "SharePoint did not create the anonymous public link. MDCA public exposure detection could not be triggered."
        if ($createLinkError) { $warnings += "createLink error: $createLinkError" }

        try {
            Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/items/$folderId" | Out-Null
            $cleanupActions += "Deleted temporary dummy folder and file."
        }
        catch {
            $cleanupErrors += "Could not delete temporary dummy folder/file: $($_.Exception.Message)"
        }

        $cleanupRecord = [PSCustomObject]@{
            status = if ($cleanupErrors.Count -eq 0) { "Completed" } else { "Failed" }
            actions = @($cleanupActions)
            errors = @($cleanupErrors)
            state_file_active = $false
        }

        $mdcaEvidence = [PSCustomObject]@{
            automatic = $true
            api_configured = $false
            alert_detected = $false
            governance_remediation_observed = $false
            matched_alert = $null
            api_error = $null
            note = "MDCA was not checked because public exposure was not created."
        }

        $metrics = [PSCustomObject]@{
            public_link_created = $false
            mdca_alert_detected = $false
            governance_remediation_observed = $false
            cleanup_completed = ($cleanupRecord.status -eq "Completed")
            monitoring_window_minutes = $MonitoringWindowMinutes
        }

        $result = New-ZTVPResult `
            -State $state `
            -Status "PARTIAL_PUBLIC_LINK_COULD_NOT_BE_CREATED" `
            -Risk "LOW" `
            -Summary "SharePoint blocked or rejected creation of the anonymous public sharing link for the controlled dummy file." `
            -FinalClaim "The MDCA detection scenario could not be triggered because the primary SharePoint sharing control prevented the public exposure." `
            -EvidenceQuality "Partial - public exposure was not created." `
            -Warnings $warnings `
            -MdcaEvidence $mdcaEvidence `
            -CleanupRecord $cleanupRecord `
            -Metrics $metrics

        Write-ZTVPJson -Path $reportPath -Object $result

        Remove-Item $statePath -Force -ErrorAction SilentlyContinue

        Write-Host "APP-C-003 completed: PARTIAL_PUBLIC_LINK_COULD_NOT_BE_CREATED"
        exit 0
    }

    $apiConfigured = (
        -not [string]::IsNullOrWhiteSpace($MdcaApiBaseUrl) -and
        -not [string]::IsNullOrWhiteSpace($MdcaApiToken)
    )

    $mdcaApiError = $null
    $matchedAlert = $null
    $alertDetected = $false
    $governanceRemediationObserved = $false
    $permissionStillExists = $true

    if (-not $apiConfigured) {
        $warnings += "MDCA API URL or token was not provided. Automatic MDCA detection cannot be checked."
    }
    else {
        $endpoint = Get-ZTVPMdcaAlertsEndpoint -BaseUrl $MdcaApiBaseUrl
        $deadline = (Get-Date).AddMinutes($MonitoringWindowMinutes)

        while ((Get-Date) -lt $deadline) {
            try {
                $alertResponse = Invoke-ZTVPMdcaAlertQuery -Endpoint $endpoint -Token $MdcaApiToken
                $match = Find-ZTVPMatchingMdcaAlert `
                    -AlertResponse $alertResponse `
                    -StartEpochMs $startEpochMs `
                    -PolicyName $MdcaPolicyName `
                    -RunId $runId `
                    -FileName $fileName `
                    -FolderName $folderName

                if ($match.matched -eq $true) {
                    $matchedAlert = $match
                    $alertDetected = $true
                }
            }
            catch {
                $mdcaApiError = $_.Exception.Message
                break
            }

            $permissionStillExists = Test-ZTVPPermissionStillExists -DriveId $driveId -FileId $fileId -PermissionId $permissionId

            if (-not $permissionStillExists) {
                $governanceRemediationObserved = $true
                break
            }

            if ($alertDetected) {
                break
            }

            Start-Sleep -Seconds $PollIntervalSeconds
        }

        if (-not $alertDetected -and -not $governanceRemediationObserved -and [string]::IsNullOrWhiteSpace($mdcaApiError)) {
            $permissionStillExists = Test-ZTVPPermissionStillExists -DriveId $driveId -FileId $fileId -PermissionId $permissionId

            if (-not $permissionStillExists) {
                $governanceRemediationObserved = $true
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($permissionId)) {
        try {
            $exists = Test-ZTVPPermissionStillExists -DriveId $driveId -FileId $fileId -PermissionId $permissionId

            if ($exists) {
                Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/items/$fileId/permissions/$permissionId" | Out-Null
                $cleanupActions += "Deleted anonymous public sharing permission."
            }
            else {
                $cleanupActions += "Anonymous public sharing permission was already removed."
            }
        }
        catch {
            $msg = $_.Exception.Message

            if (Test-ZTVPNotFound -Message $msg) {
                $cleanupActions += "Anonymous public sharing permission was already removed."
            }
            else {
                $cleanupErrors += "Could not delete anonymous permission: $msg"
            }
        }
    }

    try {
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/items/$folderId" | Out-Null
        $cleanupActions += "Deleted temporary dummy folder and file."
    }
    catch {
        $msg = $_.Exception.Message

        if (Test-ZTVPNotFound -Message $msg) {
            $cleanupActions += "Temporary dummy folder/file was already removed."
        }
        else {
            $cleanupErrors += "Could not delete temporary dummy folder/file: $msg"
        }
    }

    $cleanupStatus = if ($cleanupErrors.Count -eq 0) { "Completed" } else { "Failed" }

    $cleanupRecord = [PSCustomObject]@{
        status = $cleanupStatus
        actions = @($cleanupActions)
        errors = @($cleanupErrors)
        state_file_active = ($cleanupStatus -ne "Completed")
    }

    $status = "FAIL_PUBLIC_FILE_EXPOSURE_NOT_DETECTED"
    $risk = "HIGH"
    $summary = "The controlled dummy file became publicly shared, but no matching MDCA alert or remediation evidence was found during the monitoring window."
    $finalClaim = "Public SharePoint file exposure was created and no MDCA detection/remediation evidence was confirmed automatically."
    $evidenceQuality = "Strong exposure evidence, no matching MDCA detection evidence."

    if (-not $apiConfigured -or -not [string]::IsNullOrWhiteSpace($mdcaApiError)) {
        $status = "PARTIAL_MDCA_EVIDENCE_NOT_ACCESSIBLE"
        $risk = "MEDIUM"
        $summary = "The controlled public exposure was created, but ZTVP could not automatically access MDCA alert evidence."
        $finalClaim = "ZTVP could not determine whether MDCA detected the public file exposure because API evidence was unavailable."
        $evidenceQuality = "Partial - MDCA API evidence unavailable."

        if ($mdcaApiError) {
            $warnings += "MDCA API error: $mdcaApiError"
        }
    }
    elseif ($governanceRemediationObserved) {
        $status = "PASS_PUBLIC_FILE_EXPOSURE_REMEDIATED"
        $risk = "LOW"
        $summary = "The controlled public file exposure was created and the public permission disappeared before ZTVP cleanup, indicating governance/remediation occurred."
        $finalClaim = "MDCA or another governance process remediated the controlled public file exposure during the validation window."
        $evidenceQuality = "Strong - public permission was removed before ZTVP cleanup."
    }
    elseif ($alertDetected) {
        $status = "PASS_PUBLIC_FILE_EXPOSURE_DETECTED"
        $risk = "LOW"
        $summary = "The controlled public file exposure was created and a matching MDCA alert was found automatically."
        $finalClaim = "MDCA detected the controlled public file exposure during the validation window."
        $evidenceQuality = "Strong - matching MDCA alert found via API."
    }

    if ($cleanupStatus -ne "Completed") {
        $warnings += "Cleanup did not fully complete. Run emergency cleanup and review the SharePoint test location."
    }

    $mdcaEvidence = [PSCustomObject]@{
        automatic = $true
        api_configured = $apiConfigured
        api_endpoint_used = if ($apiConfigured) { Get-ZTVPMdcaAlertsEndpoint -BaseUrl $MdcaApiBaseUrl } else { $null }
        policy_name = $MdcaPolicyName
        alert_detected = $alertDetected
        governance_remediation_observed = $governanceRemediationObserved
        permission_still_exists_before_cleanup = $permissionStillExists
        matched_alert = $matchedAlert
        api_error = $mdcaApiError
    }

    $metrics = [PSCustomObject]@{
        public_link_created = $true
        mdca_alert_detected = $alertDetected
        governance_remediation_observed = $governanceRemediationObserved
        cleanup_completed = ($cleanupStatus -eq "Completed")
        monitoring_window_minutes = $MonitoringWindowMinutes
        poll_interval_seconds = $PollIntervalSeconds
    }

    $result = New-ZTVPResult `
        -State $state `
        -Status $status `
        -Risk $risk `
        -Summary $summary `
        -FinalClaim $finalClaim `
        -EvidenceQuality $evidenceQuality `
        -Warnings $warnings `
        -MdcaEvidence $mdcaEvidence `
        -CleanupRecord $cleanupRecord `
        -Metrics $metrics

    Write-ZTVPJson -Path $reportPath -Object $result

    if ($cleanupStatus -eq "Completed") {
        $archivePath = Join-Path $historyDir "appc003-state-$runId.json"
        try { Copy-Item $statePath $archivePath -Force } catch {}
        Remove-Item $statePath -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host "APP-C-003 validation completed."
    Write-Host "Status: $status"
    Write-Host "Risk: $risk"
    Write-Host "Public link created: True"
    Write-Host "MDCA alert detected: $alertDetected"
    Write-Host "Governance remediation observed: $governanceRemediationObserved"
    Write-Host "Cleanup: $cleanupStatus"
    Write-Host "Report: $reportPath"
    Write-Host ""
}
catch {
    $err = $_.Exception.Message

    $fallbackState = [PSCustomObject]@{
        tenant_id = $ctx.TenantId
        connected_account = $ctx.Account
        site = $null
        drive = $null
        test_object = $null
        anonymous_public_link_attempt = [PSCustomObject]@{
            attempted = $true
            public_link_created = $false
            public_url_stored = $false
            error_message = $err
        }
    }

    $result = New-ZTVPResult `
        -State $fallbackState `
        -Status "PARTIAL_TEST_ERROR" `
        -Risk "MEDIUM" `
        -Summary "APP-C-003 could not complete the automatic MDCA public sharing validation." `
        -FinalClaim "The validation failed before a reliable MDCA detection decision could be made." `
        -EvidenceQuality "Partial - test error." `
        -Warnings @($err) `
        -MdcaEvidence ([PSCustomObject]@{ automatic = $true; api_configured = $false; alert_detected = $false; governance_remediation_observed = $false; matched_alert = $null; api_error = $err }) `
        -CleanupRecord ([PSCustomObject]@{ status = "Unknown"; actions = @(); errors = @($err); state_file_active = (Test-Path $statePath) }) `
        -Metrics ([PSCustomObject]@{ public_link_created = $false; mdca_alert_detected = $false; governance_remediation_observed = $false; cleanup_completed = $false; monitoring_window_minutes = $MonitoringWindowMinutes })

    Write-ZTVPJson -Path $reportPath -Object $result

    throw
}
