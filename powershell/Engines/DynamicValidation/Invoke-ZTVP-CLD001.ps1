param(
    [ValidateSet("Root site","Custom site ID")]
    [string]$SiteMode = "Root site",

    [string]$SiteId = "",

    [ValidateSet("view","edit")]
    [string]$RequestedLinkType = "view"
)

$ErrorActionPreference = "Stop"

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

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$startedUtc = (Get-Date).ToUniversalTime().ToString("s") + "Z"
$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "CLD-C-001"
$historyDir = Join-Path $scenarioDir "history"
$htmlDir = Join-Path $reportRoot "Html"

New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null
New-Item -ItemType Directory -Path $historyDir -Force | Out-Null
New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null

$statePath = Join-Path $scenarioDir "cld001-state.json"
$reportPath = Join-Path $reportRoot "CLD-C-001-result.json"

$folderName = "ZTVP-CLD001-AnonSharing-Test-$runId"
$fileName = "ztvp-cld001-anonymous-sharing-test.txt"
$fileContent = "ZTVP controlled dummy file for anonymous sharing validation. Run ID: $runId. No business data."

$site = $null
$drive = $null
$folder = $null
$file = $null
$permission = $null

$siteResolved = $false
$fileCreated = $false
$linkCreated = $false
$linkDenied = $false
$linkErrorMessage = $null
$linkErrorCategory = $null
$operationError = $null
$cleanupActions = @()
$cleanupErrors = @()

Write-Host ""
Write-Host "========================================="
Write-Host "ZTVP APP-DV-008 - SharePoint Anonymous Sharing Link Exposure Validation"
Write-Host "========================================="
Write-Host ""
Write-Host "Site mode: $SiteMode"
Write-Host "Requested link type: $RequestedLinkType"
Write-Host ""

try {
    if ($SiteMode -eq "Custom site ID") {
        if ([string]::IsNullOrWhiteSpace($SiteId)) {
            throw "Custom site ID mode was selected but no SiteId was supplied."
        }

        $encodedSiteId = [System.Uri]::EscapeDataString($SiteId)
        $site = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$encodedSiteId?`$select=id,displayName,webUrl"
    }
    else {
        $site = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/root?`$select=id,displayName,webUrl"
    }

    $siteResolved = $true
    $resolvedSiteId = [string](Get-ZTVPValue -Object $site -Name "id")

    $drive = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$resolvedSiteId/drive"
    $driveId = [string](Get-ZTVPValue -Object $drive -Name "id")

    $folderBody = @{
        name = $folderName
        folder = @{}
        "@microsoft.graph.conflictBehavior" = "fail"
    } | ConvertTo-Json -Depth 10

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

    $fileCreated = $true
    $fileId = [string](Get-ZTVPValue -Object $file -Name "id")

    $state = [PSCustomObject]@{
        scenario_id = "APP-DV-008"
        display_id = "APP-DV-008"
        run_id = $runId
        tenant_id = $ctx.TenantId
        connected_account = $ctx.Account
        created_at = (Get-Date).ToString("s")
        site = [PSCustomObject]@{
            id = $resolvedSiteId
            displayName = Get-ZTVPValue -Object $site -Name "displayName"
            webUrl = Get-ZTVPValue -Object $site -Name "webUrl"
        }
        drive = [PSCustomObject]@{
            id = $driveId
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
        anonymous_permission = $null
        cleanup = [PSCustomObject]@{
            status = "Pending"
        }
    }

    Write-ZTVPJson -Path $statePath -Object $state

    $linkBody = @{
        type = $RequestedLinkType
        scope = "anonymous"
        retainInheritedPermissions = $false
    } | ConvertTo-Json -Depth 10

    try {
        $permission = Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/items/$fileId/createLink" `
            -Body $linkBody `
            -ContentType "application/json"

        $linkCreated = $true

        $permissionId = [string](Get-ZTVPValue -Object $permission -Name "id")
        $link = Get-ZTVPValue -Object $permission -Name "link"
        $webUrl = [string](Get-ZTVPValue -Object $link -Name "webUrl")

        $state.anonymous_permission = [PSCustomObject]@{
            permission_id = $permissionId
            link_created = $true
            link_scope = "anonymous"
            link_type = $RequestedLinkType
            web_url_present = -not [string]::IsNullOrWhiteSpace($webUrl)
            web_url_stored = $false
            web_url_note = "ZTVP does not store anonymous sharing URLs in the report."
        }

        Write-ZTVPJson -Path $statePath -Object $state
    }
    catch {
        $linkErrorMessage = $_.Exception.Message

        if ($linkErrorMessage -match "Forbidden|AccessDenied|access denied|denied|anonymous|sharing|not allowed|disabled|policy|external|link type|organization|tenant|Anyone") {
            $linkDenied = $true
            $linkErrorCategory = "DeniedBySharingPolicyOrTenantConfiguration"
        }
        else {
            $linkErrorCategory = "CreateLinkFailedUnknownReason"
        }
    }
}
catch {
    $operationError = $_.Exception.Message
}
finally {
    try {
        if ($null -ne $permission -and $null -ne $file -and $null -ne $drive) {
            $permissionIdCleanup = [string](Get-ZTVPValue -Object $permission -Name "id")
            $fileIdCleanup = [string](Get-ZTVPValue -Object $file -Name "id")
            $driveIdCleanup = [string](Get-ZTVPValue -Object $drive -Name "id")

            if (-not [string]::IsNullOrWhiteSpace($permissionIdCleanup)) {
                try {
                    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/drives/$driveIdCleanup/items/$fileIdCleanup/permissions/$permissionIdCleanup" | Out-Null
                    $cleanupActions += "Deleted anonymous permission."
                }
                catch {
                    $cleanupErrors += "Permission cleanup failed: $($_.Exception.Message)"
                }
            }
        }

        if ($null -ne $folder -and $null -ne $drive) {
            $folderIdCleanup = [string](Get-ZTVPValue -Object $folder -Name "id")
            $driveIdCleanup = [string](Get-ZTVPValue -Object $drive -Name "id")

            if (-not [string]::IsNullOrWhiteSpace($folderIdCleanup)) {
                try {
                    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/drives/$driveIdCleanup/items/$folderIdCleanup" | Out-Null
                    $cleanupActions += "Deleted temporary test folder and file."
                }
                catch {
                    $msg = $_.Exception.Message

                    if (Test-ZTVPNotFound -Message $msg) {
                        $cleanupActions += "Temporary test folder was already deleted."
                    }
                    else {
                        $cleanupErrors += "Folder/file cleanup failed: $msg"
                    }
                }
            }
        }
    }
    catch {
        $cleanupErrors += "Cleanup unexpected error: $($_.Exception.Message)"
    }
}

$cleanupStatus = if ($cleanupErrors.Count -eq 0) { "Completed" } else { "Failed" }

if ($cleanupStatus -eq "Completed") {
    Remove-Item $statePath -Force -ErrorAction SilentlyContinue
}

$status = "PARTIAL_TEST_ERROR"
$risk = "MEDIUM"
$summary = "ZTVP could not complete the anonymous sharing validation."
$finalClaim = "The validation could not determine whether anonymous SharePoint sharing links are allowed."
$evidenceQuality = "Partial"
$warnings = @()

if ($linkCreated) {
    $status = "FAIL_ANONYMOUS_SHARING_LINK_ALLOWED"
    $risk = "HIGH"
    $summary = "FAIL - Anonymous sharing link allowed."
    $finalClaim = "SharePoint allowed creation of an anonymous/public link for the controlled dummy file. This means public sharing is currently allowed and could expose business content if applied to real files."
    $evidenceQuality = "Strong - Microsoft Graph createLink returned an anonymous permission."
}
elseif ($linkDenied) {
    $status = "PASS_ANONYMOUS_SHARING_LINK_BLOCKED"
    $risk = "LOW"
    $summary = "PASS - Anonymous sharing link blocked."
    $finalClaim = "SharePoint denied creation of an anonymous/public sharing link for the controlled dummy file. This means the tenant or site sharing configuration prevented public link exposure."
    $evidenceQuality = "Strong - Microsoft Graph createLink did not issue an anonymous link and returned a sharing-policy-style denial."
}
elseif ($fileCreated -and -not $linkCreated) {
    $status = "PARTIAL_ANONYMOUS_LINK_NOT_CREATED"
    $risk = "MEDIUM"
    $summary = "PARTIAL - Anonymous link was not created, but the denial reason is unclear."
    $finalClaim = "No anonymous link was created. Review the createLink error to determine whether this was policy enforcement or an API/permission limitation."
    $evidenceQuality = "Partial - createLink failed with an unclassified error."
}
elseif ($operationError -and -not $fileCreated) {
    $status = "ERROR_TEST_SETUP_FAILED"
    $risk = "UNKNOWN"
    $summary = "ERROR - SharePoint anonymous sharing validation could not reach createLink."
    $finalClaim = "ZTVP could not complete the setup needed to test anonymous createLink. Review authentication, site, drive, and file creation evidence."
    $evidenceQuality = "Error - the scenario failed before the anonymous link creation control point."
}

if ($operationError) {
    $warnings += "Operation error: $operationError"
}

if ($linkErrorMessage) {
    $warnings += "Anonymous link attempt message: $linkErrorMessage"
}

if ($cleanupStatus -ne "Completed") {
    $warnings += "Automatic cleanup did not fully complete. Use the emergency cleanup action."
}

$result = [PSCustomObject]@{
    scenario_id = "APP-DV-008"
    display_id = "APP-DV-008"
    scenario_name = "SharePoint Anonymous Sharing Link Exposure Validation"
    pillar = "Applications"
    scope = "Cloud"
    started_utc = $startedUtc
    completed_utc = (Get-Date).ToUniversalTime().ToString("s") + "Z"
    generated_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    connected_account = $ctx.Account

    control_tested = "SharePoint and OneDrive anonymous/public sharing links should not be available unless explicitly approved."
    expected_result = "Anonymous sharing link creation for the controlled dummy file should be denied."
    failure_condition = "Microsoft Graph createLink returns an anonymous sharing permission for the dummy file."
    test_method = "Create a temporary dummy SharePoint file, attempt anonymous createLink, record the Microsoft Graph outcome, then delete the test object."

    status = $status
    risk = $risk
    executive_summary = $summary
    final_claim = $finalClaim
    evidence_quality = $evidenceQuality
    warnings = @($warnings)

    site = if ($site) {
        [PSCustomObject]@{
            id = Get-ZTVPValue -Object $site -Name "id"
            displayName = Get-ZTVPValue -Object $site -Name "displayName"
            webUrl = Get-ZTVPValue -Object $site -Name "webUrl"
        }
    } else { $null }

    drive = if ($drive) {
        [PSCustomObject]@{
            id = Get-ZTVPValue -Object $drive -Name "id"
            name = Get-ZTVPValue -Object $drive -Name "name"
            webUrl = Get-ZTVPValue -Object $drive -Name "webUrl"
        }
    } else { $null }

    test_object = [PSCustomObject]@{
        run_id = $runId
        folder_name = $folderName
        file_name = $fileName
        file_created = $fileCreated
        contains_business_data = $false
    }

    anonymous_link_attempt = [PSCustomObject]@{
        requested_scope = "anonymous"
        requested_type = $RequestedLinkType
        link_created = $linkCreated
        link_denied = $linkDenied
        error_category = $linkErrorCategory
        error_message = $linkErrorMessage
        anonymous_url_stored = $false
        anonymous_url_note = "ZTVP does not store anonymous sharing URLs in the report."
    }

    cleanup = [PSCustomObject]@{
        status = $cleanupStatus
        actions = @($cleanupActions)
        errors = @($cleanupErrors)
        active_state_file = (Test-Path $statePath)
    }

    metrics = [PSCustomObject]@{
        site_resolved = $siteResolved
        file_created = $fileCreated
        anonymous_link_created = $linkCreated
        anonymous_link_denied = $linkDenied
        cleanup_completed = ($cleanupStatus -eq "Completed")
        warning_count = $warnings.Count
    }

    recommendations = if ($status -eq "PASS_ANONYMOUS_SHARING_LINK_BLOCKED") {
        @(
            "Keep anonymous/Anyone sharing disabled unless there is a documented business exception.",
            "Continue using organization-only or specific-people links for normal collaboration.",
            "Periodically rerun APP-DV-008 after sharing setting changes.",
            "Monitor SharePoint sharing audit events."
        )
    }
    elseif ($status -eq "FAIL_ANONYMOUS_SHARING_LINK_ALLOWED") {
        @(
            "Go to SharePoint admin center -> Policies -> Sharing.",
            "Disable Anyone/anonymous links at tenant level.",
            "Review SharePoint admin center -> Sites -> Active sites -> tested site -> Sharing.",
            "Set the site to New and existing guests, Existing guests only, or Only people in your organization.",
            "Rerun APP-DV-008 after settings propagate.",
            "Monitor SharingLinkCreated / anonymous link activity."
        )
    }
    else {
        @(
            "Review the createLink error details.",
            "Verify Graph and SharePoint permissions.",
            "Confirm tenant and site sharing settings manually.",
            "Rerun after a few minutes."
        )
    }

    limitations = @(
        "This validation uses a controlled dummy file and does not test every SharePoint site.",
        "Root site mode tests the tenant root SharePoint site's default document library.",
        "A createLink failure can be caused by tenant sharing configuration, site sharing configuration, Graph permissions, or API restrictions."
    )
}

Write-ZTVPJson -Path $reportPath -Object $result

Write-Host ""
Write-Host "========================================="
Write-Host "APP-DV-008 COMPLETED"
Write-Host "========================================="
Write-Host ""
Write-Host "Status: $status"
Write-Host "Risk: $risk"
Write-Host "Anonymous link created: $linkCreated"
Write-Host "Anonymous link denied: $linkDenied"
Write-Host "Cleanup status: $cleanupStatus"
Write-Host "Report saved to: $reportPath"
Write-Host ""
