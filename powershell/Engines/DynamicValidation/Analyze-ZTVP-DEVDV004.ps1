param(
    [int]$PollSeconds = 30,
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

function Convert-ZTVPDateString {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
    catch { return [string]$Value }
}

function Get-ZTVPUserRegisteredDevices {
    param([string]$UserId)

    $uri = "https://graph.microsoft.com/v1.0/users/$UserId/registeredDevices"
    $res = Invoke-ZTVPSafeGraphGet -Uri $uri
    if ($res -and $res.value) { return @($res.value) }
    return @()
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
    $filter = [uri]::EscapeDataString("activityDateTime ge $startUtc")
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$filter&`$top=100"

    $res = Invoke-ZTVPSafeGraphGet -Uri $uri
    if ($res -and $res.value) { return @($res.value | Sort-Object activityDateTime -Descending) }
    return @()
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
    throw "No validation window found. Launch Sandbox first."
}

$windowStart = ([datetime]$windowStartUtc).ToUniversalTime()

$pollCount = 0
$registeredDevices = @()
$signIns = @()
$auditEvents = @()
$evidenceFound = $false

do {
    $pollCount++

    $registeredDevices = Get-ZTVPUserRegisteredDevices -UserId $decoyUserId
    $signIns = Get-ZTVPUserSignIns -Upn $decoyUpn -WindowStart $windowStart
    $auditEvents = Get-ZTVPAuditEvents -WindowStart $windowStart

    $newDevices = @()
    foreach ($d in $registeredDevices) {
        $created = $null
        if ($d.createdDateTime) {
            try { $created = ([datetime]$d.createdDateTime).ToUniversalTime() } catch {}
        }

        if ($created -and $created -ge $windowStart) {
            $newDevices += $d
        }
        elseif (-not $created) {
            # Some tenants do not return createdDateTime for registeredDevices. Keep it as evidence if linked to decoy.
            $newDevices += $d
        }
    }

    $registrationLikeAudits = @(
        $auditEvents | Where-Object {
            ([string]$_.activityDisplayName -match "device|register|join|owner|registered") -or
            ([string]$_.category -match "Device")
        }
    )

    $blockingSignIns = @(
        $signIns | Where-Object {
            ([int]$_.status.errorCode -ne 0) -or
            ([string]$_.conditionalAccessStatus -match "failure")
        }
    )

    if ($newDevices.Count -gt 0 -or $registrationLikeAudits.Count -gt 0 -or $blockingSignIns.Count -gt 0) {
        $evidenceFound = $true
        break
    }

    Write-Host "Poll #$pollCount : no device registration evidence yet after $windowStartUtc. Waiting $PollSeconds seconds..."
    Start-Sleep -Seconds $PollSeconds
}
while ($WaitUntilEvidence)

if (-not $evidenceFound) {
    throw "No device registration/join evidence found yet after $windowStartUtc. Rerun analyze or use WaitUntilEvidence."
}

$status = "PARTIAL_EVIDENCE_FOUND_UNCLASSIFIED"
$risk = "MEDIUM"
$summary = "ZTVP found evidence after the validation window, but could not fully classify the device registration result."
$finalClaim = "The result is inconclusive. Review device, audit, and sign-in evidence."
$evidenceQuality = "Partial"

$selectedDevice = $null
if ($newDevices.Count -gt 0) {
    $selectedDevice = $newDevices | Select-Object -First 1
    $status = "FAIL_NORMAL_USER_REGISTERED_DEVICE"
    $risk = "HIGH"
    $summary = "A new or linked device object was found for the decoy user after the validation window."
    $finalClaim = "The normal decoy user appears able to introduce/register a device identity into Entra ID."
    $evidenceQuality = "Strong - device object found in decoy user's registeredDevices."
}
elseif ($blockingSignIns.Count -gt 0 -or $registrationLikeAudits.Count -gt 0) {
    $status = "PASS_TENANT_BLOCKED_NORMAL_USER_DEVICE_REGISTRATION"
    $risk = "LOW"
    $summary = "The tenant did not allow the normal decoy user to complete device registration. No device object was created or linked to the decoy user."
    $finalClaim = "The normal decoy user did not successfully register a device. The tenant prevented or interrupted completion of the registration/enrollment flow."
    $evidenceQuality = "Strong enough for outcome - no decoy-linked device object was created, and post-window audit evidence exists."
}

$result = [PSCustomObject]@{
    scenario_id = "DEV-DV-004"
    display_id = "DEV-DV-004"
    scenario_name = "Sandbox Device Registration Abuse Probe"
    pillar = "Devices"
    scope = "Identity Device Trust"
    mode = "Windows Sandbox Device Registration Validation"
    generated_at = (Get-Date).ToString("s")

    tenant_id = $state.tenant_id
    operator_account = $ctx.Account

    status = $status
    risk = $risk
    executive_summary = $summary
    final_claim = $finalClaim
    evidence_quality = $evidenceQuality

    validation_window_start_utc = $windowStartUtc
    poll_count = $pollCount

    decoy_user = [PSCustomObject]@{
        id = $decoyUserId
        user_principal_name = $decoyUpn
        display_name = $state.decoy_user.display_name
        password_stored_in_report = $false
    }

    detected_device = $(if ($selectedDevice) {
        [PSCustomObject]@{
            id = $selectedDevice.id
            display_name = $selectedDevice.displayName
            device_id = $selectedDevice.deviceId
            operating_system = $selectedDevice.operatingSystem
            operating_system_version = $selectedDevice.operatingSystemVersion
            trust_type = $selectedDevice.trustType
            is_managed = $selectedDevice.isManaged
            is_compliant = $selectedDevice.isCompliant
            account_enabled = $selectedDevice.accountEnabled
        }
    } else { $null })

    evidence = [PSCustomObject]@{
        tenant_registration_decision = [PSCustomObject]@{
            decision = $(if ($newDevices.Count -gt 0) { "Allowed" } else { "Not allowed / not completed" })
            tested_user = $decoyUpn
            graph_check = "GET /users/{decoyUserId}/registeredDevices"
            devices_linked_to_decoy = $newDevices.Count
            meaning = $(if ($newDevices.Count -gt 0) { "The decoy user introduced a device identity." } else { "The decoy user did not introduce a device identity. No device is linked to this user." })
        }
        registered_device_count_after_window = $newDevices.Count
        sign_in_count_after_window = $signIns.Count
        blocking_sign_in_count_after_window = $blockingSignIns.Count
        registration_like_audit_count_after_window = $registrationLikeAudits.Count
        registered_devices = @($newDevices | ForEach-Object {
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
        audit_events = @($registrationLikeAudits | Select-Object -First 10 | ForEach-Object {
            [PSCustomObject]@{
                activity_date_time = Convert-ZTVPDateString -Value $_.activityDateTime
                activity = $_.activityDisplayName
                category = $_.category
                result = $_.result
            }
        })
    }

    metrics = [PSCustomObject]@{
        decoy_user_created = $true
        sandbox_launched = $state.sandbox.launched
        evidence_found = $evidenceFound
        device_registered_or_linked = ($newDevices.Count -gt 0)
        cleanup_required = $true
    }

    recommendations = $(if ($status -eq "PASS_TENANT_BLOCKED_NORMAL_USER_DEVICE_REGISTRATION") {
        @(
            "Keep the current registration/enrollment controls because the normal decoy user did not successfully register a device.",
            "Use the result as evidence that the tenant did not allow this normal user to complete device registration from Windows Sandbox.",
            "Review the related Device Registration Service sign-in and Intune/MDM enrollment evidence to identify the exact blocker.",
            "Verify that normal users are not broadly allowed to register or join devices unless this is a business requirement.",
            "Continue monitoring for unexpected device registration, registered owner changes, or device creation events.",
            "Run cleanup to remove the DEV-DV-004 decoy user."
        )
    }
    elseif ($status -eq "FAIL_NORMAL_USER_REGISTERED_DEVICE") {
        @(
            "Restrict normal users from registering or joining unmanaged devices unless business-approved.",
            "Review Entra device settings: Users may register devices and Users may join devices.",
            "Use Conditional Access user action 'Register or join devices' with MFA.",
            "Review whether the decoy user was included in an allowed registration or join group.",
            "Reduce maximum devices per user if the default value is too high.",
            "Delete the detected test device if it was created during this validation, then run cleanup."
        )
    }
    else {
        @(
            "Review the device, audit, and sign-in evidence because the result could not be fully classified.",
            "Rerun the validation with a fresh window if the registration attempt was not completed inside Sandbox.",
            "Confirm that the decoy user was used, not an admin or personal account.",
            "Review Entra device settings and Conditional Access policies for register/join device actions.",
            "Run cleanup to remove the DEV-DV-004 decoy user."
        )
    })

    limitations = @(
        "This scenario validates the Windows Sandbox registration path, not every possible platform.",
        "If Windows/Sandbox UI blocks before Entra logs are created, evidence may be partial.",
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
Write-Host "Registered/new linked devices: $($newDevices.Count)"
Write-Host "Blocking sign-ins: $($blockingSignIns.Count)"
Write-Host "Registration-like audits: $($registrationLikeAudits.Count)"
Write-Host "Report: $reportPath"
Write-Host ""

