param(
    [string]$TestFolder = "C:\Users\Public\ZTVP-DEV-DV-008",
    [string]$TestDeviceName = "",
    [string]$TenantId = "",
    [string]$ClientId = "",
    [ValidateSet("Tenant + Local Evidence", "Local Evidence Only")]
    [string]$CloudEvidenceMode = "Tenant + Local Evidence",
    [switch]$GenerateVmScript
)

$ErrorActionPreference = "Stop"

function Write-ZTVPJson {
    param([string]$Path, [object]$Object)
    $Object | ConvertTo-Json -Depth 100 | Set-Content -Path $Path -Encoding UTF8
}

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "DEV-DV-008"
$htmlDir = Join-Path $reportRoot "Html"

New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null
New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null

$statePath = Join-Path $scenarioDir "devdv008-state.json"
$preparePath = Join-Path $scenarioDir "devdv008-prepare-result.json"
$templatePath = Join-Path $scenarioDir "devdv008-local-evidence-template.ps1"
$preflightPath = Join-Path (Get-Location) "powershell\Reports\Preflight-discovery.json"

$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$windowStartUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$defaultClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
$tenantDisplayName = ""
$tenantDiscoverySource = ""
$clientIdSource = ""

if ([string]::IsNullOrWhiteSpace($ClientId)) {
    $ClientId = $defaultClientId
    $clientIdSource = "Microsoft Graph PowerShell public client / interactive public client"
}
else {
    $clientIdSource = "DEV-DV-008 parameter"
}

if (Test-Path -LiteralPath $preflightPath) {
    try {
        $preflight = Get-Content -Raw -LiteralPath $preflightPath | ConvertFrom-Json
        if ([string]::IsNullOrWhiteSpace($TenantId) -and $preflight.tenant_id) {
            $TenantId = [string]$preflight.tenant_id
            $tenantDiscoverySource = "powershell\Reports\Preflight-discovery.json"
        }
        if ($preflight.organization -and $preflight.organization.displayName) {
            $tenantDisplayName = [string]$preflight.organization.displayName
        }
    }
    catch {
        Write-Warning "Could not read tenant preflight discovery: $($_.Exception.Message)"
    }
}

if ([string]::IsNullOrWhiteSpace($tenantDiscoverySource) -and -not [string]::IsNullOrWhiteSpace($TenantId)) {
    $tenantDiscoverySource = "DEV-DV-008 parameter"
}

if ($GenerateVmScript) {
    if (-not (Test-Path -LiteralPath $statePath)) {
        throw "No DEV-DV-008 state file found. Arm the validation window before generating the VM script."
    }
    $existingState = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    if ($existingState.scenario_id -ne "DEV-DV-008") {
        throw "The current state file is not for DEV-DV-008."
    }

    $runId = [string]$existingState.run_id
    $windowStartUtc = [string]$existingState.validation_window_start_utc
    $TenantId = [string]$existingState.tenant_id
    $tenantDisplayName = [string]$existingState.tenant_display_name
    $tenantDiscoverySource = [string]$existingState.tenant_discovery_source
    $ClientId = [string]$existingState.client_id
    $clientIdSource = [string]$existingState.client_id_source
    $TestDeviceName = [string]$existingState.test_device_name
    $CloudEvidenceMode = [string]$existingState.cloud_evidence_mode
    $TestFolder = [string]$existingState.test_folder
}

$state = [PSCustomObject]@{
    scenario_id = "DEV-DV-008"
    display_id = "DEV-DV-008"
    scenario_name = "Hybrid Tamper Protection Validation"
    pillar = "Devices"
    scope = "Cloud"
    mode = "Hybrid endpoint + tenant validation"
    run_id = $runId
    prepared_at = (Get-Date).ToString("s")
    validation_window_start_utc = $windowStartUtc
    tenant_id = $TenantId
    tenant_display_name = $tenantDisplayName
    tenant_discovery_source = $tenantDiscoverySource
    client_id = $ClientId
    client_id_source = $clientIdSource
    test_device_name = $TestDeviceName
    cloud_evidence_mode = $CloudEvidenceMode
    test_folder = $TestFolder
    vm_script_generated = [bool]$GenerateVmScript
    local_evidence_imported = $false
    local_evidence_path = $null
    local_evidence_imported_utc = $null
    local_evidence_timestamp_utc = $null
    tenant_analysis_started_utc = $null
    tenant_analysis_completed_utc = $null
    analysis_completed = $false
    current_run_report_path = $null
    current_run_status = if ($GenerateVmScript) { "VM_SCRIPT_GENERATED" } else { "ARMED_NOT_EXECUTED" }
}

Write-ZTVPJson -Path $statePath -Object $state

if (-not $GenerateVmScript) {
    if (Test-Path -LiteralPath $templatePath) {
        Remove-Item -LiteralPath $templatePath -Force
    }

    $prepare = [PSCustomObject]@{
        scenario_id = "DEV-DV-008"
        status = "ARMED"
        validation_window_start_utc = $windowStartUtc
        tenant_id = $TenantId
        tenant_display_name = $tenantDisplayName
        tenant_discovery_source = $tenantDiscoverySource
        client_id = $ClientId
        client_id_source = $clientIdSource
        test_device_name = $TestDeviceName
        cloud_evidence_mode = $CloudEvidenceMode
        test_folder = $TestFolder
        state_path = $statePath
        vm_script_template_path = $null
    }

    Write-ZTVPJson -Path $preparePath -Object $prepare

    Write-Host ""
    Write-Host "DEV-DV-008 validation window started."
    Write-Host "Validation window UTC: $windowStartUtc"
    Write-Host "Tenant ID: $TenantId"
    Write-Host "Client ID: $ClientId"
    Write-Host "Test device name: $TestDeviceName"
    Write-Host "Cloud evidence mode: $CloudEvidenceMode"
    Write-Host "State: $statePath"
    Write-Host "VM script template: not generated yet. Click Step 2 to generate it for this run."
    Write-Host ""
    return
}

$escapedFolder = $TestFolder.Replace("'", "''")
$escapedRunId = $runId.Replace("'", "''")
$escapedWindowStartUtc = $windowStartUtc.Replace("'", "''")

$template = @"
`$ErrorActionPreference = "Continue"

`$folder = '$escapedFolder'
`$ztvpRunId = '$escapedRunId'
`$ztvpValidationWindowStartUtc = '$escapedWindowStartUtc'
`$evidencePath = Join-Path `$folder 'devdv008-local-evidence.json'
`$errors = @()
`$attempts = @()
`$restoreAttempts = @()

function Get-ZTVPDefenderStatusSlim {
    try {
        `$status = Get-MpComputerStatus
        return [PSCustomObject]@{
            IsTamperProtected = `$status.IsTamperProtected
            AMRunningMode = `$status.AMRunningMode
            AMServiceEnabled = `$status.AMServiceEnabled
            AntivirusEnabled = `$status.AntivirusEnabled
            RealTimeProtectionEnabled = `$status.RealTimeProtectionEnabled
            BehaviorMonitorEnabled = `$status.BehaviorMonitorEnabled
            IoavProtectionEnabled = `$status.IoavProtectionEnabled
            OnAccessProtectionEnabled = `$status.OnAccessProtectionEnabled
            NISEnabled = `$status.NISEnabled
        }
    }
    catch {
        `$script:errors += "Get-MpComputerStatus failed: `$(`$_.Exception.Message)"
        return `$null
    }
}

function Get-ZTVPDefenderPreferenceSlim {
    try {
        `$pref = Get-MpPreference
        return [PSCustomObject]@{
            DisableRealtimeMonitoring = `$pref.DisableRealtimeMonitoring
            DisableBehaviorMonitoring = `$pref.DisableBehaviorMonitoring
            DisableIOAVProtection = `$pref.DisableIOAVProtection
            DisableBlockAtFirstSeen = `$pref.DisableBlockAtFirstSeen
            MAPSReporting = `$pref.MAPSReporting
            SubmitSamplesConsent = `$pref.SubmitSamplesConsent
        }
    }
    catch {
        `$script:errors += "Get-MpPreference failed: `$(`$_.Exception.Message)"
        return `$null
    }
}

function Invoke-ZTVPTamperAttempt {
    param(
        [string]`$Name,
        [string]`$CommandText,
        [scriptblock]`$Action
    )

    `$result = [PSCustomObject]@{
        action_name = `$Name
        command = `$CommandText
        attempted = `$true
        succeeded = `$false
        error = `$null
    }

    try {
        & `$Action
        `$result.succeeded = `$true
    }
    catch {
        `$result.error = `$_.Exception.Message
        `$script:errors += "`$Name failed: `$(`$_.Exception.Message)"
    }

    return `$result
}

try {
    New-Item -ItemType Directory -Path `$folder -Force | Out-Null
}
catch {
    `$errors += "Create folder failed: `$(`$_.Exception.Message)"
}

`$beforeStatus = Get-ZTVPDefenderStatusSlim
`$beforePreference = Get-ZTVPDefenderPreferenceSlim

`$attempts += Invoke-ZTVPTamperAttempt -Name "DisableRealtimeMonitoring" -CommandText "Set-MpPreference -DisableRealtimeMonitoring `$true" -Action { Set-MpPreference -DisableRealtimeMonitoring `$true -ErrorAction Stop }
`$attempts += Invoke-ZTVPTamperAttempt -Name "DisableBehaviorMonitoring" -CommandText "Set-MpPreference -DisableBehaviorMonitoring `$true" -Action { Set-MpPreference -DisableBehaviorMonitoring `$true -ErrorAction Stop }
`$attempts += Invoke-ZTVPTamperAttempt -Name "DisableIOAVProtection" -CommandText "Set-MpPreference -DisableIOAVProtection `$true" -Action { Set-MpPreference -DisableIOAVProtection `$true -ErrorAction Stop }
`$attempts += Invoke-ZTVPTamperAttempt -Name "DisableBlockAtFirstSeen" -CommandText "Set-MpPreference -DisableBlockAtFirstSeen `$true" -Action { Set-MpPreference -DisableBlockAtFirstSeen `$true -ErrorAction Stop }

Start-Sleep -Seconds 10

`$afterStatus = Get-ZTVPDefenderStatusSlim
`$afterPreference = Get-ZTVPDefenderPreferenceSlim

`$settingsWeakened = (
    (`$afterStatus -and `$afterStatus.RealTimeProtectionEnabled -eq `$false) -or
    (`$afterStatus -and `$afterStatus.BehaviorMonitorEnabled -eq `$false) -or
    (`$afterStatus -and `$afterStatus.IoavProtectionEnabled -eq `$false) -or
    (`$afterPreference -and `$afterPreference.DisableRealtimeMonitoring -eq `$true) -or
    (`$afterPreference -and `$afterPreference.DisableBehaviorMonitoring -eq `$true) -or
    (`$afterPreference -and `$afterPreference.DisableIOAVProtection -eq `$true) -or
    (`$afterPreference -and `$afterPreference.DisableBlockAtFirstSeen -eq `$true)
)

`$restoreAttempted = `$false
`$restoreSucceeded = `$false
if (`$settingsWeakened) {
    `$restoreAttempted = `$true
    `$restoreAttempts += Invoke-ZTVPTamperAttempt -Name "RestoreRealtimeMonitoring" -CommandText "Set-MpPreference -DisableRealtimeMonitoring `$false" -Action { Set-MpPreference -DisableRealtimeMonitoring `$false -ErrorAction Stop }
    `$restoreAttempts += Invoke-ZTVPTamperAttempt -Name "RestoreBehaviorMonitoring" -CommandText "Set-MpPreference -DisableBehaviorMonitoring `$false" -Action { Set-MpPreference -DisableBehaviorMonitoring `$false -ErrorAction Stop }
    `$restoreAttempts += Invoke-ZTVPTamperAttempt -Name "RestoreIOAVProtection" -CommandText "Set-MpPreference -DisableIOAVProtection `$false" -Action { Set-MpPreference -DisableIOAVProtection `$false -ErrorAction Stop }
    `$restoreAttempts += Invoke-ZTVPTamperAttempt -Name "RestoreBlockAtFirstSeen" -CommandText "Set-MpPreference -DisableBlockAtFirstSeen `$false" -Action { Set-MpPreference -DisableBlockAtFirstSeen `$false -ErrorAction Stop }
    Start-Sleep -Seconds 5
    `$restoredStatus = Get-ZTVPDefenderStatusSlim
    `$restoredPreference = Get-ZTVPDefenderPreferenceSlim
    `$restoreSucceeded = (
        (`$restoredStatus -and `$restoredStatus.RealTimeProtectionEnabled -ne `$false) -and
        (`$restoredPreference -and `$restoredPreference.DisableRealtimeMonitoring -ne `$true) -and
        (`$restoredPreference -and `$restoredPreference.DisableBehaviorMonitoring -ne `$true) -and
        (`$restoredPreference -and `$restoredPreference.DisableIOAVProtection -ne `$true) -and
        (`$restoredPreference -and `$restoredPreference.DisableBlockAtFirstSeen -ne `$true)
    )
}

`$localSummary = [PSCustomObject]@{
    tamper_protection_enabled_before = if (`$beforeStatus) { [bool]`$beforeStatus.IsTamperProtected } else { `$false }
    tamper_protection_enabled_after = if (`$afterStatus) { [bool]`$afterStatus.IsTamperProtected } else { `$false }
    realtime_remained_enabled = if (`$afterStatus) { `$afterStatus.RealTimeProtectionEnabled -ne `$false } else { `$false }
    behavior_monitoring_remained_enabled = if (`$afterStatus) { `$afterStatus.BehaviorMonitorEnabled -ne `$false } else { `$false }
    ioav_remained_enabled = if (`$afterStatus) { `$afterStatus.IoavProtectionEnabled -ne `$false } else { `$false }
    block_at_first_seen_remained_enabled_or_protected = if (`$afterPreference) { `$afterPreference.DisableBlockAtFirstSeen -ne `$true } else { `$false }
    defender_settings_remained_protected = (-not `$settingsWeakened)
    tamper_attempt_blocked_or_ignored = (-not `$settingsWeakened)
    settings_weakened = [bool]`$settingsWeakened
    restore_attempted = [bool]`$restoreAttempted
    restore_succeeded = [bool]`$restoreSucceeded
}

`$evidence = [PSCustomObject]@{
    scenario_id = "DEV-DV-008"
    run_id = `$ztvpRunId
    validation_window_start_utc = `$ztvpValidationWindowStartUtc
    validation_method = "Manual VM Script"
    computer_name = `$env:COMPUTERNAME
    current_user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    evidence_path = `$evidencePath
    before_status = `$beforeStatus
    before_preference = `$beforePreference
    tamper_attempts = @(`$attempts)
    after_status = `$afterStatus
    after_preference = `$afterPreference
    restore_attempts = @(`$restoreAttempts)
    local_summary = `$localSummary
    errors = @(`$errors)
}

`$json = `$evidence | ConvertTo-Json -Depth 20
`$json | Set-Content -Path `$evidencePath -Encoding UTF8
Write-Host ""
Write-Host "DEV-DV-008 local VM evidence JSON:"
Write-Host ""
Write-Output `$json
Write-Host ""
Write-Host "Saved to: `$evidencePath"
"@

Set-Content -Path $templatePath -Value $template -Encoding UTF8

$prepare = [PSCustomObject]@{
    scenario_id = "DEV-DV-008"
    status = "READY"
    validation_window_start_utc = $windowStartUtc
    tenant_id = $TenantId
    tenant_display_name = $tenantDisplayName
    tenant_discovery_source = $tenantDiscoverySource
    client_id = $ClientId
    client_id_source = $clientIdSource
    test_device_name = $TestDeviceName
    cloud_evidence_mode = $CloudEvidenceMode
    test_folder = $TestFolder
    state_path = $statePath
    vm_script_template_path = $templatePath
}

Write-ZTVPJson -Path $preparePath -Object $prepare

Write-Host ""
Write-Host "DEV-DV-008 validation window started."
Write-Host "Validation window UTC: $windowStartUtc"
Write-Host "Tenant ID: $TenantId"
Write-Host "Client ID: $ClientId"
Write-Host "Test device name: $TestDeviceName"
Write-Host "Cloud evidence mode: $CloudEvidenceMode"
Write-Host "State: $statePath"
Write-Host "VM script template: $templatePath"
Write-Host ""
