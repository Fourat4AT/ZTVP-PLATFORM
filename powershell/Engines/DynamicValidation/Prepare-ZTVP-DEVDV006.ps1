param(
    [string]$TestFolder = "C:\Users\Public\ZTVP-DEV-DV-006",
    [string]$TestFile = "C:\Users\Public\ZTVP-DEV-DV-006\eicar.com.txt",
    [string]$TestDeviceName = "",
    [string]$TenantId = "",
    [string]$ClientId = "",
    [ValidateSet("Tenant + Local Evidence", "Local Evidence Only")]
    [string]$CloudEvidenceMode = "Tenant + Local Evidence"
)

$ErrorActionPreference = "Stop"

function Write-ZTVPJson {
    param([string]$Path, [object]$Object)
    $Object | ConvertTo-Json -Depth 100 | Set-Content -Path $Path -Encoding UTF8
}

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "DEV-DV-006"
$htmlDir = Join-Path $reportRoot "Html"

New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null
New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null

$statePath = Join-Path $scenarioDir "devdv006-state.json"
$preparePath = Join-Path $scenarioDir "devdv006-prepare-result.json"
$templatePath = Join-Path $scenarioDir "devdv006-local-evidence-template.ps1"
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
    $clientIdSource = "DEV-DV-006 parameter"
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
    $tenantDiscoverySource = "DEV-DV-006 parameter"
}

if ([string]::IsNullOrWhiteSpace($TenantId)) {
    Write-Warning "Tenant ID not found. Run ZTVP tenant connection/preflight discovery first."
}

$state = [PSCustomObject]@{
    scenario_id = "DEV-DV-006"
    display_id = "DEV-DV-006"
    scenario_name = "Defender EICAR Detection Validation"
    pillar = "Devices"
    scope = "Cloud"
    mode = "Manual VM Script"
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
    test_file = $TestFile
    vm_script_generated = $false
    local_evidence_imported = $false
    local_evidence_path = $null
    local_evidence_imported_utc = $null
    local_evidence_timestamp_utc = $null
    tenant_analysis_started_utc = $null
    tenant_analysis_completed_utc = $null
    current_run_report_path = $null
    current_run_status = "ARMED_NOT_EXECUTED"
}

Write-ZTVPJson -Path $statePath -Object $state

$escapedFolder = $TestFolder.Replace("'", "''")
$escapedFile = $TestFile.Replace("'", "''")

$template = @"
`$ErrorActionPreference = "Continue"

`$folder = '$escapedFolder'
`$filePath = '$escapedFile'
`$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!`$H+H*'
`$evidencePath = Join-Path `$folder 'devdv006-local-evidence.json'
`$errors = @()
`$fileWriteAttempted = `$false
`$fileWriteSucceeded = `$false
`$fileReadAttempted = `$false
`$fileReadSucceeded = `$false
`$readError = `$null
`$writeError = `$null

try {
    New-Item -ItemType Directory -Path `$folder -Force | Out-Null
}
catch {
    `$errors += "Create folder failed: `$(`$_.Exception.Message)"
}

try {
    `$fileWriteAttempted = `$true
    Set-Content -Path `$filePath -Value `$eicar -Encoding ASCII -Force
    `$fileWriteSucceeded = `$true
}
catch {
    `$writeError = `$_.Exception.Message
    `$errors += "Write EICAR file failed: `$writeError"
}

try {
    `$fileReadAttempted = `$true
    Get-Content -Path `$filePath -ErrorAction Stop | Out-Null
    `$fileReadSucceeded = `$true
}
catch {
    `$readError = `$_.Exception.Message
    `$errors += "Read EICAR file failed: `$readError"
}

Start-Sleep -Seconds 15

`$mpStatusRaw = `$null
`$mpStatus = `$null
`$mpThreatDetection = @()
`$mpThreat = @()

try {
    `$mpStatusRaw = Get-MpComputerStatus
    `$mpStatus = [PSCustomObject]@{
        AMRunningMode = `$mpStatusRaw.AMRunningMode
        AMServiceEnabled = `$mpStatusRaw.AMServiceEnabled
        AntivirusEnabled = `$mpStatusRaw.AntivirusEnabled
        RealTimeProtectionEnabled = `$mpStatusRaw.RealTimeProtectionEnabled
        BehaviorMonitorEnabled = `$mpStatusRaw.BehaviorMonitorEnabled
        IoavProtectionEnabled = `$mpStatusRaw.IoavProtectionEnabled
        OnAccessProtectionEnabled = `$mpStatusRaw.OnAccessProtectionEnabled
        NISEnabled = `$mpStatusRaw.NISEnabled
        IsTamperProtected = `$mpStatusRaw.IsTamperProtected
        DefenderSignaturesOutOfDate = `$mpStatusRaw.DefenderSignaturesOutOfDate
        AntivirusSignatureVersion = `$mpStatusRaw.AntivirusSignatureVersion
        AMProductVersion = `$mpStatusRaw.AMProductVersion
    }
}
catch {
    `$errors += "Get-MpComputerStatus failed: `$(`$_.Exception.Message)"
}

try {
    `$mpThreatDetection = @(Get-MpThreatDetection | ForEach-Object {
        [PSCustomObject]@{
            ThreatID = `$_.ThreatID
            DetectionID = `$_.DetectionID
            InitialDetectionTime = `$_.InitialDetectionTime
            LastThreatStatusChangeTime = `$_.LastThreatStatusChangeTime
            ActionSuccess = `$_.ActionSuccess
            CleaningActionID = `$_.CleaningActionID
            CurrentThreatExecutionStatusID = `$_.CurrentThreatExecutionStatusID
            DetectionSourceTypeID = `$_.DetectionSourceTypeID
            DomainUser = `$_.DomainUser
            ProcessName = `$_.ProcessName
            Resources = `$_.Resources
            ThreatStatusID = `$_.ThreatStatusID
            ThreatStatusErrorCode = `$_.ThreatStatusErrorCode
        }
    })
}
catch {
    `$errors += "Get-MpThreatDetection failed: `$(`$_.Exception.Message)"
}

try {
    `$mpThreat = @(Get-MpThreat | ForEach-Object {
        [PSCustomObject]@{
            ThreatID = `$_.ThreatID
            ThreatName = `$_.ThreatName
            SeverityID = `$_.SeverityID
            CategoryID = `$_.CategoryID
            IsActive = `$_.IsActive
            DidThreatExecute = `$_.DidThreatExecute
            RollupStatus = `$_.RollupStatus
            Resources = `$_.Resources
        }
    })
}
catch {
    `$errors += "Get-MpThreat failed: `$(`$_.Exception.Message)"
}

`$threatJson = ((`$mpThreat | ConvertTo-Json -Depth 10) + " " + (`$mpThreatDetection | ConvertTo-Json -Depth 10))
`$localSummary = [PSCustomObject]@{
    defender_realtime_enabled = [bool]`$mpStatus.RealTimeProtectionEnabled
    defender_av_enabled = [bool]`$mpStatus.AntivirusEnabled
    defender_running_mode = `$mpStatus.AMRunningMode
    eicar_read_blocked = (-not `$fileReadSucceeded -and ((`$readError -match "virus") -or (`$readError -match "potentially unwanted")))
    local_detection_found = (
        (`$threatJson -match "EICAR") -or
        (`$threatJson -match [regex]::Escape(`$filePath))
    )
    threat_names = @(`$mpThreat | ForEach-Object { `$_.ThreatName } | Where-Object { `$_ })
}

`$evidence = [PSCustomObject]@{
    scenario_id = "DEV-DV-006"
    validation_method = "Manual VM Script"
    computer_name = `$env:COMPUTERNAME
    current_user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    file_path = `$filePath
    file_write_attempted = `$fileWriteAttempted
    file_write_succeeded = `$fileWriteSucceeded
    file_write_error = `$writeError
    file_read_attempted = `$fileReadAttempted
    file_read_succeeded = `$fileReadSucceeded
    file_read_error = `$readError
    file_still_exists = (Test-Path -LiteralPath `$filePath)
    local_summary = `$localSummary
    mp_computer_status_slim = `$mpStatus
    mp_threat_detection_slim = @(`$mpThreatDetection)
    mp_threat_slim = @(`$mpThreat)
    errors = @(`$errors)
}

`$json = `$evidence | ConvertTo-Json -Depth 20
`$json | Set-Content -Path `$evidencePath -Encoding UTF8
Write-Host ""
Write-Host "DEV-DV-006 local VM evidence JSON:"
Write-Host ""
Write-Output `$json
Write-Host ""
Write-Host "Saved to: `$evidencePath"
"@

Set-Content -Path $templatePath -Value $template -Encoding UTF8

$prepare = [PSCustomObject]@{
    scenario_id = "DEV-DV-006"
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
    test_file = $TestFile
    state_path = $statePath
    vm_script_template_path = $templatePath
}

Write-ZTVPJson -Path $preparePath -Object $prepare

Write-Host ""
Write-Host "DEV-DV-006 validation window started."
Write-Host "Validation window UTC: $windowStartUtc"
Write-Host "Tenant ID: $TenantId"
Write-Host "Client ID: $ClientId"
Write-Host "Test device name: $TestDeviceName"
Write-Host "Cloud evidence mode: $CloudEvidenceMode"
Write-Host "State: $statePath"
Write-Host "VM script template: $templatePath"
Write-Host ""

