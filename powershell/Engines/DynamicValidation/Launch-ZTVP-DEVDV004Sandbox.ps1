param()

$ErrorActionPreference = "Stop"

function Write-ZTVPJson {
    param([string]$Path, [object]$Object)
    $Object | ConvertTo-Json -Depth 100 | Set-Content -Path $Path -Encoding UTF8
}

$feature = Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -ErrorAction SilentlyContinue

if (-not $feature -or $feature.State -ne "Enabled") {
    throw "Windows Sandbox is not enabled. Run as admin: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All ; then reboot."
}

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "DEV-DV-004"
$statePath = Join-Path $scenarioDir "devdv004-state.json"

if (-not (Test-Path $statePath)) {
    throw "No DEV-DV-004 state file found. Prepare decoy first."
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

$runId = [string]$state.run_id
$decoyUpn = [string]$state.decoy_user.user_principal_name
$decoyPassword = [string]$state.decoy_user.temporary_password

$sandboxRoot = Join-Path $scenarioDir "sandbox"
$packageDir = Join-Path $sandboxRoot "DEV-DV-004-Package"

New-Item -ItemType Directory -Path $packageDir -Force | Out-Null

$windowStartUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$state.validation_window_start_utc = $windowStartUtc

$instructionsPath = Join-Path $packageDir "DEV-DV-004-Instructions.html"
$startScriptPath = Join-Path $packageDir "Start-DEV-DV-004.ps1"
$wsbPath = Join-Path $sandboxRoot "DEV-DV-004-$runId.wsb"

@"
<html>
<head>
<title>DEV-DV-004 Sandbox Device Registration Probe</title>
<style>
body { font-family: Segoe UI, Arial; margin: 30px; background: #0f172a; color: white; }
.card { background: #111827; border: 1px solid #334155; border-radius: 18px; padding: 22px; margin-bottom: 16px; }
.code { background: #020617; padding: 14px; border-radius: 12px; font-family: Consolas; color: #93c5fd; }
.warn { color: #fbbf24; font-weight: bold; }
.good { color: #86efac; font-weight: bold; }
</style>
</head>
<body>
<h1>DEV-DV-004 — Sandbox Device Registration Abuse Probe</h1>

<div class="card">
<h2>Goal</h2>
<p>Try to register this clean Sandbox device using the decoy user.</p>
<p class="warn">Do not use your admin account.</p>
</div>

<div class="card">
<h2>Decoy credentials</h2>
<div class="code">
UPN: $decoyUpn<br>
Password: $decoyPassword
</div>
</div>

<div class="card">
<h2>Steps inside Sandbox</h2>
<ol>
<li>Windows Settings should open automatically.</li>
<li>Go to <b>Accounts → Access work or school</b>.</li>
<li>Click <b>Connect</b>.</li>
<li>Sign in using the decoy UPN/password above.</li>
<li>Try the normal work/school account registration flow.</li>
<li>If asked to register/enroll/manage the device, continue only inside this Sandbox.</li>
<li>Return to ZTVP on the host and click <b>Wait for Device Registration Evidence</b>.</li>
</ol>
</div>

<div class="card">
<h2>Validation window</h2>
<div class="code">$windowStartUtc</div>
<p class="good">ZTVP will ignore device/log evidence before this timestamp.</p>
</div>
</body>
</html>
"@ | Set-Content -Path $instructionsPath -Encoding UTF8

@"
Start-Sleep -Seconds 2
Start-Process "ms-settings:workplace"
Start-Sleep -Seconds 2
Start-Process "`$PSScriptRoot\DEV-DV-004-Instructions.html"
"@ | Set-Content -Path $startScriptPath -Encoding UTF8

$hostPackageDir = (Resolve-Path $packageDir).Path

@"
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$hostPackageDir</HostFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -File "C:\Users\WDAGUtilityAccount\Desktop\DEV-DV-004-Package\Start-DEV-DV-004.ps1"</Command>
  </LogonCommand>
</Configuration>
"@ | Set-Content -Path $wsbPath -Encoding UTF8

$state.sandbox.launched = $true
$state.sandbox.launched_at = (Get-Date).ToString("s")
$state.sandbox.wsb_path = $wsbPath

Write-ZTVPJson -Path $statePath -Object $state

Start-Process $wsbPath

Write-Host ""
Write-Host "DEV-DV-004 Windows Sandbox launched."
Write-Host "Validation window start UTC: $windowStartUtc"
Write-Host "WSB: $wsbPath"
Write-Host ""
