param()

$ErrorActionPreference = "Stop"

function Write-ZTVPJson {
    param([string]$Path, [object]$Object)
    $Object | ConvertTo-Json -Depth 100 | Set-Content -Path $Path -Encoding UTF8
}

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "DEV-DV-008"
$htmlDir = Join-Path $reportRoot "Html"
$cleanupPath = Join-Path $scenarioDir "devdv008-cleanup-result.json"
$reportPath = Join-Path $reportRoot "DEV-DV-008-result.json"
$htmlReportPath = Join-Path $htmlDir "DEV-DV-008-result.html"

New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null

$scenarioFiles = @(
    (Join-Path $scenarioDir "devdv008-state.json"),
    (Join-Path $scenarioDir "devdv008-local-evidence.json"),
    (Join-Path $scenarioDir "devdv008-local-evidence-template.ps1"),
    (Join-Path $scenarioDir "devdv008-prepare-result.json"),
    $reportPath,
    $htmlReportPath
)

$removed = @()
$errors = @()

foreach ($path in $scenarioFiles) {
    if (Test-Path -LiteralPath $path) {
        try {
            Remove-Item -LiteralPath $path -Force
            $removed += $path
        }
        catch {
            $errors += "Could not remove $path : $($_.Exception.Message)"
        }
    }
}

$status = if ($errors.Count -eq 0) { "Completed" } else { "Failed" }

$result = [PSCustomObject]@{
    scenario_id = "DEV-DV-008"
    cleanup_status = $status
    cleaned_at = (Get-Date).ToString("s")
    removed_files = @($removed)
    errors = @($errors)
    note = "Cleanup removes DEV-DV-008 state, imported local evidence, generated VM script template files, and final reports so the scenario starts from the beginning."
}

Write-ZTVPJson -Path $cleanupPath -Object $result

Write-Host ""
Write-Host "DEV-DV-008 cleanup completed."
Write-Host "Status: $status"
Write-Host "Removed files: $($removed.Count)"
Write-Host "Cleanup result: $cleanupPath"
Write-Host ""
