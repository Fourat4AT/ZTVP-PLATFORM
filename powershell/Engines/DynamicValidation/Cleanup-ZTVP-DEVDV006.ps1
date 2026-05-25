param()

$ErrorActionPreference = "Stop"

function Write-ZTVPJson {
    param([string]$Path, [object]$Object)
    $Object | ConvertTo-Json -Depth 100 | Set-Content -Path $Path -Encoding UTF8
}

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "DEV-DV-006"
$cleanupPath = Join-Path $scenarioDir "devdv006-cleanup-result.json"

New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null

$scenarioFiles = @(
    (Join-Path $scenarioDir "devdv006-state.json"),
    (Join-Path $scenarioDir "devdv006-local-evidence.json"),
    (Join-Path $scenarioDir "devdv006-tenant-manual-evidence.json"),
    (Join-Path $scenarioDir "devdv006-local-evidence-template.ps1"),
    (Join-Path $scenarioDir "devdv006-prepare-result.json")
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
    scenario_id = "DEV-DV-006"
    cleanup_status = $status
    cleaned_at = (Get-Date).ToString("s")
    removed_files = @($removed)
    errors = @($errors)
    note = "Cleanup removes only DEV-DV-006 state, imported local evidence, and generated VM script template files. Final JSON/HTML reports are kept."
}

Write-ZTVPJson -Path $cleanupPath -Object $result

Write-Host ""
Write-Host "DEV-DV-006 cleanup completed."
Write-Host "Status: $status"
Write-Host "Removed files: $($removed.Count)"
Write-Host "Cleanup result: $cleanupPath"
Write-Host ""

