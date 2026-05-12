param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath
)

function Resolve-ZTVPPath {
    param([string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }

    return (Resolve-Path $Path).Path
}

if (-not (Test-Path $JsonPath)) {
    throw "JSON report not found: $JsonPath"
}

$jsonFullPath = Resolve-ZTVPPath -Path $JsonPath
$result = Get-Content -Path $jsonFullPath -Raw | ConvertFrom-Json

$toolsDir = $PSScriptRoot
$scenarioId = $result.scenario_id

$converterMap = @{
    "B5" = "Convert-ZTVPB5ReportToHtml.ps1"
    "B4" = "Convert-ZTVPB4ReportToHtml.ps1"
    "B3" = "Convert-ZTVPB3ReportToHtml.ps1"
    "B2" = "Convert-ZTVPB2ReportToHtml.ps1"
    "B1" = "Convert-ZTVPB1ReportToHtml.ps1"
    "ID4" = "Convert-ZTVPID4ReportToHtml.ps1"
    "E1" = "Convert-ZTVPE1ReportToHtml.ps1"
    "E2" = "Convert-ZTVPE2ReportToHtml.ps1"
    "E3" = "Convert-ZTVPE3ReportToHtml.ps1"
    "E4" = "Convert-ZTVPE4ReportToHtml.ps1"
    "E5" = "Convert-ZTVPE5ReportToHtml.ps1"
    "P1" = "Convert-ZTVPP1ReportToHtml.ps1"
    "P2" = "Convert-ZTVPP2ReportToHtml.ps1"
    "P3" = "Convert-ZTVPP3ReportToHtml.ps1"
}

if ($converterMap.ContainsKey($scenarioId)) {
    $scenarioConverter = Join-Path $toolsDir $converterMap[$scenarioId]

    if (Test-Path $scenarioConverter) {
        Write-Host "Using $scenarioId scenario-specific HTML report generator..." -ForegroundColor Cyan
        & $scenarioConverter -JsonPath $jsonFullPath
        return
    }

    Write-Warning "$scenarioId converter not found. Falling back to shared converter."
}

$sharedConverter = Join-Path $toolsDir "Convert-ZTVPReportToHtml.Shared.ps1"

if (-not (Test-Path $sharedConverter)) {
    throw "Shared converter not found: $sharedConverter"
}

Write-Host "Using shared HTML report generator..." -ForegroundColor Cyan
& $sharedConverter -JsonPath $jsonFullPath














