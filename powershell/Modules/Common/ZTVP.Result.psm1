function New-ZTVPFinding {
    param(
        [string]$Title,
        [string]$Detail
    )

    return [PSCustomObject]@{
        title  = $Title
        detail = $Detail
    }
}

function New-ZTVPRecommendation {
    param(
        [string]$Title,
        [string]$Detail
    )

    return [PSCustomObject]@{
        title  = $Title
        detail = $Detail
    }
}

function New-ZTVPResult {
    param(
        [string]$ScenarioId,
        [string]$ScenarioName,
        [string]$Category,
        [string]$Status,
        [string]$Risk,
        [array]$Findings = @(),
        [array]$Recommendations = @(),
        [object]$Evidence = $null,
        [string]$CurrentState = "",
        [string]$ZeroTrustTarget = "",
        [string]$GapSummary = ""
    )

    return [PSCustomObject]@{
        scenario_id       = $ScenarioId
        scenario_name     = $ScenarioName
        category          = $Category
        status            = $Status
        risk              = $Risk
        findings          = $Findings
        recommendations   = $Recommendations
        evidence          = $Evidence
        current_state     = $CurrentState
        zero_trust_target = $ZeroTrustTarget
        gap_summary       = $GapSummary
        timestamp         = (Get-Date).ToString("s")
    }
}

function Save-ZTVPResultJson {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Result,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [switch]$SkipHtml
    )

    $folder = Split-Path $OutputPath -Parent

    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }

    $Result | ConvertTo-Json -Depth 20 | Set-Content -Path $OutputPath -Encoding UTF8

    Write-Host "JSON report saved to: $OutputPath" -ForegroundColor Green

    if ($SkipHtml) {
        return
    }

    try {
        $converterCandidates = @(
            (Join-Path (Get-Location) "powershell\Tools\Convert-ZTVPReportToHtml.ps1"),
            (Join-Path $PSScriptRoot "..\..\Tools\Convert-ZTVPReportToHtml.ps1")
        )

        $converter = $null

        foreach ($candidate in $converterCandidates) {
            $resolved = Resolve-Path $candidate -ErrorAction SilentlyContinue

            if ($resolved) {
                $converter = $resolved.Path
                break
            }
        }

        if (-not $converter) {
            Write-Warning "HTML converter was not found. JSON was saved, but HTML was not generated."
            return
        }

        & $converter -JsonPath $OutputPath
    }
    catch {
        Write-Warning "JSON was saved, but HTML generation failed."
        Write-Warning $_.Exception.Message
    }
}

Export-ModuleMember -Function New-ZTVPFinding, New-ZTVPRecommendation, New-ZTVPResult, Save-ZTVPResultJson
