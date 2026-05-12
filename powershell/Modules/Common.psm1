function New-ZTVPResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScenarioId,

        [Parameter(Mandatory = $true)]
        [string]$ScenarioName,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Summary,

        [Parameter(Mandatory = $false)]
        [object]$Details = $null
    )

    return [PSCustomObject]@{
        ScenarioId   = $ScenarioId
        ScenarioName = $ScenarioName
        Status       = $Status
        Summary      = $Summary
        Details      = $Details
        Timestamp    = (Get-Date).ToString("s")
    }
}

function Export-ZTVPResultJson {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Result,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $folder = Split-Path $OutputPath -Parent
    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }

    $Result | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
}

Export-ModuleMember -Function New-ZTVPResult, Export-ZTVPResultJson