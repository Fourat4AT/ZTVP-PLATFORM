function Save-ZTVPResultJson {
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

Export-ModuleMember -Function Save-ZTVPResultJson
