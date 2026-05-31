param(
    [Parameter(ValueFromPipeline = $true)]
    [object]$Token,

    [string]$AccessToken,

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [string]$ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
)

begin {
    $ErrorActionPreference = "Stop"
    $scope = "https://api.security.microsoft.com/AdvancedHunting.Read"
    $resource = "https://api.security.microsoft.com"
    $endpoint = "https://api.security.microsoft.com/api/advancedhunting/run"
    $cachePath = Join-Path (Get-Location) "powershell\Auth\ztvp-defenderxdr-token-cache.json"
    $cacheDir = Split-Path -Parent $cachePath
}

process {
    if ([string]::IsNullOrWhiteSpace($AccessToken) -and $Token) {
        if ($Token -is [string]) {
            $AccessToken = [string]$Token
        }
        elseif ($Token.PSObject.Properties["AccessToken"]) {
            $AccessToken = [string]$Token.AccessToken
        }
        elseif ($Token.PSObject.Properties["access_token"]) {
            $AccessToken = [string]$Token.access_token
        }
    }
}

end {
    if ([string]::IsNullOrWhiteSpace($AccessToken)) {
        throw "No Defender XDR access token was supplied. Pass -AccessToken or pipe/pass a token object with AccessToken."
    }

    $headers = @{
        Authorization = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    }
    $body = @{
        Query = "DeviceInfo | take 1"
    } | ConvertTo-Json -Depth 10

    try {
        Invoke-RestMethod `
            -Method POST `
            -Uri $endpoint `
            -Headers $headers `
            -Body $body `
            -ErrorAction Stop | Out-Null
    }
    catch {
        $reason = $_.Exception.Message
        try {
            $stream = $_.Exception.Response.GetResponseStream()
            if ($stream) {
                $reader = [System.IO.StreamReader]::new($stream)
                $responseBody = $reader.ReadToEnd()
                if (-not [string]::IsNullOrWhiteSpace($responseBody)) {
                    $reason = "$reason Response: $responseBody"
                }
            }
        }
        catch {}

        Write-Error @"
Defender XDR token cache was not saved because the Advanced Hunting validation query failed.
Query: DeviceInfo | take 1
Endpoint: $endpoint
Reason: $reason
"@
        throw
    }

    New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null

    $cache = [PSCustomObject]@{
        access_token = $AccessToken
        tenant_id = $TenantId
        client_id = $ClientId
        resource = $resource
        scope = $scope
        created_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        auth_method = "Manual MSAL.PS"
    }

    $cache | ConvertTo-Json -Depth 5 | Set-Content -Path $cachePath -Encoding UTF8

    Write-Host "Defender XDR Advanced Hunting token cache saved."
    Write-Host "Validation query: DeviceInfo | take 1"
    Write-Host "Endpoint tested: $endpoint"
    Write-Host "Token cache saved to: $cachePath"
}
