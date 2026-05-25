param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId
)

$ErrorActionPreference = "Stop"

$scope = "https://api.security.microsoft.com/AdvancedHunting.Read"
$resource = "https://api.security.microsoft.com"
$endpoint = "https://api.security.microsoft.com/api/advancedhunting/run"
$cachePath = Join-Path (Get-Location) "powershell\Auth\ztvp-defenderxdr-token-cache.json"
$cacheDir = Split-Path -Parent $cachePath

function Get-ZTVPManualMsalFallback {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$Scope
    )

    return @"
Import-Module MSAL.PS

`$TenantId = "$TenantId"
`$ClientId = "$ClientId"
`$Scope = "$Scope"

`$token = Get-MsalToken ``
  -TenantId `$TenantId ``
  -ClientId `$ClientId ``
  -Scopes `$Scope ``
  -Interactive ``
  -Prompt SelectAccount

`$cachePath = ".\powershell\Auth\ztvp-defenderxdr-token-cache.json"
`$cache = [PSCustomObject]@{
  access_token = `$token.AccessToken
  tenant_id = `$TenantId
  client_id = `$ClientId
  resource = "https://api.security.microsoft.com"
  scope = `$Scope
  created_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  auth_method = "Manual working MSAL.PS token"
}
`$cache | ConvertTo-Json -Depth 5 | Set-Content -Path `$cachePath -Encoding UTF8
"@
}

$authMethod = $null
$accessToken = $null
$expiresOnUtc = $null
$msalImportComplete = $false
try {
    if (-not (Get-Module -ListAvailable -Name MSAL.PS)) {
        throw "MSAL.PS is not installed."
    }

    Import-Module MSAL.PS -ErrorAction Stop
    $msalImportComplete = $true

    $msalToken = Get-MsalToken `
        -TenantId $TenantId `
        -ClientId $ClientId `
        -Scopes $scope `
        -Interactive `
        -Prompt SelectAccount

    if (-not $msalToken.AccessToken) {
        throw "MSAL returned no access token."
    }

    $accessToken = [string]$msalToken.AccessToken
    if ($msalToken.ExpiresOn) {
        $expiresOnUtc = ([datetimeoffset]$msalToken.ExpiresOn).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    $authMethod = "MSAL.PS"
}
catch {
    $msalError = $_.Exception.Message
    $manualFallback = Get-ZTVPManualMsalFallback -TenantId $TenantId -ClientId $ClientId -Scope $scope
    $failureMessage = if ($msalImportComplete) {
        "MSAL.PS Defender XDR sign-in failed. Run the manual MSAL connection command below, then save the token cache."
    }
    else {
        "MSAL.PS could not load in this PowerShell host. Run the manual MSAL connection command below, then save the token cache."
    }
    Write-Error @"
$failureMessage

MSAL.PS error: $msalError

Required delegated permission: AdvancedHunting.Read
Resource: https://api.security.microsoft.com
Endpoint: /api/advancedhunting/run

$manualFallback
"@
    throw
}

$headers = @{
    Authorization = "Bearer $accessToken"
    "Content-Type" = "application/json"
}

$body = @{
    Query = "DeviceInfo | take 1"
} | ConvertTo-Json -Depth 10

try {
    $testResponse = Invoke-RestMethod `
        -Method POST `
        -Uri $endpoint `
        -Headers $headers `
        -Body $body `
        -ErrorAction Stop
}
catch {
    Write-Error @"
Defender XDR Advanced Hunting test query failed.
Error: $($_.Exception.Message)

Required delegated permission: AdvancedHunting.Read
Resource: https://api.security.microsoft.com
Endpoint: /api/advancedhunting/run
"@
    throw
}

New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null

$cache = [PSCustomObject]@{
    access_token = $accessToken
    expires_on = $expiresOnUtc
    tenant_id = $TenantId
    client_id = $ClientId
    resource = $resource
    scope = $scope
    auth_method = $authMethod
    endpoint = $endpoint
    test_query = "DeviceInfo | take 1"
    test_result_count = @($testResponse.Results).Count
    created_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

$cache | ConvertTo-Json -Depth 10 | Set-Content -Path $cachePath -Encoding UTF8

Write-Host "Connected to Defender XDR Advanced Hunting."
Write-Host "Auth method: $authMethod"
Write-Host "Token scope: $scope"
Write-Host "Endpoint tested: $endpoint"
Write-Host "Token cache saved to: $cachePath"
