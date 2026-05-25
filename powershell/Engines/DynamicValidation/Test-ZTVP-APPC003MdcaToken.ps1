param(
    [Parameter(Mandatory=$true)]
    [string]$MdcaApiBaseUrl,

    [Parameter(Mandatory=$true)]
    [string]$MdcaApiToken
)

$ErrorActionPreference = "Stop"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-ZTVPMdcaAlertsEndpoint {
    param([string]$BaseUrl)

    $base = $BaseUrl.Trim().TrimEnd("/")

    if ([string]::IsNullOrWhiteSpace($base)) {
        throw "MDCA API base URL is empty."
    }

    if ($base.ToLower().EndsWith("/api")) {
        return "$base/v1/alerts/"
    }

    return "$base/api/v1/alerts/"
}

function Write-ZTVPJson {
    param(
        [string]$Path,
        [object]$Object
    )

    $Object |
        ConvertTo-Json -Depth 100 |
        Set-Content -Path $Path -Encoding UTF8
}

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "APP-C-003"
New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null

$resultPath = Join-Path $scenarioDir "appc003-mdca-token-test.json"

$token = $MdcaApiToken.Trim()

if ($token.StartsWith("Token ", [System.StringComparison]::OrdinalIgnoreCase)) {
    $token = $token.Substring(6).Trim()
}

if ($token.StartsWith("Bearer ", [System.StringComparison]::OrdinalIgnoreCase)) {
    $token = $token.Substring(7).Trim()
}

if ([string]::IsNullOrWhiteSpace($token)) {
    throw "MDCA API token is empty after cleanup."
}

$endpoint = Get-ZTVPMdcaAlertsEndpoint -BaseUrl $MdcaApiBaseUrl

$headers = @{
    "Authorization" = "Token $token"
    "Content-Type"  = "application/json"
}

$body = @{
    skip = 0
    limit = 5
    sortField = "date"
    sortDirection = "desc"
} | ConvertTo-Json -Depth 20

try {
    $response = Invoke-RestMethod `
        -Method POST `
        -Uri $endpoint `
        -Headers $headers `
        -Body $body `
        -ContentType "application/json" `
        -ErrorAction Stop

    $dataCount = 0

    if ($null -ne $response.data) {
        $dataCount = @($response.data).Count
    }

    $result = [PSCustomObject]@{
        scenario_id = "APP-C-003"
        test = "MDCA API token connectivity test"
        status = "SUCCESS"
        endpoint = $endpoint
        token_stored = $false
        alert_rows_returned = $dataCount
        tested_at = (Get-Date).ToString("s")
    }

    Write-ZTVPJson -Path $resultPath -Object $result

    Write-Host ""
    Write-Host "MDCA API token test succeeded."
    Write-Host "Endpoint: $endpoint"
    Write-Host "Alert rows returned: $dataCount"
    Write-Host "Result: $resultPath"
    Write-Host ""
    exit 0
}
catch {
    $message = $_.Exception.Message

    $result = [PSCustomObject]@{
        scenario_id = "APP-C-003"
        test = "MDCA API token connectivity test"
        status = "FAILED"
        endpoint = $endpoint
        token_stored = $false
        error = $message
        tested_at = (Get-Date).ToString("s")
    }

    Write-ZTVPJson -Path $resultPath -Object $result

    Write-Host ""
    Write-Host "MDCA API token test failed."
    Write-Host "Endpoint: $endpoint"
    Write-Host "Error: $message"
    Write-Host "Result: $resultPath"
    Write-Host ""

    exit 1
}
