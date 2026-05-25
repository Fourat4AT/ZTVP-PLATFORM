param(
    [string]$ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e",
    [string]$Scope = "https://graph.microsoft.com/User.Read"
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "Directory.Read.All"
)

function Ensure-ZTVPGraphConnection {
    param([string[]]$Scopes)

    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    $needReconnect = $false

    if (-not $ctx) {
        $needReconnect = $true
    }
    else {
        $currentScopes = @()

        if ($ctx.Scopes) {
            $currentScopes = @($ctx.Scopes | ForEach-Object { $_.ToLower() })
        }

        foreach ($scope in $Scopes) {
            if ($currentScopes -notcontains $scope.ToLower()) {
                $needReconnect = $true
            }
        }
    }

    if ($needReconnect) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
        Connect-MgGraph -Scopes $Scopes -NoWelcome | Out-Null
        $ctx = Get-MgContext
    }

    return $ctx
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-002"
$statePath = Join-Path $stateDir "decoy-state.json"
$publicPath = Join-Path $stateDir "device-code-challenge-public.json"
$privatePath = Join-Path $stateDir "device-code-challenge-private.json"

if (-not (Test-Path $statePath)) {
    throw "No active ID-C-002 decoy state was found. Generate a fresh decoy user first."
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

if ($state.cleanup.status -eq "Completed") {
    throw "The current ID-C-002 run is already closed. Generate a new decoy user."
}

$tenantId = $ctx.TenantId

if ([string]::IsNullOrWhiteSpace($tenantId)) {
    throw "Could not determine tenant ID from Microsoft Graph context."
}

$deviceCodeUri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode"

$body = @{
    client_id = $ClientId
    scope = $Scope
}

$response = Invoke-RestMethod `
    -Method POST `
    -Uri $deviceCodeUri `
    -Body $body `
    -ContentType "application/x-www-form-urlencoded"

$startedAt = Get-Date
$expiresAt = $startedAt.AddSeconds([int]$response.expires_in)

$public = [PSCustomObject]@{
    scenario_id = "ID-C-002"
    run_id = $state.run_id
    tenant_id = $tenantId
    client_id = $ClientId
    scope = $Scope
    started_at = $startedAt.ToString("s")
    expires_at = $expiresAt.ToString("s")
    expires_in_seconds = [int]$response.expires_in
    interval_seconds = [int]$response.interval
    user_code = [string]$response.user_code
    verification_uri = [string]$response.verification_uri
    verification_uri_complete = [string]$response.verification_uri_complete
    message = [string]$response.message
}

$private = [PSCustomObject]@{
    scenario_id = "ID-C-002"
    run_id = $state.run_id
    tenant_id = $tenantId
    client_id = $ClientId
    scope = $Scope
    started_at = $startedAt.ToString("s")
    expires_at = $expiresAt.ToString("s")
    expires_in_seconds = [int]$response.expires_in
    interval_seconds = [int]$response.interval
    user_code = [string]$response.user_code
    verification_uri = [string]$response.verification_uri
    verification_uri_complete = [string]$response.verification_uri_complete
    message = [string]$response.message
    device_code = [string]$response.device_code
}

$public | ConvertTo-Json -Depth 20 | Set-Content -Path $publicPath -Encoding UTF8
$private | ConvertTo-Json -Depth 20 | Set-Content -Path $privatePath -Encoding UTF8

$state.device_code_challenge = $public
$state | ConvertTo-Json -Depth 40 | Set-Content -Path $statePath -Encoding UTF8

Write-Host ""
Write-Host "ID-C-002 device-code challenge created"
Write-Host "Open: $($public.verification_uri)"
Write-Host "Code: $($public.user_code)"
Write-Host "Expires: $($public.expires_at)"
Write-Host "Client ID: $ClientId"
Write-Host "Public challenge: $publicPath"
Write-Host ""
