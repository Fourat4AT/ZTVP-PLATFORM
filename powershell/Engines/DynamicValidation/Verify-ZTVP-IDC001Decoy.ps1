$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "User.Read.All",
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

function Get-ZTVPValue {
    param([object]$Object, [string]$Name)

    if ($null -eq $Object) { return $null }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ([string]$key -eq $Name) { return $Object[$key] }
        }
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }

    return $null
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-001"
$statePath = Join-Path $stateDir "decoy-state.json"
$verifyPath = Join-Path $stateDir "decoy-verify-result.json"

if (-not (Test-Path $statePath)) {
    $result = [PSCustomObject]@{
        scenario_id = "ID-C-001"
        verified_at = (Get-Date).ToString("s")
        status = "NoState"
        exists = $false
        message = "No active local decoy state was found."
    }

    $result | ConvertTo-Json -Depth 20 | Set-Content -Path $verifyPath -Encoding UTF8
    Write-Host "No active local decoy state was found."
    exit 0
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

$userId = [string]$state.decoy_user.id
$userUpn = [string]$state.decoy_user.user_principal_name

$exists = $false
$userDetails = $null
$errorText = $null
$verificationMethod = "None"
$idMatch = $false
$upnMatch = $false

try {
    if (-not [string]::IsNullOrWhiteSpace($userId)) {
        $uri = "https://graph.microsoft.com/v1.0/users/$userId?`$select=id,userPrincipalName,displayName,accountEnabled,createdDateTime"
        $userDetails = Invoke-MgGraphRequest -Method GET -Uri $uri
        $exists = $true
        $verificationMethod = "ObjectId"
    }
}
catch {
    $errorText = $_.Exception.Message
}

if (-not $exists -and -not [string]::IsNullOrWhiteSpace($userUpn)) {
    try {
        $encodedUpn = [System.Uri]::EscapeDataString($userUpn)
        $uri = "https://graph.microsoft.com/v1.0/users/$encodedUpn?`$select=id,userPrincipalName,displayName,accountEnabled,createdDateTime"
        $userDetails = Invoke-MgGraphRequest -Method GET -Uri $uri
        $exists = $true
        $verificationMethod = "UserPrincipalName"
        $errorText = $null
    }
    catch {
        $errorText = $_.Exception.Message
    }
}

if ($exists -and $null -ne $userDetails) {
    $graphId = [string](Get-ZTVPValue -Object $userDetails -Name "id")
    $graphUpn = [string](Get-ZTVPValue -Object $userDetails -Name "userPrincipalName")

    $idMatch = (-not [string]::IsNullOrWhiteSpace($userId) -and $graphId -eq $userId)
    $upnMatch = ($graphUpn.Trim().ToLower() -eq $userUpn.Trim().ToLower())
}

$result = [PSCustomObject]@{
    scenario_id = "ID-C-001"
    verified_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    connected_account = $ctx.Account
    status = if ($exists) { "Exists" } else { "Missing" }
    exists = $exists
    verification_method = $verificationMethod
    id_match = $idMatch
    upn_match = $upnMatch
    expected_user = [PSCustomObject]@{
        id = $userId
        user_principal_name = $userUpn
    }
    graph_user = $userDetails
    error = $errorText
}

$result | ConvertTo-Json -Depth 30 | Set-Content -Path $verifyPath -Encoding UTF8

Write-Host ""
Write-Host "ID-C-001 exact decoy verification completed"
Write-Host "Expected active user: $userUpn"
Write-Host "Expected object ID: $userId"
Write-Host "Exists in tenant: $exists"
Write-Host "Verification method: $verificationMethod"
Write-Host "UPN match: $upnMatch"
Write-Host "ID match: $idMatch"
Write-Host "Report: $verifyPath"
Write-Host ""
