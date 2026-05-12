Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users

$context = Get-MgContext

if (-not $context) {
    Write-Host "Not connected to Microsoft Graph." -ForegroundColor Red
    Write-Host "Run .\powershell\connect_graph.ps1 first." -ForegroundColor Yellow
    exit 1
}

$users = Get-MgUser -Top 10 -Property Id,DisplayName,UserPrincipalName

$users | Select-Object Id, DisplayName, UserPrincipalName | Format-Table -AutoSize