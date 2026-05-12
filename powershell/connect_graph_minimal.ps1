Import-Module Microsoft.Graph.Authentication

$Scopes = @(
    "User.Read"
)

try {
    Connect-MgGraph -Scopes $Scopes -ErrorAction Stop

    Write-Host ""
    Write-Host "Connected to Microsoft Graph successfully (MINIMAL mode)." -ForegroundColor Green
    Write-Host "This mode is for runner/menu testing only." -ForegroundColor Yellow
    Write-Host ""

    Get-MgContext
}
catch {
    Write-Host ""
    Write-Host "Microsoft Graph connection failed." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    Write-Host ""
}