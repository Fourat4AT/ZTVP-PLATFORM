Import-Module Microsoft.Graph.Authentication

$Scopes = @(
    "User.Read.All",
    "Directory.Read.All",
    "Policy.Read.All",
    "UserAuthenticationMethod.Read.All"
)

try {
    Connect-MgGraph -Scopes $Scopes -ErrorAction Stop

    Write-Host ""
    Write-Host "Connected to Microsoft Graph successfully (FULL mode)." -ForegroundColor Green
    Write-Host "This mode is for real assessment and requires admin-consented scopes." -ForegroundColor Yellow
    Write-Host ""

    Get-MgContext
}
catch {
    Write-Host ""
    Write-Host "Microsoft Graph connection failed." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    Write-Host ""
}