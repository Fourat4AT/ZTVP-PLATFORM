$ErrorActionPreference = "Stop"

$catalogPath = ".\powershell\ScenarioCatalog.ps1"
$runnerPath  = ".\powershell\Run-ZTVP.ps1"

$catalogBackup = ".\powershell\ScenarioCatalog.backup-final-baseline-fix-$(Get-Date -Format 'yyyyMMdd-HHmmss').ps1"
$runnerBackup  = ".\powershell\Run-ZTVP.backup-final-baseline-fix-$(Get-Date -Format 'yyyyMMdd-HHmmss').ps1"

Copy-Item $catalogPath $catalogBackup -Force
Copy-Item $runnerPath $runnerBackup -Force

# ============================================================
# 1. Clean broken ScenarioCatalog baseline override blocks
# ============================================================

$catalog = Get-Content $catalogPath -Raw

$markers = @(
    "ZTVP BASELINE FINAL FIX",
    "ZTVP BASELINE HARD FIX",
    "ZTVP BASELINE SECURITY SCENARIOS",
    "ZTVP BASELINE OVERRIDE FIX",
    "ZTVP BASELINE MENU REPAIR"
)

foreach ($marker in $markers) {
    $catalog = [regex]::Replace(
        $catalog,
        "(?s)\r?\n?# BEGIN $marker.*?# END $marker\r?\n?",
        "`r`n"
    )
}

# Restore any renamed Get-ZTVPScenarios function back to the normal name.
$catalog = [regex]::Replace(
    $catalog,
    '(?m)^(\s*)function\s+Get-ZTVPScenarios_BaseOriginal\s*\{',
    '$1function Get-ZTVPScenarios {',
    1
)

$catalog = [regex]::Replace(
    $catalog,
    '(?m)^(\s*)function\s+Get-ZTVPScenarios_Original_BaselineFix\s*\{',
    '$1function Get-ZTVPScenarios {',
    1
)

$catalog = [regex]::Replace(
    $catalog,
    '(?m)^(\s*)function\s+Get-ZTVPScenarios_Original_BaselineFinalFix\s*\{',
    '$1function Get-ZTVPScenarios {',
    1
)

Set-Content $catalogPath $catalog -Encoding UTF8

# ============================================================
# 2. Patch runner directly:
#    If category is Baseline Security, return B1-B5 directly.
#    This avoids the broken catalog filter path completely.
# ============================================================

$runner = Get-Content $runnerPath -Raw

$pattern = '\$allScenarios\s*=\s*@\(\s*Get-ZTVPScenariosByCategory\s+-CategoryId\s+\$Category\.Id\s*\)'

$replacement = @"
if (`$Category.Name -eq "Baseline Security" -or `$Category.Id -match "(?i)baseline|^5$") {
    `$allScenarios = @()

    `$allScenarios += [PSCustomObject]@{
        ScenarioId   = "B1"
        Name         = "Tenant Security Defaults and Baseline Control Review"
        CategoryId   = `$Category.Id
        CategoryName = "Baseline Security"
        PillarId     = "IDENTITY"
        PillarName   = "Identity"
        Objective    = "Validate whether the tenant has a baseline protection model through Security Defaults or enabled custom Conditional Access controls."
        EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B1.ps1"
        FunctionName = "Invoke-ZTVP-B1"
        Implemented  = `$true
        Scope        = "Cloud"
        Priority     = "High"
        Phase        = "Phase 1"
    }

    `$allScenarios += [PSCustomObject]@{
        ScenarioId   = "B2"
        Name         = "Default User Permissions and App Registration Review"
        CategoryId   = `$Category.Id
        CategoryName = "Baseline Security"
        PillarId     = "IDENTITY"
        PillarName   = "Identity"
        Objective    = "Review default user permissions such as app registration, group creation, and directory self-service capabilities."
        EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B2.ps1"
        FunctionName = "Invoke-ZTVP-B2"
        Implemented  = `$false
        Scope        = "Cloud"
        Priority     = "High"
        Phase        = "Phase 1"
    }

    `$allScenarios += [PSCustomObject]@{
        ScenarioId   = "B3"
        Name         = "User Consent and Enterprise App Baseline Review"
        CategoryId   = `$Category.Id
        CategoryName = "Baseline Security"
        PillarId     = "IDENTITY"
        PillarName   = "Identity"
        Objective    = "Review user consent, admin consent workflow, and enterprise application consent baseline posture."
        EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B3.ps1"
        FunctionName = "Invoke-ZTVP-B3"
        Implemented  = `$false
        Scope        = "Cloud"
        Priority     = "High"
        Phase        = "Phase 1"
    }

    `$allScenarios += [PSCustomObject]@{
        ScenarioId   = "B4"
        Name         = "Password and Account Protection Baseline Review"
        CategoryId   = `$Category.Id
        CategoryName = "Baseline Security"
        PillarId     = "IDENTITY"
        PillarName   = "Identity"
        Objective    = "Review password protection, account protection, lockout, and self-service password reset baseline posture."
        EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B4.ps1"
        FunctionName = "Invoke-ZTVP-B4"
        Implemented  = `$false
        Scope        = "Cloud"
        Priority     = "Medium"
        Phase        = "Phase 1"
    }

    `$allScenarios += [PSCustomObject]@{
        ScenarioId   = "B5"
        Name         = "User Account Hygiene Review"
        CategoryId   = `$Category.Id
        CategoryName = "Baseline Security"
        PillarId     = "IDENTITY"
        PillarName   = "Identity"
        Objective    = "Review stale, disabled, guest, unlicensed, and potentially unmanaged user account hygiene indicators."
        EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B5.ps1"
        FunctionName = "Invoke-ZTVP-B5"
        Implemented  = `$false
        Scope        = "Cloud"
        Priority     = "Medium"
        Phase        = "Phase 1"
    }
}
else {
    `$allScenarios = @(Get-ZTVPScenariosByCategory -CategoryId `$Category.Id)
}
"@

if (-not [regex]::IsMatch($runner, $pattern)) {
    throw "Could not find scenario-loading line in Run-ZTVP.ps1. Backup: $runnerBackup"
}

$runner = [regex]::Replace(
    $runner,
    $pattern,
    [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $replacement },
    1
)

Set-Content $runnerPath $runner -Encoding UTF8

# ============================================================
# 3. Parser checks
# ============================================================

foreach ($file in @($catalogPath, $runnerPath)) {
    $tokens = $null
    $errors = $null

    [System.Management.Automation.Language.Parser]::ParseFile(
        (Resolve-Path $file),
        [ref]$tokens,
        [ref]$errors
    ) | Out-Null

    if ($errors.Count -gt 0) {
        Write-Host "Parser errors in $file" -ForegroundColor Red
        $errors | Format-List
        throw "Parser check failed. Backups: $catalogBackup and $runnerBackup"
    }
}

Write-Host ""
Write-Host "Baseline Security menu repaired." -ForegroundColor Green
Write-Host "ScenarioCatalog backup: $catalogBackup" -ForegroundColor Yellow
Write-Host "Run-ZTVP backup     : $runnerBackup" -ForegroundColor Yellow
Write-Host ""
Write-Host "Run now:" -ForegroundColor Cyan
Write-Host ".\powershell\Run-ZTVP.ps1"
