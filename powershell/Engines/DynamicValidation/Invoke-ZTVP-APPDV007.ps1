param()

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$ProbeScopes = @(
    "Application.ReadWrite.All"
)

function Write-ZTVPJson {
    param([string]$Path, [object]$Object)

    $Object | ConvertTo-Json -Depth 100 | Set-Content -Path $Path -Encoding UTF8
}

function Test-ZTVPAuthorizationBlocked {
    param([string]$Message)

    return (
        $Message -match "Authorization_RequestDenied" -or
        $Message -match "Insufficient privileges" -or
        $Message -match "Forbidden" -or
        $Message -match "403" -or
        $Message -match "not authorized" -or
        $Message -match "permission"
    )
}

function Test-ZTVPNotFound {
    param([string]$Message)

    return (
        $Message -match "404" -or
        $Message -match "not found" -or
        $Message -match "Request_ResourceNotFound" -or
        $Message -match "ResourceNotFound"
    )
}

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "APP-DV-007"
$statePath = Join-Path $scenarioDir "appdv007-state.json"
$reportPath = Join-Path $reportRoot "APP-DV-007-result.json"

if (-not (Test-Path $statePath)) {
    throw "No APP-DV-007 state file found. Run Step 1 Prepare Decoy first."
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json
$decoyUpn = [string]$state.decoy_user.user_principal_name
$runId = [string]$state.run_id
$appDisplayName = "ZTVP-APP-DV-007-AppRegistration-Probe-$runId"

Write-Host ""
Write-Host "IMPORTANT:"
Write-Host "Microsoft normal interactive login will open."
Write-Host "Choose 'Use another account' and sign in as the DECOY user. Do not select your admin account:"
Write-Host "$decoyUpn"
Write-Host ""

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}

# Force Microsoft Graph PowerShell to stop reusing the cached admin account.
# This should make the sign-in picker appear so the operator can choose the decoy user.
$env:MSGRAPH_ENABLE_WAM = "false"

Connect-MgGraph `
    -Scopes $ProbeScopes `
    -ContextScope Process `
    -NoWelcome | Out-Null

$ctx = Get-MgContext

$connectedAccount = [string]$ctx.Account
$warnings = @()
$appCreated = $false
$appId = $null
$appObjectId = $null
$createError = $null
$appCleanupCompleted = $false
$cleanupActions = @()
$cleanupErrors = @()

$usedDecoy = ($connectedAccount.ToLower() -eq $decoyUpn.ToLower())

if (-not $usedDecoy) {
    $warnings += "Wrong account used. Expected decoy user $decoyUpn but connected account was $connectedAccount."
}

if ($usedDecoy) {
    try {
        $body = @{
            displayName = $appDisplayName
            signInAudience = "AzureADMyOrg"
        } | ConvertTo-Json -Depth 20

        $createdApp = Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/applications" `
            -Body $body `
            -ContentType "application/json"

        $appCreated = $true
        $appId = [string]$createdApp.appId
        $appObjectId = [string]$createdApp.id

        $state.app_probe.attempted = $true
        $state.app_probe.app_registration_created = $true
        $state.app_probe.app_object_id = $appObjectId
        $state.app_probe.app_id = $appId
        $state.app_probe.display_name = $appDisplayName
        $state.app_probe.error_message = $null

        Write-ZTVPJson -Path $statePath -Object $state

        try {
            Invoke-MgGraphRequest `
                -Method DELETE `
                -Uri "https://graph.microsoft.com/v1.0/applications/$appObjectId" | Out-Null

            $appCleanupCompleted = $true
            $cleanupActions += "Deleted temporary app registration using decoy session."
        }
        catch {
            $cleanupErrors += "Could not delete temporary app registration using decoy session: $($_.Exception.Message)"
        }
    }
    catch {
        $createError = $_.Exception.Message

        $state.app_probe.attempted = $true
        $state.app_probe.app_registration_created = $false
        $state.app_probe.display_name = $appDisplayName
        $state.app_probe.error_message = $createError

        Write-ZTVPJson -Path $statePath -Object $state
    }
}

$status = "PARTIAL_WRONG_ACCOUNT_USED"
$risk = "MEDIUM"
$summary = "The probe did not run with the prepared decoy user."
$finalClaim = "Sign in with the exact decoy UPN/password from Step 1 and rerun Step 2."
$evidenceQuality = "Partial - wrong account used."

if ($usedDecoy -and $appCreated) {
    $status = "FAIL_DECOY_USER_CAN_CREATE_APP_REGISTRATION"
    $risk = "HIGH"
    $summary = "The managed decoy normal user successfully created an Entra ID app registration."
    $finalClaim = "A normal decoy user can create app registrations in this tenant."
    $evidenceQuality = "Strong - real POST /applications succeeded using the decoy user session."

    if (-not $appCleanupCompleted) {
        $status = "PARTIAL_CLEANUP_REQUIRED"
        $warnings += "Temporary app registration was created but not cleaned by the probe. Run cleanup."
    }
}
elseif ($usedDecoy -and -not $appCreated -and $createError -and (Test-ZTVPAuthorizationBlocked -Message $createError)) {
    $status = "PASS_DECOY_USER_CANNOT_CREATE_APP_REGISTRATION"
    $risk = "LOW"
    $summary = "The managed decoy normal user attempted to create an app registration and was blocked."
    $finalClaim = "A normal decoy user cannot create app registrations in this tenant."
    $evidenceQuality = "Strong - real POST /applications attempt was blocked."
}
elseif ($usedDecoy -and -not $appCreated) {
    $status = "PARTIAL_CREATE_ATTEMPT_INCONCLUSIVE"
    $risk = "MEDIUM"
    $summary = "The decoy user signed in, but the create attempt failed for an unclear reason."
    $finalClaim = "ZTVP could not classify the result from this error alone."
    $evidenceQuality = "Partial - ambiguous create failure."

    if ($createError) {
        $warnings += "Create error: $createError"
    }
}

$result = [PSCustomObject]@{
    scenario_id = "APP-DV-007"
    display_id = "APP-DV-007"
    scenario_name = "App Registration Permission Probe"
    pillar = "Applications"
    scope = "Cloud"
    mode = "Three-Step Managed Decoy Login"
    generated_at = (Get-Date).ToString("s")

    tenant_id = $ctx.TenantId
    expected_decoy_user = $decoyUpn
    connected_probe_account = $connectedAccount

    status = $status
    risk = $risk
    executive_summary = $summary
    final_claim = $finalClaim
    evidence_quality = $evidenceQuality
    warnings = @($warnings)

    decoy_user = [PSCustomObject]@{
        id = $state.decoy_user.id
        user_principal_name = $state.decoy_user.user_principal_name
        display_name = $state.decoy_user.display_name
        password_stored_in_report = $false
        created_by_ztvp = $true
    }

    app_registration_creation_evidence = [PSCustomObject]@{
        actual_create_attempt_performed = $usedDecoy
        graph_endpoint = "POST https://graph.microsoft.com/v1.0/applications"
        app_registration_created = $appCreated
        display_name = $appDisplayName
        app_id = $appId
        object_id = $appObjectId
        error_message = $createError
        secrets_created = $false
        certificates_created = $false
        api_permissions_added = $false
        redirect_uris_added = $false
    }

    cleanup = [PSCustomObject]@{
        app_cleanup_completed = $appCleanupCompleted
        decoy_user_cleanup_required = $true
        state_file_active = $true
        actions = @($cleanupActions)
        errors = @($cleanupErrors)
    }

    metrics = [PSCustomObject]@{
        probe_used_decoy_user = $usedDecoy
        actual_create_attempt_performed = $usedDecoy
        app_registration_created = $appCreated
        app_cleanup_completed = $appCleanupCompleted
        decoy_user_cleanup_required = $true
        secrets_created = $false
        certificates_created = $false
        api_permissions_added = $false
    }

    recommendations = @(
        "If the decoy user can create app registrations, restrict normal user app registration creation in Entra ID.",
        "Allow app registration only for approved developers or controlled groups.",
        "Monitor Entra audit logs for application creation.",
        "Review existing app registrations for unknown owners.",
        "Require admin consent workflow for application permissions.",
        "Run cleanup to delete the APP-DV-007 decoy user."
    )

    limitations = @(
        "This validation requires the operator to sign in as the decoy user during Step 2.",
        "No secrets, certificates, redirect URIs, or API permissions are created.",
        "The decoy user is temporary and must be cleaned up."
    )
}

Write-ZTVPJson -Path $reportPath -Object $result

Write-Host ""
Write-Host "APP-DV-007 probe completed."
Write-Host "Status: $status"
Write-Host "Risk: $risk"
Write-Host "Expected decoy: $decoyUpn"
Write-Host "Connected account: $connectedAccount"
Write-Host "App registration created: $appCreated"
Write-Host "Report: $reportPath"
Write-Host ""
