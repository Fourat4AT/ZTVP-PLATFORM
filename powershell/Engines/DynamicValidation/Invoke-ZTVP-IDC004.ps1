param(
    [string]$ObservedOutcome = "NOT_RECORDED",
    [int]$LookbackMinutes = 240
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "Directory.Read.All",
    "Application.Read.All",
    "DelegatedPermissionGrant.ReadWrite.All",
    "AuditLog.Read.All"
)

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

function ConvertTo-ZTVPArray {
    param([object]$Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return @($Value) }
    return @($Value)
}

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

function Invoke-ZTVPPagedGraphQuery {
    param([string]$Uri, [int]$MaxPages = 10)

    $items = @()
    $page = 0
    $nextUri = $Uri

    while ($nextUri -and $page -lt $MaxPages) {
        $page++
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri
        $value = Get-ZTVPValue -Object $response -Name "value"

        if ($value) { $items += @($value) }

        $nextLink = Get-ZTVPValue -Object $response -Name "@odata.nextLink"

        if ([string]::IsNullOrWhiteSpace([string]$nextLink)) {
            $nextUri = $null
        }
        else {
            $nextUri = [string]$nextLink
        }
    }

    return $items
}

function Get-ZTVPOAuthPermissionGrants {
    param(
        [string]$ServicePrincipalId,
        [string]$UserId
    )

    $items = @()

    if (-not [string]::IsNullOrWhiteSpace($ServicePrincipalId)) {
        $filter = "clientId eq '$ServicePrincipalId'"
        $encoded = [System.Uri]::EscapeDataString($filter)
        $uri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=$encoded"

        try {
            $items += @(Invoke-ZTVPPagedGraphQuery -Uri $uri -MaxPages 10)
        }
        catch {}
    }

    $rows = @()

    foreach ($grant in $items) {
        $id = [string](Get-ZTVPValue -Object $grant -Name "id")
        $clientId = [string](Get-ZTVPValue -Object $grant -Name "clientId")
        $consentType = [string](Get-ZTVPValue -Object $grant -Name "consentType")
        $principalId = [string](Get-ZTVPValue -Object $grant -Name "principalId")
        $resourceId = [string](Get-ZTVPValue -Object $grant -Name "resourceId")
        $scope = [string](Get-ZTVPValue -Object $grant -Name "scope")

        $appliesToDecoy = $false

        if ($consentType -eq "AllPrincipals") {
            $appliesToDecoy = $true
        }
        elseif (-not [string]::IsNullOrWhiteSpace($principalId) -and $principalId -eq $UserId) {
            $appliesToDecoy = $true
        }

        if ($appliesToDecoy) {
            $rows += [PSCustomObject]@{
                id = $id
                clientId = $clientId
                consentType = $consentType
                principalId = $principalId
                resourceId = $resourceId
                scope = $scope
                applies_to_decoy = $appliesToDecoy
            }
        }
    }

    return $rows
}

function Get-ZTVPDirectoryAuditEvidence {
    param(
        [datetime]$StartUtcDate,
        [string]$AppId,
        [string]$AppDisplayName,
        [string]$UserPrincipalName
    )

    $startUtc = $StartUtcDate.ToString("o")
    $filter = "activityDateTime ge $startUtc"
    $encoded = [System.Uri]::EscapeDataString($filter)
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$encoded&`$top=100"

    $items = @()

    try {
        $items = @(Invoke-ZTVPPagedGraphQuery -Uri $uri -MaxPages 10)
    }
    catch {
        return @()
    }

    $rows = @()

    foreach ($item in $items) {
        $raw = ""
        try { $raw = ($item | ConvertTo-Json -Depth 50 -Compress) } catch {}

        if (
            $raw -notmatch [regex]::Escape($AppId) -and
            $raw -notmatch [regex]::Escape($AppDisplayName) -and
            $raw -notmatch [regex]::Escape($UserPrincipalName)
        ) {
            continue
        }

        $rows += [PSCustomObject]@{
            id = Get-ZTVPValue -Object $item -Name "id"
            activityDateTime = Get-ZTVPValue -Object $item -Name "activityDateTime"
            activityDisplayName = Get-ZTVPValue -Object $item -Name "activityDisplayName"
            category = Get-ZTVPValue -Object $item -Name "category"
            result = Get-ZTVPValue -Object $item -Name "result"
            resultReason = Get-ZTVPValue -Object $item -Name "resultReason"
            raw = $item
        }
    }

    return $rows
}

function Get-ZTVPSignInEvidence {
    param(
        [datetime]$StartUtcDate,
        [string]$UserPrincipalName
    )

    $startUtc = $StartUtcDate.ToString("o")
    $safeUpn = $UserPrincipalName.Replace("'", "''")
    $filter = "createdDateTime ge $startUtc and userPrincipalName eq '$safeUpn'"
    $encoded = [System.Uri]::EscapeDataString($filter)
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$encoded"

    $items = @()

    try {
        $items = @(Invoke-ZTVPPagedGraphQuery -Uri $uri -MaxPages 10)
    }
    catch {
        return @()
    }

    $rows = @()

    foreach ($item in $items) {
        $statusObj = Get-ZTVPValue -Object $item -Name "status"

        $rows += [PSCustomObject]@{
            createdDateTime = Get-ZTVPValue -Object $item -Name "createdDateTime"
            userPrincipalName = Get-ZTVPValue -Object $item -Name "userPrincipalName"
            appDisplayName = Get-ZTVPValue -Object $item -Name "appDisplayName"
            resourceDisplayName = Get-ZTVPValue -Object $item -Name "resourceDisplayName"
            conditionalAccessStatus = Get-ZTVPValue -Object $item -Name "conditionalAccessStatus"
            errorCode = Get-ZTVPValue -Object $statusObj -Name "errorCode"
            failureReason = Get-ZTVPValue -Object $statusObj -Name "failureReason"
            ipAddress = Get-ZTVPValue -Object $item -Name "ipAddress"
        }
    }

    return $rows
}

function Get-ZTVPAuthorizationPolicy {
    try {
        $policy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"

        return [PSCustomObject]@{
            readable = $true
            defaultUserRolePermissions = Get-ZTVPValue -Object $policy -Name "defaultUserRolePermissions"
            raw = $policy
            error = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            readable = $false
            defaultUserRolePermissions = $null
            raw = $null
            error = $_.Exception.Message
        }
    }
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-004"
$statePath = Join-Path $stateDir "consent-state.json"

if (-not (Test-Path $statePath)) {
    throw "No active ID-C-004 consent state was found. Prepare the scenario first."
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

$targetUpn = [string]$state.decoy_user.user_principal_name
$targetUserId = [string]$state.decoy_user.id
$appId = [string]$state.test_application.app_id
$appObjectId = [string]$state.test_application.app_object_id
$appDisplayName = [string]$state.test_application.display_name
$servicePrincipalId = [string]$state.test_application.service_principal_id
$scope = [string]$state.test_application.requested_scope

Write-Host ""
Write-Host "========================================="
Write-Host "ZTVP ID-C-004 - OAuth App Consent Exposure Validation"
Write-Host "========================================="
Write-Host ""
Write-Host "Decoy user: $targetUpn"
Write-Host "Test app: $appDisplayName"
Write-Host "App ID: $appId"
Write-Host "Observed browser outcome: $ObservedOutcome"
Write-Host ""

$startUtcDate = (Get-Date).ToUniversalTime().AddMinutes(-1 * $LookbackMinutes)

Start-Sleep -Seconds 8

$grants = @(Get-ZTVPOAuthPermissionGrants -ServicePrincipalId $servicePrincipalId -UserId $targetUserId)
$directoryAudits = @(Get-ZTVPDirectoryAuditEvidence -StartUtcDate $startUtcDate -AppId $appId -AppDisplayName $appDisplayName -UserPrincipalName $targetUpn)
$signIns = @(Get-ZTVPSignInEvidence -StartUtcDate $startUtcDate -UserPrincipalName $targetUpn)
$authorizationPolicy = Get-ZTVPAuthorizationPolicy

$grantCreated = ($grants.Count -gt 0)
$observedBlocked = ($ObservedOutcome -eq "ADMIN_APPROVAL_REQUIRED" -or $ObservedOutcome -eq "CONSENT_BLOCKED")
$observedAccepted = ($ObservedOutcome -eq "USER_ACCEPTED_CONSENT")
$observedInterrupted = ($ObservedOutcome -eq "SIGNIN_INTERRUPTED")

$warnings = @()
$evidenceQuality = "Unknown"

if ($grantCreated) {
    $status = "FAIL_USER_CONSENT_ALLOWED"
    $risk = "MEDIUM"
    $evidenceQuality = "Strong - OAuth grant exists"
    $summary = "A delegated OAuth permission grant was created for the controlled ZTVP test application."
    $finalClaim = "A standard decoy user was able to grant OAuth delegated permissions to the test application. User consent exposure exists for the tested scope."
}
elseif ($observedBlocked) {
    $status = "PASS_USER_CONSENT_BLOCKED"
    $risk = "LOW"
    $evidenceQuality = "Strong - Browser outcome plus no OAuth grant"
    $summary = "No OAuth permission grant was created and the observed browser outcome indicated consent was blocked or administrator approval was required."
    $finalClaim = "The tenant prevented the standard decoy user from granting OAuth permissions to the controlled test application."
}
elseif ($observedInterrupted) {
    $status = "PARTIAL_SIGNIN_INTERRUPTED"
    $risk = "MEDIUM"
    $evidenceQuality = "Partial"
    $summary = "No OAuth permission grant was created, but the consent decision was not reached because sign-in or registration was interrupted."
    $finalClaim = "This run did not prove user-consent enforcement because the decoy user did not complete the consent decision path."
}
elseif ($observedAccepted -and -not $grantCreated) {
    $status = "PARTIAL_ACCEPTED_BUT_NO_GRANT_FOUND"
    $risk = "MEDIUM"
    $evidenceQuality = "Partial / inconsistent"
    $summary = "The browser outcome was recorded as accepted, but Microsoft Graph did not show an OAuth permission grant for the test app."
    $finalClaim = "The run is inconsistent. Wait a few minutes and collect evidence again before drawing a conclusion."
}
elseif ($signIns.Count -gt 0 -or $directoryAudits.Count -gt 0) {
    $status = "PASS_NO_OAUTH_GRANT_CREATED"
    $risk = "LOW"
    $evidenceQuality = "Moderate - telemetry exists and no grant exists"
    $summary = "The decoy user produced telemetry, but no OAuth permission grant was created for the test app."
    $finalClaim = "The controlled test app did not receive delegated OAuth permissions from the decoy user."
}
else {
    $status = "PARTIAL_NO_ATTEMPT_EVIDENCE"
    $risk = "MEDIUM"
    $evidenceQuality = "Partial"
    $summary = "No OAuth permission grant was found, but ZTVP also did not find clear sign-in or audit evidence for the consent attempt."
    $finalClaim = "No grant was created, but the run cannot prove that the consent flow was actually completed or blocked."
}

if (-not $grantCreated -and $signIns.Count -eq 0) {
    $warnings += "No decoy sign-in evidence was found yet. Entra sign-in telemetry can be delayed or the browser attempt may not have reached sign-in."
}

if (-not $grantCreated -and $directoryAudits.Count -eq 0) {
    $warnings += "No matching directory audit evidence was found yet. OAuth consent audit events can be delayed or absent when consent is blocked before grant creation."
}

if ($grantCreated) {
    $warnings += "Cleanup must remove created OAuth permission grants before deleting the test app."
}

$result = [PSCustomObject]@{
    scenario_id = "ID-C-004"
    scenario_name = "OAuth App Consent Exposure Validation"
    pillar = "Identity"
    scope = "Cloud"
    generated_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    connected_account = $ctx.Account

    control_tested = "Standard users should not be able to grant OAuth delegated permissions to unapproved applications without administrator approval."
    expected_result = "The decoy user is blocked from granting consent or receives an administrator approval requirement. No oauth2PermissionGrant should be created."
    failure_condition = "An oauth2PermissionGrant is created for the controlled ZTVP test application."
    test_method = "Fresh standard decoy user, temporary OAuth test app registration, real Microsoft consent URL, Graph oauth2PermissionGrant inspection, sign-in/audit telemetry, and cleanup."
    final_claim = $finalClaim

    status = $status
    risk = $risk
    evidence_quality = $evidenceQuality
    executive_summary = $summary
    warnings = @($warnings)

    observed_browser_outcome = $ObservedOutcome

    decoy_user = [PSCustomObject]@{
        id = $targetUserId
        user_principal_name = $targetUpn
    }

    test_application = [PSCustomObject]@{
        app_object_id = $appObjectId
        app_id = $appId
        display_name = $appDisplayName
        service_principal_id = $servicePrincipalId
        requested_scope = $scope
        consent_url = $state.consent_attempt.consent_url
    }

    authorization_policy = $authorizationPolicy

    oauth_grants = @($grants)
    directory_audit_evidence = @($directoryAudits)
    sign_in_evidence = @($signIns)

    metrics = [PSCustomObject]@{
        oauth_grant_created = $grantCreated
        oauth_grant_count = $grants.Count
        directory_audit_evidence_count = $directoryAudits.Count
        sign_in_evidence_count = $signIns.Count
        lookback_minutes = $LookbackMinutes
    }
}

$reportPath = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-004-result.json"

$result |
    ConvertTo-Json -Depth 100 |
    Set-Content -Path $reportPath -Encoding UTF8

Write-Host ""
Write-Host "========================================="
Write-Host "ID-C-004 COMPLETED"
Write-Host "========================================="
Write-Host ""
Write-Host "Status: $status"
Write-Host "Risk: $risk"
Write-Host "Evidence quality: $evidenceQuality"
Write-Host "OAuth grant created: $grantCreated"
Write-Host "OAuth grants found: $($grants.Count)"
Write-Host "Directory audit rows: $($directoryAudits.Count)"
Write-Host "Sign-in evidence rows: $($signIns.Count)"
Write-Host "Report saved to: $reportPath"
Write-Host ""
