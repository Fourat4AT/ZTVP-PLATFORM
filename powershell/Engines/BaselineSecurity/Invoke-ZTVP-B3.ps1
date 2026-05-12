Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Authentication -Force -ErrorAction SilentlyContinue

function Get-B3Value {
    param($Object, [string[]]$Names)

    if ($null -eq $Object) {
        return $null
    }

    foreach ($name in $Names) {
        if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($name)) {
            return $Object[$name]
        }

        if ($Object.PSObject.Properties[$name]) {
            return $Object.$name
        }

        if ($Object.PSObject.Properties["AdditionalProperties"] -and $Object.AdditionalProperties -and $Object.AdditionalProperties.ContainsKey($name)) {
            return $Object.AdditionalProperties[$name]
        }
    }

    return $null
}

function ConvertTo-B3Bool {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -eq $true) {
        return $true
    }

    if ($Value -eq $false) {
        return $false
    }

    $text = $Value.ToString().ToLowerInvariant()

    if ($text -eq "true") {
        return $true
    }

    if ($text -eq "false") {
        return $false
    }

    return $null
}

function ConvertTo-B3Text {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return $Value.ToString()
}

function Invoke-B3GraphCollection {
    param([string]$Uri)

    $items = @()
    $next = $Uri

    while (-not [string]::IsNullOrWhiteSpace($next)) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop

        if ($response.PSObject.Properties["value"]) {
            $items += @($response.value)
        }
        elseif ($response -is [System.Collections.IDictionary] -and $response.Contains("value")) {
            $items += @($response["value"])
        }
        else {
            $items += $response
            break
        }

        $next = ""

        if ($response.PSObject.Properties["@odata.nextLink"]) {
            $next = $response.'@odata.nextLink'
        }
        elseif ($response -is [System.Collections.IDictionary] -and $response.Contains("@odata.nextLink")) {
            $next = $response["@odata.nextLink"]
        }
    }

    return $items
}

function Get-B3SafeGraph {
    param([string]$Uri)

    try {
        $value = Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop

        return [PSCustomObject]@{
            Readable = $true
            Error    = ""
            Value    = $value
        }
    }
    catch {
        return [PSCustomObject]@{
            Readable = $false
            Error    = $_.Exception.Message
            Value    = $null
        }
    }
}

function Get-B3SafeCollection {
    param([string]$Uri)

    try {
        $value = @(Invoke-B3GraphCollection -Uri $Uri)

        return [PSCustomObject]@{
            Readable = $true
            Error    = ""
            Value    = $value
        }
    }
    catch {
        return [PSCustomObject]@{
            Readable = $false
            Error    = $_.Exception.Message
            Value    = @()
        }
    }
}

function Test-B3HighRiskScope {
    param([string]$Scope)

    if ([string]::IsNullOrWhiteSpace($Scope)) {
        return $false
    }

    $s = $Scope.ToLowerInvariant()

    $highRiskScopes = @(
        "directory.read.all",
        "directory.readwrite.all",
        "directory.accessasuser.all",
        "identityriskyuser.readwrite.all",
        "user.readwrite.all",
        "group.readwrite.all",
        "groupmember.readwrite.all",
        "application.readwrite.all",
        "approleassignment.readwrite.all",
        "rolemanagement.readwrite.directory",
        "mail.readwrite",
        "mail.send",
        "mail.send.shared",
        "mail.readwrite.shared",
        "files.readwrite.all",
        "sites.readwrite.all",
        "sites.fullcontrol.all",
        "offline_access"
    )

    foreach ($scopeName in $highRiskScopes) {
        if ($s -eq $scopeName -or $s -match [regex]::Escape($scopeName)) {
            return $true
        }
    }

    return $false
}

function ConvertTo-B3GrantEvidence {
    param($Grant)

    $scopeText = ConvertTo-B3Text (Get-B3Value $Grant @("scope", "Scope"))
    $scopes = @()

    if (-not [string]::IsNullOrWhiteSpace($scopeText)) {
        $scopes = @($scopeText -split "\s+" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    $highRiskScopes = @($scopes | Where-Object { Test-B3HighRiskScope $_ })

    $consentType = ConvertTo-B3Text (Get-B3Value $Grant @("consentType", "ConsentType"))
    $clientId = ConvertTo-B3Text (Get-B3Value $Grant @("clientId", "ClientId"))
    $resourceId = ConvertTo-B3Text (Get-B3Value $Grant @("resourceId", "ResourceId"))
    $principalId = ConvertTo-B3Text (Get-B3Value $Grant @("principalId", "PrincipalId"))

    $consentScope = "User-specific"

    if ($consentType -eq "AllPrincipals") {
        $consentScope = "Tenant-wide"
    }

    $riskLabel = "Low"

    if ($highRiskScopes.Count -gt 0 -and $consentType -eq "AllPrincipals") {
        $riskLabel = "High"
    }
    elseif ($highRiskScopes.Count -gt 0) {
        $riskLabel = "Medium"
    }

    return [PSCustomObject]@{
        id                    = ConvertTo-B3Text (Get-B3Value $Grant @("id", "Id"))
        client_id             = $clientId
        resource_id           = $resourceId
        principal_id          = $principalId
        consent_type          = $consentType
        consent_scope         = $consentScope
        scope                 = $scopeText
        scope_count           = $scopes.Count
        high_risk_scope_count = $highRiskScopes.Count
        high_risk_scopes      = $highRiskScopes
        tenant_wide           = [bool]($consentType -eq "AllPrincipals")
        user_specific         = [bool]($consentType -eq "Principal")
        risk_label            = $riskLabel
        action                = $(if ($riskLabel -eq "High") { "Validate owner, publisher, business need, then remove if not required." } elseif ($riskLabel -eq "Medium") { "Review scope and business justification." } else { "No immediate action." })
    }
}

function Get-B3UserConsentState {
    param($AssignedPolicies)

    $assigned = @($AssignedPolicies | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace($_.ToString()) })

    if ($assigned.Count -eq 0) {
        return [PSCustomObject]@{
            State   = "Restricted"
            Risk    = "Low"
            Meaning = "Normal users do not appear to have default user consent policy assignments."
        }
    }

    $joined = ($assigned -join " ").ToLowerInvariant()

    if ($joined -match "microsoft-dynamically-managed-permissions") {
        return [PSCustomObject]@{
            State   = "Microsoft-managed policy"
            Risk    = "Info"
            Meaning = "Microsoft-managed consent policies are present. This is recorded as context, not treated as the main failure."
        }
    }

    if ($joined -match "microsoft-user-default-legacy" -or $joined -match "managepermissiongrantsforself") {
        return [PSCustomObject]@{
            State   = "Broad or legacy user consent"
            Risk    = "High"
            Meaning = "Default users appear assigned a broad or legacy user consent policy."
        }
    }

    if ($joined -match "low") {
        return [PSCustomObject]@{
            State   = "Limited low-impact consent"
            Risk    = "Medium"
            Meaning = "Default users appear allowed to consent only to selected low-impact permissions."
        }
    }

    return [PSCustomObject]@{
        State   = "Custom policy"
        Risk    = "Medium"
        Meaning = "A custom permission grant policy is assigned. Review expected behavior."
    }
}

function Invoke-ZTVP-B3 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== B3 - User Consent and Enterprise App Baseline Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        $authz = Get-B3SafeGraph "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
        $adminConsent = Get-B3SafeGraph "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy"
        $oauth = Get-B3SafeCollection "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$top=999"

        if (-not $authz.Readable) {
            $findings += New-ZTVPFinding -Title "Consent policy evidence unavailable" -Detail "Authorization policy could not be read."
            $recommendations += New-ZTVPRecommendation -Title "Fix consent policy visibility" -Detail "Confirm Graph permissions allow reading authorization policy."
        }

        if (-not $adminConsent.Readable) {
            $findings += New-ZTVPFinding -Title "Admin consent workflow evidence unavailable" -Detail "Admin consent request policy could not be read."
            $recommendations += New-ZTVPRecommendation -Title "Fix admin consent workflow visibility" -Detail "Confirm Graph permissions allow reading adminConsentRequestPolicy."
        }

        if (-not $oauth.Readable) {
            $findings += New-ZTVPFinding -Title "OAuth grant evidence unavailable" -Detail "OAuth delegated grants could not be read."
            $recommendations += New-ZTVPRecommendation -Title "Fix OAuth grant visibility" -Detail "Confirm Graph permissions allow reading oauth2PermissionGrants."
        }

        $assignedPolicies = @()

        if ($authz.Readable) {
            $defaultPerms = Get-B3Value $authz.Value @("defaultUserRolePermissions", "DefaultUserRolePermissions")
            $assignedPolicies = @(Get-B3Value $defaultPerms @("permissionGrantPoliciesAssigned", "PermissionGrantPoliciesAssigned"))
        }

        $userConsent = Get-B3UserConsentState -AssignedPolicies $assignedPolicies

        $adminConsentEnabled = $null
        $reviewerCount = 0

        if ($adminConsent.Readable) {
            $adminConsentEnabled = ConvertTo-B3Bool (Get-B3Value $adminConsent.Value @("isEnabled", "IsEnabled"))
            $reviewers = @(Get-B3Value $adminConsent.Value @("reviewers", "Reviewers"))
            $reviewerCount = $reviewers.Count
        }

        $grantEvidence = @()

        foreach ($grant in @($oauth.Value)) {
            if ($null -ne $grant) {
                $grantEvidence += ConvertTo-B3GrantEvidence -Grant $grant
            }
        }

        $tenantWideGrants = @($grantEvidence | Where-Object { $_.tenant_wide -eq $true })
        $userSpecificGrants = @($grantEvidence | Where-Object { $_.user_specific -eq $true })
        $highRiskGrants = @($grantEvidence | Where-Object { $_.high_risk_scope_count -gt 0 })
        $tenantWideHighRiskGrants = @($tenantWideGrants | Where-Object { $_.high_risk_scope_count -gt 0 })

        if ($adminConsentEnabled -eq $true) {
            $recommendations += New-ZTVPRecommendation -Title "Keep admin consent workflow enabled" -Detail "This is good. Keep using it as the governed approval path for app permissions."
        }
        elseif ($adminConsent.Readable) {
            $findings += New-ZTVPFinding -Title "Admin consent workflow is not enabled" -Detail "Users may not have a governed request path for app permissions."
            $recommendations += New-ZTVPRecommendation -Title "Enable admin consent workflow" -Detail "Enable admin consent workflow so users request app approval instead of approving apps directly."
        }

        if ($userConsent.Risk -eq "High") {
            $findings += New-ZTVPFinding -Title "Broad user consent is enabled" -Detail "Default users appear assigned a broad or legacy user consent policy."
            $recommendations += New-ZTVPRecommendation -Title "Restrict user consent" -Detail "Disable broad user consent or limit it to approved low-impact scenarios."
        }
        elseif ($userConsent.Risk -eq "Medium") {
            $recommendations += New-ZTVPRecommendation -Title "Review user consent policy" -Detail "Confirm the assigned user consent policy matches the tenant governance model."
        }

        if ($tenantWideHighRiskGrants.Count -gt 0) {
            $findings += New-ZTVPFinding -Title "Tenant-wide high-risk app grants detected" -Detail "$($tenantWideHighRiskGrants.Count) tenant-wide app permission grants include high-risk permissions. These should be reviewed first in the HTML report priority queue."

            $recommendations += New-ZTVPRecommendation -Title "Review tenant-wide high-risk app grants" -Detail "For each high-risk tenant-wide grant, confirm the app owner, publisher, business need, and permissions. Remove grants that are not required."
        }
        elseif ($highRiskGrants.Count -gt 0) {
            $findings += New-ZTVPFinding -Title "High-risk user-specific app grants detected" -Detail "$($highRiskGrants.Count) app permission grants include high-risk permissions."
            $recommendations += New-ZTVPRecommendation -Title "Review high-risk delegated grants" -Detail "Validate owner, business need, and permissions."
        }

        $status = "PASS"
        $risk = "LOW"

        if (-not $authz.Readable -or -not $adminConsent.Readable -or -not $oauth.Readable) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }

        if ($tenantWideHighRiskGrants.Count -gt 0 -or $userConsent.Risk -eq "High") {
            $status = "FAIL"
            $risk = "HIGH"
        }
        elseif ($highRiskGrants.Count -gt 0 -or $userConsent.Risk -eq "Medium" -or $adminConsentEnabled -ne $true) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }

        $adminConsentText = "Unknown"

        if ($adminConsentEnabled -eq $true) {
            $adminConsentText = "Enabled"
        }
        elseif ($adminConsentEnabled -eq $false) {
            $adminConsentText = "Not enabled"
        }

        if ($status -eq "PASS") {
            $summary = "App consent is governed. Admin consent workflow is enabled and no tenant-wide high-risk app grants were detected."
            $gap = "No major app consent baseline gap was detected."
        }
        elseif ($status -eq "PARTIAL") {
            $summary = "App consent needs review. Admin consent workflow is $adminConsentText. High-risk or custom consent items need validation."
            $gap = "App consent posture is partially aligned and needs validation."
        }
        else {
            $summary = "App consent has high-risk exposure. Admin consent workflow is $adminConsentText, but $($tenantWideHighRiskGrants.Count) tenant-wide high-risk app grants need review."
            $gap = "Tenant-wide high-risk app permissions require review and cleanup."
        }

        $overview = @(
            "Admin consent workflow: $adminConsentText"
            "Tenant-wide high-risk grants: $($tenantWideHighRiskGrants.Count)"
            "High-risk grants total: $($highRiskGrants.Count)"
            "Tenant-wide grants total: $($tenantWideGrants.Count)"
            "OAuth grants total: $($grantEvidence.Count)"
            "User consent policy: $($userConsent.State)"
        ) -join "; "

        $currentState = @(
            "Admin consent workflow: $adminConsentText."
            "Admin consent reviewers: $reviewerCount."
            "OAuth grants assessed: $($grantEvidence.Count)."
            "Tenant-wide grants: $($tenantWideGrants.Count)."
            "High-risk grants: $($highRiskGrants.Count)."
            "Tenant-wide high-risk grants: $($tenantWideHighRiskGrants.Count)."
            "User consent policy: $($userConsent.State)."
        ) -join " "

        $resultArgs = @{
            ScenarioId      = "B3"
            ScenarioName    = "User Consent and Enterprise App Baseline Review"
            Category        = "Baseline Security"
            Status          = $status
            Risk            = $risk
            Findings        = $findings
            Recommendations = $recommendations
            Evidence        = [PSCustomObject]@{
                executive_summary = $summary
                consent_overview = $overview

                admin_consent_workflow_enabled = $adminConsentEnabled
                admin_consent_workflow_state = $adminConsentText
                admin_consent_reviewer_count = $reviewerCount

                user_consent_state = $userConsent.State
                user_consent_risk = $userConsent.Risk
                user_consent_meaning = $userConsent.Meaning
                permission_grant_policies_assigned_count = $assignedPolicies.Count
                permission_grant_policies_assigned = $assignedPolicies

                oauth_delegated_grant_count = $grantEvidence.Count
                tenant_wide_delegated_grant_count = $tenantWideGrants.Count
                user_specific_delegated_grant_count = $userSpecificGrants.Count
                high_risk_delegated_grant_count = $highRiskGrants.Count
                tenant_wide_high_risk_delegated_grant_count = $tenantWideHighRiskGrants.Count

                oauth_delegated_grants = $grantEvidence
                tenant_wide_delegated_grants = $tenantWideGrants
                high_risk_delegated_grants = $highRiskGrants
                tenant_wide_high_risk_delegated_grants = $tenantWideHighRiskGrants
            }
            CurrentState    = $currentState
            ZeroTrustTarget = "App consent should be governed through admin consent workflow. Tenant-wide high-risk delegated permissions should be minimized, justified, and reviewed."
            GapSummary      = $gap
        }

        return New-ZTVPResult @resultArgs
    }
    catch {
        $resultArgs = @{
            ScenarioId      = "B3"
            ScenarioName    = "User Consent and Enterprise App Baseline Review"
            Category        = "Baseline Security"
            Status          = "ERROR"
            Risk            = "CRITICAL"
            Findings        = @(New-ZTVPFinding -Title "Execution error" -Detail $_.Exception.Message)
            Recommendations = @(New-ZTVPRecommendation -Title "Fix B3 execution issue" -Detail "Review Graph permissions for authorization policy, admin consent request policy, and OAuth grants.")
            Evidence        = $null
            CurrentState    = "B3 could not complete consent baseline assessment."
            ZeroTrustTarget = "App consent should be governed and high-risk app grants should be reviewed."
            GapSummary      = "B3 could not be evaluated because execution failed."
        }

        return New-ZTVPResult @resultArgs
    }
}
