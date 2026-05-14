Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Authentication -Force -ErrorAction SilentlyContinue

function Invoke-HA2GraphCollection {
    param([string]$Uri)

    $items = @()
    $next = $Uri

    while (-not [string]::IsNullOrWhiteSpace($next)) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop

        if ($response.value) {
            $items += @($response.value)
        }

        $next = ""

        if ($response.'@odata.nextLink') {
            $next = $response.'@odata.nextLink'
        }
    }

    return $items
}

function Invoke-ZTVP-HA2 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== H-A2 - Password Hash Sync / PTA / Federation Posture Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        $domainsReadable = $false
        $domainsError = ""
        $domains = @()

        try {
            $domains = @(Invoke-HA2GraphCollection -Uri "https://graph.microsoft.com/v1.0/domains?`$select=id,isVerified,authenticationType")
            $domainsReadable = $true
        }
        catch {
            $domainsError = $_.Exception.Message
        }

        $verifiedDomains = @($domains | Where-Object { $_.isVerified -eq $true })
        $federatedDomains = @($verifiedDomains | Where-Object { $_.authenticationType -eq "Federated" })
        $managedDomains = @($verifiedDomains | Where-Object { $_.authenticationType -eq "Managed" })

        $adSyncModuleAvailable = $false
        $schedulerReadable = $false
        $schedulerError = ""
        $scheduler = $null

        try {
            Import-Module ADSync -ErrorAction Stop
            $adSyncModuleAvailable = $true
        }
        catch {
            $adSyncModuleAvailable = $false
        }

        if ($adSyncModuleAvailable) {
            try {
                $scheduler = Get-ADSyncScheduler -ErrorAction Stop
                $schedulerReadable = $true
            }
            catch {
                $schedulerError = $_.Exception.Message
            }
        }

        $authModel = "Unknown"

        if ($federatedDomains.Count -gt 0) {
            $authModel = "Federated"
        }
        elseif ($managedDomains.Count -gt 0) {
            $authModel = "Managed"
        }

        if (-not $domainsReadable) {
            $findings += New-ZTVPFinding -Title "Cloud domain authentication model could not be read" -Detail $domainsError
            $recommendations += New-ZTVPRecommendation -Title "Fix domain visibility" -Detail "Confirm Graph permissions allow reading tenant domains."
        }

        if ($federatedDomains.Count -gt 0) {
            $findings += New-ZTVPFinding -Title "Federated domain authentication detected" -Detail "$($federatedDomains.Count) verified domain(s) use federated authentication. Federation requires health, certificate, MFA, and resilience validation."
            $recommendations += New-ZTVPRecommendation -Title "Validate federation health and resilience" -Detail "Confirm AD FS or federation service health, certificate expiry, MFA integration, monitoring, and emergency sign-in plan."
        }

        if (-not $adSyncModuleAvailable) {
            $findings += New-ZTVPFinding -Title "ADSync module not available on this machine" -Detail "The ADSync PowerShell module was not found. Sync scheduler and local Entra Connect evidence could not be collected."
            $recommendations += New-ZTVPRecommendation -Title "Run H-A2 on the Entra Connect server for full evidence" -Detail "Run this scenario on the Entra Connect server to collect ADSync scheduler and sync configuration evidence."
        }
        elseif (-not $schedulerReadable) {
            $findings += New-ZTVPFinding -Title "ADSync scheduler could not be read" -Detail $schedulerError
            $recommendations += New-ZTVPRecommendation -Title "Fix ADSync scheduler visibility" -Detail "Run with permissions that can read Entra Connect scheduler status."
        }

        $syncEnabled = $null
        $syncCycleEnabled = $null
        $nextSyncCyclePolicyType = ""
        $nextSyncCycleStartTime = ""

        if ($schedulerReadable) {
            $syncEnabled = $scheduler.SyncCycleEnabled
            $syncCycleEnabled = $scheduler.SyncCycleEnabled
            $nextSyncCyclePolicyType = $scheduler.NextSyncCyclePolicyType
            $nextSyncCycleStartTime = $scheduler.NextSyncCycleStartTimeInUTC

            if ($scheduler.SyncCycleEnabled -ne $true) {
                $findings += New-ZTVPFinding -Title "Entra Connect sync scheduler is disabled" -Detail "ADSync scheduler exists but SyncCycleEnabled is not true."
                $recommendations += New-ZTVPRecommendation -Title "Enable or justify disabled sync scheduler" -Detail "Confirm why the sync scheduler is disabled and whether identity changes are flowing to Entra ID."
            }
        }

        $status = "PASS"
        $risk = "LOW"

        if (-not $domainsReadable) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }
        elseif ($federatedDomains.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }
        elseif (-not $adSyncModuleAvailable) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }
        elseif ($schedulerReadable -and $scheduler.SyncCycleEnabled -ne $true) {
            $status = "FAIL"
            $risk = "HIGH"
        }

        if ($status -eq "PASS") {
            $summary = "Hybrid authentication posture appears understandable. Verified domains are managed and ADSync scheduler evidence was collected."
            $gap = "No major hybrid authentication model gap was detected."
        }
        elseif ($status -eq "PARTIAL") {
            $summary = "Hybrid authentication posture needs review. Domain authentication model or local Entra Connect evidence requires validation."
            $gap = "Hybrid authentication model is partially aligned and requires validation."
        }
        else {
            $summary = "Hybrid authentication posture has a high-risk sync gap. Entra Connect scheduler evidence indicates sync may not be enabled."
            $gap = "Hybrid authentication/sync posture is not aligned."
        }

        $overview = @(
            "Authentication model: $authModel"
            "Verified domains: $($verifiedDomains.Count)"
            "Federated domains: $($federatedDomains.Count)"
            "Managed domains: $($managedDomains.Count)"
            "ADSync module available: $adSyncModuleAvailable"
            "ADSync scheduler readable: $schedulerReadable"
            "SyncCycleEnabled: $syncCycleEnabled"
        ) -join "; "

        return New-ZTVPResult `
            -ScenarioId "H-A2" `
            -ScenarioName "Password Hash Sync / PTA / Federation Posture Review" `
            -Category "Authentication Security" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary = $summary
                hybrid_auth_model_overview = $overview
                authentication_model = $authModel
                verified_domain_count = $verifiedDomains.Count
                federated_domain_count = $federatedDomains.Count
                managed_domain_count = $managedDomains.Count
                domains = $domains
                federated_domains = $federatedDomains
                managed_domains = $managedDomains
                adsync_module_available = $adSyncModuleAvailable
                adsync_scheduler_readable = $schedulerReadable
                adsync_scheduler_error = $schedulerError
                sync_cycle_enabled = $syncCycleEnabled
                next_sync_cycle_policy_type = $nextSyncCyclePolicyType
                next_sync_cycle_start_time_utc = $nextSyncCycleStartTime
            }) `
            -CurrentState $overview `
            -ZeroTrustTarget "Hybrid authentication model should be documented, resilient, and visible. Entra Connect sync evidence should be readable, and federated/PTA architectures should have health and fallback validation." `
            -GapSummary $gap
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "H-A2" `
            -ScenarioName "Password Hash Sync / PTA / Federation Posture Review" `
            -Category "Authentication Security" `
            -Status "ERROR" `
            -Risk "CRITICAL" `
            -Findings @(New-ZTVPFinding -Title "Execution error" -Detail $_.Exception.Message) `
            -Recommendations @(New-ZTVPRecommendation -Title "Fix H-A2 execution issue" -Detail "Confirm Microsoft Graph connectivity and, for full evidence, run from the Entra Connect server with the ADSync module.") `
            -Evidence $null `
            -CurrentState "H-A2 could not complete hybrid authentication model assessment." `
            -ZeroTrustTarget "Hybrid authentication model should be documented and visible." `
            -GapSummary "H-A2 could not be evaluated because execution failed."
    }
}
