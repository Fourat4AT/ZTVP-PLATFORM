Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Authentication -Force -ErrorAction SilentlyContinue

function Invoke-HA1GraphCollection {
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

function Get-HA1MethodClass {
    param([string]$ODataType)

    if ([string]::IsNullOrWhiteSpace($ODataType)) {
        return "Unknown"
    }

    $t = $ODataType.ToLowerInvariant()

    if ($t -match "fido2" -or
        $t -match "windowshelloforbusiness" -or
        $t -match "microsoftauthenticator" -or
        $t -match "temporaryaccesspass" -or
        $t -match "x509certificate" -or
        $t -match "softwareoath") {
        return "Strong"
    }

    if ($t -match "phone" -or
        $t -match "email" -or
        $t -match "password") {
        return "WeakOrRecovery"
    }

    return "Other"
}

function Invoke-ZTVP-HA1 {
    [CmdletBinding()]
    param(
        [int]$MaxUsers = 200
    )

    Write-Host ""
    Write-Host "=== H-A1 - Hybrid Authentication Method Alignment Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        $usersReadable = $false
        $usersError = ""
        $syncedUsers = @()

        $uri = "https://graph.microsoft.com/v1.0/users?`$top=999&`$select=id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled,onPremisesSamAccountName,onPremisesSecurityIdentifier,onPremisesLastSyncDateTime&`$filter=onPremisesSyncEnabled eq true and accountEnabled eq true"

        try {
            $syncedUsers = @(Invoke-HA1GraphCollection -Uri $uri | Select-Object -First $MaxUsers)
            $usersReadable = $true
        }
        catch {
            $usersReadable = $false
            $usersError = $_.Exception.Message
        }

        $methodEvidence = @()
        $methodReadErrors = @()

        foreach ($user in $syncedUsers) {
            $methods = @()
            $methodReadable = $true
            $methodError = ""

            try {
                $methodResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)/authentication/methods" -ErrorAction Stop
                $methods = @($methodResponse.value)
            }
            catch {
                $methodReadable = $false
                $methodError = $_.Exception.Message

                $methodReadErrors += [PSCustomObject]@{
                    user_principal_name = $user.userPrincipalName
                    display_name = $user.displayName
                    error = $methodError
                }
            }

            $methodTypes = @()
            $strongMethods = @()
            $weakOrRecoveryMethods = @()
            $otherMethods = @()

            foreach ($m in $methods) {
                $odata = ""

                if ($m.'@odata.type') {
                    $odata = $m.'@odata.type'
                }

                $class = Get-HA1MethodClass -ODataType $odata
                $methodTypes += $odata

                if ($class -eq "Strong") {
                    $strongMethods += $odata
                }
                elseif ($class -eq "WeakOrRecovery") {
                    $weakOrRecoveryMethods += $odata
                }
                else {
                    $otherMethods += $odata
                }
            }

            $methodEvidence += [PSCustomObject]@{
                user_principal_name = $user.userPrincipalName
                display_name = $user.displayName
                onprem_sam_account_name = $user.onPremisesSamAccountName
                onprem_security_identifier = $user.onPremisesSecurityIdentifier
                last_sync = $user.onPremisesLastSyncDateTime
                method_readable = $methodReadable
                method_count = $methods.Count
                strong_method_count = $strongMethods.Count
                weak_or_recovery_method_count = $weakOrRecoveryMethods.Count
                other_method_count = $otherMethods.Count
                has_strong_method = [bool]($strongMethods.Count -gt 0)
                has_only_weak_or_recovery = [bool]($strongMethods.Count -eq 0 -and $weakOrRecoveryMethods.Count -gt 0)
                method_types = $methodTypes
                strong_methods = $strongMethods
                weak_or_recovery_methods = $weakOrRecoveryMethods
                other_methods = $otherMethods
            }
        }

        $strongUsers = @($methodEvidence | Where-Object { $_.method_readable -eq $true -and $_.strong_method_count -gt 0 })
        $missingStrong = @($methodEvidence | Where-Object { $_.method_readable -eq $true -and $_.strong_method_count -eq 0 })
        $onlyWeakOrRecovery = @($methodEvidence | Where-Object { $_.method_readable -eq $true -and $_.has_only_weak_or_recovery -eq $true })

        if (-not $usersReadable) {
            $findings += New-ZTVPFinding -Title "Synced users could not be read" -Detail $usersError
            $recommendations += New-ZTVPRecommendation -Title "Fix synced-user visibility" -Detail "Confirm Graph permissions allow reading users and on-premises sync properties."
        }
        elseif ($syncedUsers.Count -eq 0) {
            $findings += New-ZTVPFinding -Title "No enabled synced users detected" -Detail "No enabled users with onPremisesSyncEnabled=true were returned."
            $recommendations += New-ZTVPRecommendation -Title "Confirm hybrid user sync" -Detail "Confirm Entra Connect is syncing users and that enabled synced users exist in the tenant."
        }

        if ($methodReadErrors.Count -gt 0) {
            $findings += New-ZTVPFinding -Title "Authentication method evidence is incomplete" -Detail "$($methodReadErrors.Count) synced user(s) had unreadable authentication method evidence."
            $recommendations += New-ZTVPRecommendation -Title "Fix authentication method visibility" -Detail "Use an account and Graph permission set that can read user authentication methods."
        }

        if ($missingStrong.Count -gt 0) {
            $findings += New-ZTVPFinding -Title "Synced users without strong authentication method evidence" -Detail "$($missingStrong.Count) of $($methodEvidence.Count) enabled synced user(s) do not have strong cloud authentication method evidence."
            $recommendations += New-ZTVPRecommendation -Title "Register strong methods for synced users" -Detail "Start with privileged and high-impact synced users. Use Microsoft Authenticator, FIDO2/passkeys, Windows Hello for Business, TAP, certificate-based authentication, or equivalent."
        }

        if ($onlyWeakOrRecovery.Count -gt 0) {
            $recommendations += New-ZTVPRecommendation -Title "Reduce weak or recovery-only method reliance" -Detail "$($onlyWeakOrRecovery.Count) synced user(s) appear to have only password, SMS, voice, email, or recovery-style method evidence. Move them to stronger methods."
        }

        $status = "PASS"
        $risk = "LOW"

        if (-not $usersReadable -or $methodReadErrors.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }
        elseif ($syncedUsers.Count -eq 0) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }
        elseif ($missingStrong.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }

        $strongCount = $strongUsers.Count
        $missingStrongCount = $missingStrong.Count

        if ($status -eq "PASS") {
            $summary = "$($syncedUsers.Count) enabled synced user(s) were assessed. All assessed synced users have strong cloud authentication method evidence."
            $gap = "No major hybrid authentication method alignment gap was detected."
        }
        elseif (-not $usersReadable) {
            $summary = "H-A1 could not read enabled synced users from Entra ID."
            $gap = "Hybrid authentication method posture could not be confirmed because synced user evidence was unavailable."
        }
        elseif ($methodReadErrors.Count -gt 0) {
            $summary = "$($syncedUsers.Count) enabled synced user(s) were found, but authentication method evidence was incomplete for $($methodReadErrors.Count) user(s)."
            $gap = "Hybrid authentication method posture is partially aligned, but evidence visibility needs correction."
        }
        elseif ($syncedUsers.Count -eq 0) {
            $summary = "No enabled synced users were detected. Confirm whether this tenant has active hybrid users."
            $gap = "Hybrid authentication method posture could not be validated because no enabled synced users were detected."
        }
        else {
            $summary = "$($syncedUsers.Count) enabled synced user(s) were assessed. $strongCount have strong authentication method evidence and $missingStrongCount are missing strong method evidence."
            $gap = "Hybrid authentication method posture is partially aligned because some enabled synced users are missing strong authentication method evidence."
        }

        $overview = @(
            "Synced users assessed: $($syncedUsers.Count)"
            "Users with strong methods: $($strongUsers.Count)"
            "Users missing strong methods: $($missingStrong.Count)"
            "Users with only weak/recovery method evidence: $($onlyWeakOrRecovery.Count)"
            "Method read errors: $($methodReadErrors.Count)"
        ) -join "; "

        return New-ZTVPResult `
            -ScenarioId "H-A1" `
            -ScenarioName "Hybrid Authentication Method Alignment Review" `
            -Category "Authentication Security" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary = $summary
                hybrid_authentication_overview = $overview
                synced_user_count = $syncedUsers.Count
                method_evidence_count = $methodEvidence.Count
                users_with_strong_method_count = $strongUsers.Count
                users_missing_strong_method_count = $missingStrong.Count
                users_only_weak_or_recovery_method_count = $onlyWeakOrRecovery.Count
                method_read_error_count = $methodReadErrors.Count
                synced_user_method_evidence = $methodEvidence
                users_with_strong_methods = $strongUsers
                users_missing_strong_methods = $missingStrong
                users_only_weak_or_recovery_methods = $onlyWeakOrRecovery
                method_read_errors = $methodReadErrors
            }) `
            -CurrentState $overview `
            -ZeroTrustTarget "Enabled synced users should have strong cloud authentication methods. Privileged or high-impact synced users should not rely only on password, SMS, voice, email, or recovery-style methods." `
            -GapSummary $gap
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "H-A1" `
            -ScenarioName "Hybrid Authentication Method Alignment Review" `
            -Category "Authentication Security" `
            -Status "ERROR" `
            -Risk "CRITICAL" `
            -Findings @(New-ZTVPFinding -Title "Execution error" -Detail $_.Exception.Message) `
            -Recommendations @(New-ZTVPRecommendation -Title "Fix H-A1 execution issue" -Detail "Confirm Microsoft Graph connectivity and permissions for users and authentication methods.") `
            -Evidence $null `
            -CurrentState "H-A1 could not complete hybrid authentication method assessment." `
            -ZeroTrustTarget "Synced users should have strong cloud authentication methods." `
            -GapSummary "H-A1 could not be evaluated because execution failed."
    }
}
