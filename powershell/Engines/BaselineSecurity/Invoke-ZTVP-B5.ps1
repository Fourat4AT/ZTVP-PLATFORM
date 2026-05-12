Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Authentication -Force -ErrorAction SilentlyContinue

function Get-B5Value {
    param($Object, [string[]]$Names)

    if ($null -eq $Object) { return $null }

    foreach ($name in $Names) {
        if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($name)) { return $Object[$name] }
        if ($Object.PSObject.Properties[$name]) { return $Object.$name }
        if ($Object.PSObject.Properties["AdditionalProperties"] -and $Object.AdditionalProperties -and $Object.AdditionalProperties.ContainsKey($name)) { return $Object.AdditionalProperties[$name] }
    }

    return $null
}

function ConvertTo-B5Text {
    param($Value)

    if ($null -eq $Value) { return "" }
    return $Value.ToString()
}

function ConvertTo-B5Bool {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -eq $true) { return $true }
    if ($Value -eq $false) { return $false }

    $text = $Value.ToString().ToLowerInvariant()
    if ($text -eq "true") { return $true }
    if ($text -eq "false") { return $false }

    return $null
}

function Invoke-B5GraphCollection {
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

function Get-B5Users {
    $selectWithSignIn = "id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,signInActivity,assignedLicenses,passwordPolicies,onPremisesSyncEnabled"
    $selectBasic = "id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,assignedLicenses,passwordPolicies,onPremisesSyncEnabled"

    try {
        $users = @(Invoke-B5GraphCollection -Uri "https://graph.microsoft.com/v1.0/users?`$select=$selectWithSignIn&`$top=500")
        return [PSCustomObject]@{ Readable = $true; SignInReadable = $true; Error = ""; Users = $users }
    }
    catch {
        $firstError = $_.Exception.Message

        try {
            $users = @(Invoke-B5GraphCollection -Uri "https://graph.microsoft.com/v1.0/users?`$select=$selectBasic&`$top=999")
            return [PSCustomObject]@{ Readable = $true; SignInReadable = $false; Error = $firstError; Users = $users }
        }
        catch {
            return [PSCustomObject]@{ Readable = $false; SignInReadable = $false; Error = $_.Exception.Message; Users = @() }
        }
    }
}

function ConvertTo-B5UserEvidence {
    param($User, [datetime]$Now, [int]$StaleDays)

    $id = ConvertTo-B5Text (Get-B5Value $User @("id", "Id"))
    $displayName = ConvertTo-B5Text (Get-B5Value $User @("displayName", "DisplayName"))
    $upn = ConvertTo-B5Text (Get-B5Value $User @("userPrincipalName", "UserPrincipalName"))
    $userType = ConvertTo-B5Text (Get-B5Value $User @("userType", "UserType"))
    $accountEnabled = ConvertTo-B5Bool (Get-B5Value $User @("accountEnabled", "AccountEnabled"))
    $passwordPolicies = ConvertTo-B5Text (Get-B5Value $User @("passwordPolicies", "PasswordPolicies"))
    $onPremSync = ConvertTo-B5Bool (Get-B5Value $User @("onPremisesSyncEnabled", "OnPremisesSyncEnabled"))

    $assignedLicensesRaw = Get-B5Value $User @("assignedLicenses", "AssignedLicenses")
    $licenseCount = 0

    if ($null -ne $assignedLicensesRaw) {
        $licenseCount = @($assignedLicensesRaw).Count
    }

    $created = $null
    $createdRaw = Get-B5Value $User @("createdDateTime", "CreatedDateTime")

    if ($createdRaw) {
        [datetime]$tmpC = [datetime]::MinValue
        if ([datetime]::TryParse($createdRaw.ToString(), [ref]$tmpC)) {
            $created = $tmpC
        }
    }

    $lastSignIn = $null
    $signInActivity = Get-B5Value $User @("signInActivity", "SignInActivity")

    if ($null -ne $signInActivity) {
        $lastSuccessful = Get-B5Value $signInActivity @("lastSuccessfulSignInDateTime", "LastSuccessfulSignInDateTime")
        $lastSignInRaw = Get-B5Value $signInActivity @("lastSignInDateTime", "LastSignInDateTime")

        $raw = $lastSuccessful
        if (-not $raw) { $raw = $lastSignInRaw }

        if ($raw) {
            [datetime]$tmpS = [datetime]::MinValue
            if ([datetime]::TryParse($raw.ToString(), [ref]$tmpS)) {
                $lastSignIn = $tmpS
            }
        }
    }

    $createdAgeDays = $null
    if ($null -ne $created) {
        $createdAgeDays = [int]($Now - $created).TotalDays
    }

    $lastSignInAgeDays = $null
    if ($null -ne $lastSignIn) {
        $lastSignInAgeDays = [int]($Now - $lastSignIn).TotalDays
    }

    $isGuest = [bool]($userType -eq "Guest")
    $isMember = [bool]($userType -eq "Member")
    $isEnabled = [bool]($accountEnabled -eq $true)
    $isDisabled = [bool]($accountEnabled -eq $false)
    $enabledGuest = [bool]($isEnabled -and $isGuest)
    $unlicensedEnabledMember = [bool]($isEnabled -and $isMember -and $licenseCount -eq 0)
    $staleEnabled = [bool]($isEnabled -and $lastSignInAgeDays -ne $null -and $lastSignInAgeDays -ge $StaleDays)
    $noRecentEvidence = [bool]($isEnabled -and $null -eq $lastSignIn -and $createdAgeDays -ne $null -and $createdAgeDays -ge $StaleDays)
    $disablePwdExpiration = [bool]($passwordPolicies.ToLowerInvariant() -match "disablepasswordexpiration")

    [PSCustomObject]@{
        id = $id
        display_name = $displayName
        user_principal_name = $upn
        user_type = $userType
        account_enabled = $accountEnabled
        created_age_days = $createdAgeDays
        last_sign_in_age_days = $lastSignInAgeDays
        assigned_license_count = $licenseCount
        password_policies = $passwordPolicies
        on_premises_sync_enabled = $onPremSync
        is_guest = $isGuest
        is_member = $isMember
        is_enabled = $isEnabled
        is_disabled = $isDisabled
        enabled_guest = $enabledGuest
        unlicensed_enabled_member = $unlicensedEnabledMember
        stale_enabled_user = $staleEnabled
        no_recent_sign_in_evidence = $noRecentEvidence
        disable_password_expiration = $disablePwdExpiration
    }
}

function Invoke-ZTVP-B5 {
    [CmdletBinding()]
    param([int]$StaleDays = 90)

    Write-Host ""
    Write-Host "=== B5 - User Account Hygiene Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        $usersResult = Get-B5Users

        if (-not $usersResult.Readable) {
            $resultArgs = @{
                ScenarioId      = "B5"
                ScenarioName    = "User Account Hygiene Review"
                Category        = "Baseline Security"
                Status          = "ERROR"
                Risk            = "CRITICAL"
                Findings        = @(New-ZTVPFinding -Title "Users could not be collected" -Detail $usersResult.Error)
                Recommendations = @(New-ZTVPRecommendation -Title "Fix user inventory visibility" -Detail "Confirm Graph permissions allow reading users.")
                Evidence        = $null
                CurrentState    = "User account hygiene evidence was unavailable."
                ZeroTrustTarget = "User accounts should be actively governed and reviewed."
                GapSummary      = "B5 could not be evaluated because user inventory was unavailable."
            }

            return New-ZTVPResult @resultArgs
        }

        $now = Get-Date
        $userEvidence = @()

        foreach ($user in @($usersResult.Users)) {
            if ($null -ne $user) {
                $userEvidence += ConvertTo-B5UserEvidence -User $user -Now $now -StaleDays $StaleDays
            }
        }

        $enabledUsers = @($userEvidence | Where-Object { $_.is_enabled -eq $true })
        $disabledUsers = @($userEvidence | Where-Object { $_.is_disabled -eq $true })
        $guestUsers = @($userEvidence | Where-Object { $_.is_guest -eq $true })
        $enabledGuests = @($userEvidence | Where-Object { $_.enabled_guest -eq $true })
        $staleEnabled = @($userEvidence | Where-Object { $_.stale_enabled_user -eq $true })
        $noRecentEvidence = @($userEvidence | Where-Object { $_.no_recent_sign_in_evidence -eq $true })
        $unlicensedEnabled = @($userEvidence | Where-Object { $_.unlicensed_enabled_member -eq $true })
        $disablePwdExpiration = @($userEvidence | Where-Object { $_.disable_password_expiration -eq $true })

        if (-not $usersResult.SignInReadable) {
            $findings += New-ZTVPFinding -Title "Sign-in activity was not readable" -Detail "B5 collected users, but sign-in activity was unavailable. Stale-account analysis is limited. Error: $($usersResult.Error)"
            $recommendations += New-ZTVPRecommendation -Title "Improve sign-in activity visibility" -Detail "Confirm Graph permissions and licensing allow reading signInActivity."
        }

        if ($staleEnabled.Count -gt 0) {
            $sample = (($staleEnabled | Select-Object -First 15 | ForEach-Object { "$($_.user_principal_name) [$($_.last_sign_in_age_days)d]" }) -join " | ")
            $findings += New-ZTVPFinding -Title "Stale enabled users detected" -Detail "Enabled users have not signed in for at least $StaleDays days. Sample: $sample"
            $recommendations += New-ZTVPRecommendation -Title "Review stale enabled users" -Detail "Disable, remove, or justify enabled accounts that have not signed in recently."
        }

        if ($noRecentEvidence.Count -gt 0) {
            $sample = (($noRecentEvidence | Select-Object -First 15 | ForEach-Object { $_.user_principal_name }) -join " | ")
            $findings += New-ZTVPFinding -Title "Enabled users with no recent sign-in evidence detected" -Detail "Enabled users are older than $StaleDays days but have no readable recent sign-in evidence. Sample: $sample"
            $recommendations += New-ZTVPRecommendation -Title "Review accounts with no sign-in evidence" -Detail "Confirm whether these accounts are unused, service-like, emergency, or still required."
        }

        if ($enabledGuests.Count -gt 0) {
            $recommendations += New-ZTVPRecommendation -Title "Review enabled guest accounts" -Detail "Enabled guest users should have owners, business justification, and periodic access review."
        }

        if ($unlicensedEnabled.Count -gt 0) {
            $sample = (($unlicensedEnabled | Select-Object -First 15 | ForEach-Object { $_.user_principal_name }) -join " | ")
            $findings += New-ZTVPFinding -Title "Enabled unlicensed member accounts detected" -Detail "Enabled member users with no assigned licenses may need review. Sample: $sample"
            $recommendations += New-ZTVPRecommendation -Title "Review enabled unlicensed member accounts" -Detail "Confirm whether unlicensed enabled member accounts are required, service-like, emergency, or should be disabled."
        }

        if ($disablePwdExpiration.Count -gt 0) {
            $recommendations += New-ZTVPRecommendation -Title "Review DisablePasswordExpiration flags" -Detail "Accounts with DisablePasswordExpiration should be justified and monitored."
        }

        $status = "PASS"
        $risk = "LOW"

        if ($staleEnabled.Count -ge 10 -or $noRecentEvidence.Count -ge 10) {
            $status = "FAIL"
            $risk = "HIGH"
        }
        elseif ($staleEnabled.Count -gt 0 -or $noRecentEvidence.Count -gt 0 -or $unlicensedEnabled.Count -gt 0 -or -not $usersResult.SignInReadable) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }

        $overview = @(
            "Users assessed: $($userEvidence.Count)"
            "Enabled users: $($enabledUsers.Count)"
            "Disabled users: $($disabledUsers.Count)"
            "Guest users: $($guestUsers.Count)"
            "Enabled guests: $($enabledGuests.Count)"
            "Stale enabled users: $($staleEnabled.Count)"
            "No recent sign-in evidence: $($noRecentEvidence.Count)"
            "Enabled unlicensed members: $($unlicensedEnabled.Count)"
            "DisablePasswordExpiration users: $($disablePwdExpiration.Count)"
        ) -join "; "

        if ($status -eq "PASS") {
            $summary = "User account hygiene appears controlled. $overview."
            $gap = "No major user account hygiene gap was detected."
        }
        elseif ($status -eq "PARTIAL") {
            $summary = "User account hygiene needs review. $overview."
            $gap = "User account hygiene is partially aligned because stale, unlicensed, guest, or evidence-limited accounts require review."
        }
        else {
            $summary = "User account hygiene has significant exposure. $overview."
            $gap = "User account hygiene is not aligned because many stale or evidence-limited enabled accounts require action."
        }

        $currentState = @(
            "Users assessed: $($userEvidence.Count)."
            "Enabled users: $($enabledUsers.Count)."
            "Disabled users: $($disabledUsers.Count)."
            "Guest users: $($guestUsers.Count)."
            "Enabled guest users: $($enabledGuests.Count)."
            "Sign-in activity readable: $($usersResult.SignInReadable)."
            "Stale threshold days: $StaleDays."
            "Stale enabled users: $($staleEnabled.Count)."
            "Enabled users with no recent sign-in evidence: $($noRecentEvidence.Count)."
            "Enabled unlicensed members: $($unlicensedEnabled.Count)."
            "DisablePasswordExpiration users: $($disablePwdExpiration.Count)."
        ) -join " "

        $resultArgs = @{
            ScenarioId      = "B5"
            ScenarioName    = "User Account Hygiene Review"
            Category        = "Baseline Security"
            Status          = $status
            Risk            = $risk
            Findings        = $findings
            Recommendations = $recommendations
            Evidence        = [PSCustomObject]@{
                executive_summary = $summary
                account_hygiene_overview = $overview
                users_readable = $usersResult.Readable
                sign_in_activity_readable = $usersResult.SignInReadable
                stale_threshold_days = $StaleDays
                user_count = $userEvidence.Count
                enabled_user_count = $enabledUsers.Count
                disabled_user_count = $disabledUsers.Count
                guest_user_count = $guestUsers.Count
                enabled_guest_user_count = $enabledGuests.Count
                stale_enabled_user_count = $staleEnabled.Count
                no_recent_sign_in_evidence_user_count = $noRecentEvidence.Count
                enabled_unlicensed_member_count = $unlicensedEnabled.Count
                disable_password_expiration_user_count = $disablePwdExpiration.Count
                users = $userEvidence
                stale_enabled_users = $staleEnabled
                no_recent_sign_in_evidence_users = $noRecentEvidence
                enabled_unlicensed_members = $unlicensedEnabled
                enabled_guests = $enabledGuests
            }
            CurrentState    = $currentState
            ZeroTrustTarget = "User accounts should be regularly reviewed. Stale enabled accounts, unmanaged guests, unlicensed enabled members, and special password policy flags should be disabled, justified, or monitored."
            GapSummary      = $gap
        }

        return New-ZTVPResult @resultArgs
    }
    catch {
        $resultArgs = @{
            ScenarioId      = "B5"
            ScenarioName    = "User Account Hygiene Review"
            Category        = "Baseline Security"
            Status          = "ERROR"
            Risk            = "CRITICAL"
            Findings        = @(New-ZTVPFinding -Title "Execution error" -Detail $_.Exception.Message)
            Recommendations = @(New-ZTVPRecommendation -Title "Fix B5 execution issue" -Detail "Review Graph permissions for user inventory and sign-in activity evidence.")
            Evidence        = $null
            CurrentState    = "B5 could not complete user account hygiene assessment."
            ZeroTrustTarget = "User accounts should be actively governed and reviewed."
            GapSummary      = "B5 could not be evaluated because execution failed."
        }

        return New-ZTVPResult @resultArgs
    }
}

