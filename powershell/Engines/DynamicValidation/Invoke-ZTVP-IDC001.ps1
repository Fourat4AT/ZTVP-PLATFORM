param(
    [Parameter(Mandatory = $true)]
    [string]$DecoyUserPrincipalName,

    [int]$LookbackMinutes = 240
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "AuditLog.Read.All",
    "Directory.Read.All",
    "User.Read.All",
    "Policy.Read.All"
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
    param(
        [string]$Uri,
        [int]$MaxPages = 20
    )

    $items = @()
    $page = 0
    $nextUri = $Uri

    while ($nextUri -and $page -lt $MaxPages) {
        $page++

        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri
        $value = Get-ZTVPValue -Object $response -Name "value"

        if ($value) {
            $items += @($value)
        }

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

function Get-ZTVPUserId {
    param([string]$UserPrincipalName)

    try {
        $encodedUpn = [System.Uri]::EscapeDataString($UserPrincipalName)
        $uri = "https://graph.microsoft.com/v1.0/users/$encodedUpn?`$select=id,userPrincipalName"
        $user = Invoke-MgGraphRequest -Method GET -Uri $uri
        return [string](Get-ZTVPValue -Object $user -Name "id")
    }
    catch {
        return $null
    }
}

function Get-ZTVPConditionalAccessMfaPolicies {
    $policies = @()

    try {
        $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$top=100"
        $items = @(Invoke-ZTVPPagedGraphQuery -Uri $uri -MaxPages 10)

        foreach ($policy in $items) {
            $id = [string](Get-ZTVPValue -Object $policy -Name "id")
            $name = [string](Get-ZTVPValue -Object $policy -Name "displayName")
            $state = [string](Get-ZTVPValue -Object $policy -Name "state")

            $conditions = Get-ZTVPValue -Object $policy -Name "conditions"
            $users = Get-ZTVPValue -Object $conditions -Name "users"
            $applications = Get-ZTVPValue -Object $conditions -Name "applications"
            $grantControls = Get-ZTVPValue -Object $policy -Name "grantControls"

            $includeUsers = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $users -Name "includeUsers"))
            $excludeUsers = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $users -Name "excludeUsers"))
            $includeGroups = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $users -Name "includeGroups"))
            $excludeGroups = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $users -Name "excludeGroups"))

            $includeApps = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $applications -Name "includeApplications"))
            $excludeApps = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $applications -Name "excludeApplications"))

            $grantJson = ""
            try {
                $grantJson = ($grantControls | ConvertTo-Json -Depth 30 -Compress)
            }
            catch {}

            $hasMfaGrant = $false
            if ($grantJson -match "mfa|multiFactor|requireMultiFactorAuthentication|authenticationStrength") {
                $hasMfaGrant = $true
            }

            if (-not $hasMfaGrant) {
                continue
            }

            $stateLower = $state.Trim().ToLower()

            $mode = "Unknown"
            $enforces = $false
            $reportOnly = $false

            if ($stateLower -eq "enabled") {
                $mode = "Enabled"
                $enforces = $true
            }
            elseif ($stateLower -match "report") {
                $mode = "Report-only"
                $reportOnly = $true
            }
            elseif ($stateLower -eq "disabled") {
                $mode = "Disabled"
            }

            $policies += [PSCustomObject]@{
                id = $id
                displayName = $name
                state = $state
                mode = $mode
                enforces = $enforces
                reportOnly = $reportOnly
                hasMfaGrant = $hasMfaGrant
                targetsAllUsers = ($includeUsers -contains "All")
                targetsAllApps = ($includeApps -contains "All")
                includeUsers = @($includeUsers)
                excludeUsers = @($excludeUsers)
                includeGroups = @($includeGroups)
                excludeGroups = @($excludeGroups)
                includeApplications = @($includeApps)
                excludeApplications = @($excludeApps)
            }
        }
    }
    catch {
        $policies += [PSCustomObject]@{
            id = $null
            displayName = "Unable to read Conditional Access policies"
            state = "Unknown"
            mode = "Error"
            enforces = $false
            reportOnly = $false
            hasMfaGrant = $false
            targetsAllUsers = $false
            targetsAllApps = $false
            includeUsers = @()
            excludeUsers = @()
            includeGroups = @()
            excludeGroups = @()
            includeApplications = @()
            excludeApplications = @()
            error = $_.Exception.Message
        }
    }

    return $policies
}

function Get-ZTVPRecentSignIns {
    param(
        [int]$Top = 1000,
        [int]$MaxPages = 20
    )

    $all = @()
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=$Top"

    try {
        $all = @(Invoke-ZTVPPagedGraphQuery -Uri $uri -MaxPages $MaxPages)
    }
    catch {
        $all = @()
    }

    return $all
}

function Get-ZTVPTargetSignIns {
    param(
        [string]$TargetUpn,
        [string]$TargetUserId,
        [datetime]$StartUtcDate
    )

    $all = @()
    $startUtc = $StartUtcDate.ToString("o")
    $targetLower = $TargetUpn.Trim().ToLower()
    $safeOriginal = $TargetUpn.Replace("'", "''")
    $safeLower = $targetLower.Replace("'", "''")

    $queryUris = @()

    $filter1 = "createdDateTime ge $startUtc and userPrincipalName eq '$safeOriginal'"
    $queryUris += "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$([System.Uri]::EscapeDataString($filter1))"

    if ($safeLower -ne $safeOriginal) {
        $filter2 = "createdDateTime ge $startUtc and userPrincipalName eq '$safeLower'"
        $queryUris += "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$([System.Uri]::EscapeDataString($filter2))"
    }

    if (-not [string]::IsNullOrWhiteSpace($TargetUserId)) {
        $filter3 = "createdDateTime ge $startUtc and userId eq '$TargetUserId'"
        $queryUris += "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$([System.Uri]::EscapeDataString($filter3))"
    }

    foreach ($uri in $queryUris) {
        try {
            $all += @(Invoke-ZTVPPagedGraphQuery -Uri $uri -MaxPages 10)
        }
        catch {}
    }

    $scanned = @(Get-ZTVPRecentSignIns -Top 1000 -MaxPages 20)

    $all += @(
        $scanned | Where-Object {
            $logUpn = ([string](Get-ZTVPValue -Object $_ -Name "userPrincipalName")).Trim().ToLower()
            $logUserId = [string](Get-ZTVPValue -Object $_ -Name "userId")

            (
                $logUpn -eq $targetLower -or
                (
                    -not [string]::IsNullOrWhiteSpace($TargetUserId) -and
                    $logUserId -eq $TargetUserId
                )
            )
        }
    )

    $seen = @{}
    $deduped = @()

    foreach ($item in $all) {
        $id = [string](Get-ZTVPValue -Object $item -Name "id")

        if ([string]::IsNullOrWhiteSpace($id)) {
            $id = ([string](Get-ZTVPValue -Object $item -Name "createdDateTime")) + "|" + ([string](Get-ZTVPValue -Object $item -Name "appDisplayName"))
        }

        if (-not $seen.ContainsKey($id)) {
            $seen[$id] = $true
            $deduped += $item
        }
    }

    return [PSCustomObject]@{
        targetSignIns = @($deduped)
        scannedSignIns = @($scanned)
    }
}

function Convert-ZTVPSignInEvidence {
    param(
        [object[]]$SignIns,
        [datetime]$StartUtcDate
    )

    $rows = @()

    foreach ($signIn in $SignIns) {
        $createdRaw = [string](Get-ZTVPValue -Object $signIn -Name "createdDateTime")
        $withinLookback = $false

        try {
            $createdUtc = ([DateTimeOffset]::Parse($createdRaw)).UtcDateTime
            if ($createdUtc -ge $StartUtcDate) { $withinLookback = $true }
        }
        catch {}

        $isInteractiveRaw = Get-ZTVPValue -Object $signIn -Name "isInteractive"
        $isInteractive = $null

        if ($null -ne $isInteractiveRaw) {
            $isInteractive = [bool]$isInteractiveRaw
        }

        $evidenceType = "Unknown"
        if ($isInteractive -eq $true) { $evidenceType = "Interactive" }
        elseif ($isInteractive -eq $false) { $evidenceType = "NonInteractive" }

        $statusObj = Get-ZTVPValue -Object $signIn -Name "status"
        $statusCode = Get-ZTVPValue -Object $statusObj -Name "errorCode"
        $failureReason = [string](Get-ZTVPValue -Object $statusObj -Name "failureReason")
        $additionalDetails = [string](Get-ZTVPValue -Object $statusObj -Name "additionalDetails")

        $authRequirement = [string](Get-ZTVPValue -Object $signIn -Name "authenticationRequirement")
        $caStatus = [string](Get-ZTVPValue -Object $signIn -Name "conditionalAccessStatus")
        $appDisplayName = [string](Get-ZTVPValue -Object $signIn -Name "appDisplayName")
        $resourceDisplayName = [string](Get-ZTVPValue -Object $signIn -Name "resourceDisplayName")

        $authDetails = Get-ZTVPValue -Object $signIn -Name "authenticationDetails"
        $policies = Get-ZTVPValue -Object $signIn -Name "appliedConditionalAccessPolicies"
        $location = Get-ZTVPValue -Object $signIn -Name "location"

        $authJson = ""
        try { $authJson = ($authDetails | ConvertTo-Json -Depth 30 -Compress) } catch {}

        $policyObjects = @()
        $policySummary = ""
        $anyConditionalAccessApplied = $false
        $conditionalAccessMfaPolicyApplied = $false
        $reportOnlyMfaPolicyMatched = $false
        $caMfaPolicyNames = @()
        $reportOnlyMfaPolicyNames = @()
        $notAppliedPolicyCount = 0

        foreach ($policy in @(ConvertTo-ZTVPArray $policies)) {
            if ($null -eq $policy) { continue }

            $policyName = [string](Get-ZTVPValue -Object $policy -Name "displayName")
            $policyResult = [string](Get-ZTVPValue -Object $policy -Name "result")
            $grantControls = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $policy -Name "enforcedGrantControls"))
            $sessionControls = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $policy -Name "enforcedSessionControls"))

            $policyJson = ""
            try { $policyJson = ($policy | ConvertTo-Json -Depth 30 -Compress) } catch {}

            $resultLower = $policyResult.Trim().ToLower()
            $isNotApplied = ($resultLower -eq "notapplied")
            $isReportOnly = ($resultLower -match "reportonly")
            $isAppliedEnforced = (-not $isNotApplied -and -not $isReportOnly -and -not [string]::IsNullOrWhiteSpace($resultLower))

            if ($isNotApplied) {
                $notAppliedPolicyCount++
            }

            if ($isAppliedEnforced) {
                $anyConditionalAccessApplied = $true
            }

            $hasMfaGrant = $false

            if ("$($grantControls -join ',') $policyJson" -match "mfa|multiFactor|requireMultiFactorAuthentication|authenticationStrength") {
                $hasMfaGrant = $true
            }

            if ($hasMfaGrant -and $isAppliedEnforced) {
                $conditionalAccessMfaPolicyApplied = $true
                if (-not [string]::IsNullOrWhiteSpace($policyName)) {
                    $caMfaPolicyNames += $policyName
                }
            }

            if ($hasMfaGrant -and $isReportOnly) {
                $reportOnlyMfaPolicyMatched = $true
                if (-not [string]::IsNullOrWhiteSpace($policyName)) {
                    $reportOnlyMfaPolicyNames += $policyName
                }
            }

            $policyObjects += [PSCustomObject]@{
                displayName = $policyName
                result = $policyResult
                enforcedGrantControls = @($grantControls)
                enforcedSessionControls = @($sessionControls)
                mfaGrantDetected = $hasMfaGrant
                mfaPolicyApplied = ($hasMfaGrant -and $isAppliedEnforced)
                reportOnlyMfaPolicyMatched = ($hasMfaGrant -and $isReportOnly)
            }
        }

        try {
            $policySummary = (@($policyObjects | ForEach-Object {
                "$($_.displayName) : $($_.result) : $($_.enforcedGrantControls -join ',')"
            }) -join "; ")
        }
        catch {}

        $locationSummary = ""

        try {
            $city = Get-ZTVPValue -Object $location -Name "city"
            $state = Get-ZTVPValue -Object $location -Name "state"
            $country = Get-ZTVPValue -Object $location -Name "countryOrRegion"

            $locationSummary = (@($city, $state, $country) | Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            }) -join ", "
        }
        catch {}

        $authEvidenceOnly = "$authRequirement $authJson $failureReason $additionalDetails $statusCode"
        $statusCodeText = [string]$statusCode

        $registrationOnly = $false
        if (
            $statusCodeText -in @("50072", "50079") -or
            $authEvidenceOnly -match "registration|register.*security|security info|proof.?up|more information required|MFA registration|Authenticator app setup"
        ) {
            $registrationOnly = $true
        }

        $mfaObserved = $false

        if ($authEvidenceOnly -match "multiFactorAuthentication|MFA|mfa|Authenticator|PhoneAppNotification|PhoneAppOTP|FIDO|WindowsHello|OATH|Temporary Access Pass|50076|50074") {
            $mfaObserved = $true
        }

        if ($conditionalAccessMfaPolicyApplied) {
            $mfaObserved = $true
        }

        $success = $false
        if ($statusCode -eq 0 -or [string]$statusCode -eq "0") {
            $success = $true
        }

        $interrupted = $false
        if ($authEvidenceOnly -match "interrupted|additional authentication|multi-factor|registration|required|50076|50079|50074|50072") {
            $interrupted = $true
        }

        $adminResourceAccessed = $false

        if ("$appDisplayName $resourceDisplayName" -match "Azure Portal|Azure Resource Manager|Microsoft 365 admin|Microsoft 365 Admin|Microsoft Entra|Windows Azure Active Directory|OfficeHome|Admin") {
            $adminResourceAccessed = $true
        }

        $mfaObservedForAccess = ($mfaObserved -eq $true -and $registrationOnly -ne $true)
        $passwordOnlyPrivilegedSuccess = $false

        if ($evidenceType -eq "Interactive" -and $success -eq $true -and $adminResourceAccessed -eq $true -and $mfaObservedForAccess -ne $true) {
            $passwordOnlyPrivilegedSuccess = $true
        }

        $rows += [PSCustomObject]@{
            CreatedDateTime = $createdRaw
            WithinLookback = $withinLookback
            EvidenceType = $evidenceType
            IsInteractive = $isInteractive
            UserPrincipalName = Get-ZTVPValue -Object $signIn -Name "userPrincipalName"
            UserDisplayName = Get-ZTVPValue -Object $signIn -Name "userDisplayName"
            AppDisplayName = $appDisplayName
            ResourceDisplayName = $resourceDisplayName
            AdminResourceAccessed = $adminResourceAccessed
            IpAddress = Get-ZTVPValue -Object $signIn -Name "ipAddress"
            Location = $locationSummary
            ClientAppUsed = Get-ZTVPValue -Object $signIn -Name "clientAppUsed"
            AuthenticationRequirement = $authRequirement
            ConditionalAccessStatus = $caStatus
            AppliedConditionalAccess = $policySummary
            ConditionalAccessPolicies = @($policyObjects)
            AnyConditionalAccessApplied = $anyConditionalAccessApplied
            ConditionalAccessMfaPolicyApplied = $conditionalAccessMfaPolicyApplied
            ConditionalAccessMfaPolicyNames = @($caMfaPolicyNames | Sort-Object -Unique)
            ReportOnlyMfaPolicyMatched = $reportOnlyMfaPolicyMatched
            ReportOnlyMfaPolicyNames = @($reportOnlyMfaPolicyNames | Sort-Object -Unique)
            NotAppliedPolicyCount = $notAppliedPolicyCount
            StatusCode = $statusCode
            FailureReason = $failureReason
            AdditionalDetails = $additionalDetails
            Success = $success
            Interrupted = $interrupted
            RegistrationOnly = $registrationOnly
            MfaObserved = $mfaObserved
            MfaObservedForAccess = $mfaObservedForAccess
            PasswordOnlyPrivilegedSuccess = $passwordOnlyPrivilegedSuccess
        }
    }

    return $rows
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$targetUpnOriginal = $DecoyUserPrincipalName.Trim()
$targetUpnLower = $targetUpnOriginal.ToLower()
$targetPrefix = ($targetUpnLower -split "@")[0]
$startUtcDate = (Get-Date).ToUniversalTime().AddMinutes(-1 * $LookbackMinutes)

Write-Host ""
Write-Host "========================================="
Write-Host "ZTVP ID-C-001 - Privileged Access MFA Enforcement Validation"
Write-Host "========================================="
Write-Host ""
Write-Host "Target user: $targetUpnOriginal"
Write-Host "Lookback minutes: $LookbackMinutes"

$userId = Get-ZTVPUserId -UserPrincipalName $targetUpnOriginal

Write-Host "Target user ID: $userId"
Write-Host "Reading Conditional Access MFA policies..."
$configuredMfaPolicies = @(Get-ZTVPConditionalAccessMfaPolicies)

$enabledConfiguredMfaPolicies = @(
    $configuredMfaPolicies | Where-Object {
        $_.enforces -eq $true -and $_.hasMfaGrant -eq $true
    }
)

$reportOnlyConfiguredMfaPolicies = @(
    $configuredMfaPolicies | Where-Object {
        $_.reportOnly -eq $true -and $_.hasMfaGrant -eq $true
    }
)

Write-Host "Configured MFA CA policies: $($configuredMfaPolicies.Count)"
Write-Host "Enabled MFA CA policies: $($enabledConfiguredMfaPolicies.Count)"
Write-Host "Report-only MFA CA policies: $($reportOnlyConfiguredMfaPolicies.Count)"

Write-Host "Collecting sign-in evidence..."
$queryResult = Get-ZTVPTargetSignIns -TargetUpn $targetUpnOriginal -TargetUserId $userId -StartUtcDate $startUtcDate

$targetSignIns = @($queryResult.targetSignIns)
$scannedSignIns = @($queryResult.scannedSignIns)

$nearMatches = @(
    $scannedSignIns | Where-Object {
        $logUpn = ([string](Get-ZTVPValue -Object $_ -Name "userPrincipalName")).Trim().ToLower()
        $logUpn -like "$targetPrefix*"
    } | Select-Object -First 20
)

$evidenceRowsAll = @(Convert-ZTVPSignInEvidence -SignIns $targetSignIns -StartUtcDate $startUtcDate)

$evidenceRows = @(
    $evidenceRowsAll | Where-Object {
        $_.WithinLookback -eq $true
    }
)

$interactiveRows = @($evidenceRows | Where-Object { $_.EvidenceType -eq "Interactive" })
$nonInteractiveRows = @($evidenceRows | Where-Object { $_.EvidenceType -eq "NonInteractive" })
$interactiveRegistrationOnly = @($interactiveRows | Where-Object { $_.RegistrationOnly -eq $true })
$interactiveMfa = @($interactiveRows | Where-Object { $_.MfaObservedForAccess -eq $true })
$interactiveInterrupted = @($interactiveRows | Where-Object { $_.Interrupted -eq $true -and $_.RegistrationOnly -ne $true })
$passwordOnlyPrivilegedSuccess = @($interactiveRows | Where-Object { $_.PasswordOnlyPrivilegedSuccess -eq $true })
$interactiveAdminAccess = @($interactiveRows | Where-Object { $_.AdminResourceAccessed -eq $true })
$interactiveCaApplied = @($interactiveRows | Where-Object { $_.AnyConditionalAccessApplied -eq $true })
$interactiveCaMfaApplied = @($interactiveRows | Where-Object { $_.ConditionalAccessMfaPolicyApplied -eq $true })
$nonInteractiveMfa = @($nonInteractiveRows | Where-Object { $_.MfaObservedForAccess -eq $true })

$caMfaNames = @()
$reportOnlyNames = @()

foreach ($row in $evidenceRows) {
    if ($row.ConditionalAccessMfaPolicyNames) {
        $caMfaNames += @($row.ConditionalAccessMfaPolicyNames)
    }

    if ($row.ReportOnlyMfaPolicyNames) {
        $reportOnlyNames += @($row.ReportOnlyMfaPolicyNames)
    }
}

$caMfaNames = @($caMfaNames | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
$reportOnlyNames = @($reportOnlyNames | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)

$warnings = @()
$evidenceQuality = "Unknown"
$mfaSource = "Unknown"
$finalClaim = ""

if ($passwordOnlyPrivilegedSuccess.Count -gt 0) {
    $status = "FAIL"
    $risk = "HIGH"
    $evidenceQuality = "High Risk"
    $mfaSource = "No MFA evidence for successful privileged admin access"
    $summary = "The tenant allowed an interactive privileged admin-resource sign-in without MFA evidence."
    $finalClaim = "Privileged password-only access was not prevented during this controlled validation."
}
elseif ($interactiveRegistrationOnly.Count -gt 0 -and $interactiveMfa.Count -eq 0 -and $interactiveInterrupted.Count -eq 0) {
    $status = "PARTIAL_REGISTRATION_ONLY"
    $risk = "MEDIUM"
    $evidenceQuality = "Setup Only"
    $mfaSource = "MFA/security info registration only"
    $summary = "Only initial MFA or security-info registration evidence was found. Registration setup does not prove MFA enforcement for privileged access."
    $finalClaim = "Complete registration, sign out, then sign in again to an admin resource to validate MFA enforcement."
    $warnings += "Initial MFA/security-info registration was detected. ZTVP does not count registration-only evidence as a clean MFA enforcement PASS."
}
elseif ($interactiveMfa.Count -gt 0 -and $interactiveAdminAccess.Count -gt 0) {
    $status = "PASS_STRONG"
    $risk = "LOW"
    $evidenceQuality = "Strong"

    if ($caMfaNames.Count -gt 0) {
        $mfaSource = "Conditional Access MFA grant"
        $summary = "The tenant prevented password-only privileged access. Interactive admin-resource sign-in evidence was found and MFA enforcement was observed with Conditional Access attribution."
    }
    else {
        $mfaSource = "MFA enforced, policy source unclear"
        $summary = "The tenant prevented password-only privileged access. Interactive admin-resource sign-in evidence was found and MFA evidence was observed."
        $warnings += "MFA evidence was observed, but the exact enforcing Conditional Access policy was not clearly attributable in the sign-in record."
    }

    $finalClaim = "The controlled privileged decoy user did not obtain admin-resource access with password-only authentication."
}
elseif ($interactiveMfa.Count -gt 0) {
    $status = "PASS_STRONG"
    $risk = "LOW"
    $evidenceQuality = "Strong"
    $mfaSource = if ($caMfaNames.Count -gt 0) { "Conditional Access MFA grant" } else { "MFA enforced, policy source unclear" }
    $summary = "Interactive sign-in evidence was found and MFA evidence was observed for the privileged decoy user."
    $finalClaim = "The tenant enforced MFA during the controlled privileged sign-in."
}
elseif ($interactiveInterrupted.Count -gt 0) {
    $status = "PASS_CHALLENGED"
    $risk = "LOW"
    $evidenceQuality = "Strong"
    $mfaSource = "Challenge or interruption observed"
    $summary = "Interactive sign-in evidence shows the privileged decoy user was challenged or interrupted before access."
    $finalClaim = "The tenant did not allow a clean password-only privileged sign-in during this controlled validation."
}
elseif ($interactiveRows.Count -gt 0) {
    $status = "PARTIAL_INTERACTIVE_NO_MFA_EVIDENCE"
    $risk = "MEDIUM"
    $evidenceQuality = "Partial"
    $mfaSource = "Unclear"
    $summary = "Interactive sign-in evidence was found, but MFA enforcement evidence was not clearly observed."
    $finalClaim = "The test produced interactive sign-in evidence, but MFA enforcement could not be proven from the retrieved log fields."
}
elseif ($nonInteractiveRows.Count -gt 0 -and $nonInteractiveMfa.Count -gt 0) {
    $status = "PARTIAL_CORROBORATED"
    $risk = "MEDIUM"
    $evidenceQuality = "Supporting"
    $mfaSource = "Supporting non-interactive evidence"
    $summary = "Only non-interactive sign-in evidence was found, but it contains MFA or Conditional Access-related evidence."
    $finalClaim = "Supporting evidence exists, but a fresh interactive privileged sign-in should be repeated for a strong validation result."
}
elseif ($nonInteractiveRows.Count -gt 0) {
    $status = "PARTIAL_NONINTERACTIVE_ONLY"
    $risk = "MEDIUM"
    $evidenceQuality = "Supporting"
    $mfaSource = "No interactive MFA proof"
    $summary = "Only non-interactive sign-in evidence was found for the decoy user. These are background token or SSO events."
    $finalClaim = "The test did not produce interactive proof of privileged MFA enforcement."
}
elseif ($evidenceRowsAll.Count -gt 0) {
    $status = "PARTIAL_OUTSIDE_WINDOW"
    $risk = "MEDIUM"
    $evidenceQuality = "Partial"
    $mfaSource = "Outside selected lookback"
    $summary = "Sign-ins for the decoy user were found, but none were inside the selected lookback window."
    $finalClaim = "Increase the lookback window or repeat the controlled sign-in."
}
else {
    if ($enabledConfiguredMfaPolicies.Count -gt 0) {
        $status = "NO_SIGNIN_EVIDENCE_POLICY_CONFIGURED"
        $risk = "MEDIUM"
        $summary = "MFA Conditional Access policy configuration was found, but no sign-in evidence was found for the exact decoy user."
        $mfaSource = "Configured policy exists, no telemetry proof yet"
        $finalClaim = "The tenant appears configured for MFA enforcement, but this run cannot validate enforcement without a sign-in log for the exact decoy account."
    }
    elseif ($reportOnlyConfiguredMfaPolicies.Count -gt 0) {
        $status = "NO_SIGNIN_EVIDENCE_REPORT_ONLY_POLICY"
        $risk = "MEDIUM"
        $summary = "A report-only MFA Conditional Access policy was found, but no sign-in evidence was found for the exact decoy user."
        $mfaSource = "Report-only policy only"
        $finalClaim = "Report-only Conditional Access does not prove enforcement. A real sign-in event is still required."
        $warnings += "At least one MFA Conditional Access policy is in report-only mode. Report-only policies evaluate and report but do not enforce access controls."
    }
    else {
        $status = "NO_EVIDENCE"
        $risk = "MEDIUM"
        $summary = "No sign-in evidence and no enabled MFA Conditional Access policy configuration were found by this probe."
        $mfaSource = "No sign-in evidence found"
        $finalClaim = "The validation could not prove whether privileged password-only access was prevented."
    }

    $evidenceQuality = "None"
}

if ($reportOnlyConfiguredMfaPolicies.Count -gt 0) {
    $warnings += "Report-only MFA policy configuration was detected. ZTVP will not treat report-only policy data as enforcement."
}

$policyAttribution = [PSCustomObject]@{
    mfa_source = $mfaSource
    conditional_access_mfa_policy_applied = ($caMfaNames.Count -gt 0)
    conditional_access_mfa_policy_names = @($caMfaNames)
    report_only_mfa_policy_names = @($reportOnlyNames)
    configured_enabled_mfa_policy_count = $enabledConfiguredMfaPolicies.Count
    configured_report_only_mfa_policy_count = $reportOnlyConfiguredMfaPolicies.Count
    interactive_ca_applied_count = $interactiveCaApplied.Count
    interactive_ca_mfa_applied_count = $interactiveCaMfaApplied.Count
    interpretation = if ($caMfaNames.Count -gt 0) {
        "MFA was observed and an applied Conditional Access policy contained an MFA grant/control."
    }
    elseif ($interactiveMfa.Count -gt 0) {
        "MFA was observed, but the enforcing source could not be conclusively attributed to a specific applied Conditional Access policy."
    }
    elseif ($interactiveRegistrationOnly.Count -gt 0) {
        "Only initial MFA/security-info registration was observed. A second post-registration sign-in is required to prove enforcement."
    }
    elseif ($enabledConfiguredMfaPolicies.Count -gt 0) {
        "An enabled MFA Conditional Access policy exists, but no matching decoy sign-in telemetry was found for this run."
    }
    elseif ($reportOnlyConfiguredMfaPolicies.Count -gt 0) {
        "Only report-only MFA Conditional Access configuration was detected. This does not prove enforcement."
    }
    else {
        "Policy attribution could not be determined from the retrieved evidence."
    }
}

$result = [PSCustomObject]@{
    scenario_id = "ID-C-001"
    scenario_name = "Privileged Access MFA Enforcement Validation"
    pillar = "Identity"
    scope = "Cloud"
    generated_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    connected_account = $ctx.Account

    control_tested = "Privileged users must not access administrative resources using password-only authentication."
    expected_result = "The privileged decoy sign-in should be challenged for MFA, blocked, or interrupted before admin-resource access is granted."
    failure_condition = "A privileged decoy user reaches Azure Portal or an administrative resource successfully without MFA evidence."
    test_method = "Fresh decoy privileged identity, controlled interactive sign-in, Microsoft Entra sign-in telemetry, MFA and Conditional Access evidence classification."
    final_claim = $finalClaim

    status = $status
    risk = $risk
    evidence_quality = $evidenceQuality
    target_user = $targetUpnOriginal
    target_user_id = $userId
    lookback_minutes = $LookbackMinutes
    executive_summary = $summary
    validation_explanation = "ZTVP validates actual enforcement using sign-in telemetry. Conditional Access configuration is shown separately from proof of enforcement."
    warnings = @($warnings)
    policy_attribution = $policyAttribution
    configured_mfa_policies = @($configuredMfaPolicies)

    metrics = [PSCustomObject]@{
        graph_signins_scanned = $scannedSignIns.Count
        near_decoy_prefix_matches = $nearMatches.Count
        target_signins_total_retrieved = $evidenceRowsAll.Count
        target_signins_inside_lookback = $evidenceRows.Count
        interactive_signins_count = $interactiveRows.Count
        interactive_registration_only_count = $interactiveRegistrationOnly.Count
        noninteractive_signins_count = $nonInteractiveRows.Count
        interactive_admin_resource_access_count = $interactiveAdminAccess.Count
        interactive_mfa_evidence_count = $interactiveMfa.Count
        interactive_interrupted_count = $interactiveInterrupted.Count
        interactive_ca_applied_count = $interactiveCaApplied.Count
        interactive_ca_mfa_applied_count = $interactiveCaMfaApplied.Count
        configured_enabled_mfa_policy_count = $enabledConfiguredMfaPolicies.Count
        configured_report_only_mfa_policy_count = $reportOnlyConfiguredMfaPolicies.Count
        noninteractive_mfa_evidence_count = $nonInteractiveMfa.Count
        password_only_privileged_success_count = $passwordOnlyPrivilegedSuccess.Count
        successful_interactive_without_mfa_count = $passwordOnlyPrivilegedSuccess.Count
        mfa_evidence_count = ($interactiveMfa.Count + $nonInteractiveMfa.Count)
        successful_without_mfa_count = $passwordOnlyPrivilegedSuccess.Count
    }

    evidence = @($evidenceRows)
    all_target_evidence_retrieved = @($evidenceRowsAll)

    diagnostic = [PSCustomObject]@{
        scanned_signins = $scannedSignIns.Count
        target_user_id = $userId
        target_prefix = $targetPrefix
        near_decoy_prefix_matches = @(
            $nearMatches | ForEach-Object {
                [PSCustomObject]@{
                    createdDateTime = Get-ZTVPValue -Object $_ -Name "createdDateTime"
                    userPrincipalName = Get-ZTVPValue -Object $_ -Name "userPrincipalName"
                    appDisplayName = Get-ZTVPValue -Object $_ -Name "appDisplayName"
                    resourceDisplayName = Get-ZTVPValue -Object $_ -Name "resourceDisplayName"
                    isInteractive = Get-ZTVPValue -Object $_ -Name "isInteractive"
                    status = Get-ZTVPValue -Object $_ -Name "status"
                }
            }
        )
    }
}

$reportDir = Join-Path (Get-Location) "powershell\Reports\Dynamic"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

$outPath = Join-Path $reportDir "ID-C-001-result.json"

$result |
    ConvertTo-Json -Depth 100 |
    Set-Content -Path $outPath -Encoding UTF8

Write-Host ""
Write-Host "========================================="
Write-Host "ID-C-001 COMPLETED"
Write-Host "========================================="
Write-Host ""
Write-Host "Status: $status"
Write-Host "Risk: $risk"
Write-Host "Evidence quality: $evidenceQuality"
Write-Host "MFA source: $mfaSource"
Write-Host "Configured MFA CA policies: $($configuredMfaPolicies.Count)"
Write-Host "Enabled MFA CA policies: $($enabledConfiguredMfaPolicies.Count)"
Write-Host "Report-only MFA CA policies: $($reportOnlyConfiguredMfaPolicies.Count)"
Write-Host "Graph sign-ins scanned: $($scannedSignIns.Count)"
Write-Host "Target sign-ins in lookback: $($evidenceRows.Count)"
Write-Host "Interactive sign-ins: $($interactiveRows.Count)"
Write-Host "Password-only privileged success: $($passwordOnlyPrivilegedSuccess.Count)"
Write-Host "Report saved to: $outPath"
Write-Host ""
