Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Authentication -Force -ErrorAction SilentlyContinue

function Get-B4Value {
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

function ConvertTo-B4Bool {
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

function ConvertTo-B4Text {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return $Value.ToString()
}

function Get-B4SafeGraph {
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

function Get-B4AuthenticationMethodConfigurations {
    param($Policy)

    $configs = @(Get-B4Value $Policy @("authenticationMethodConfigurations", "AuthenticationMethodConfigurations"))

    if ($configs.Count -gt 0) {
        return $configs
    }

    return @()
}

function ConvertTo-B4MethodEvidence {
    param($Method)

    $id = ConvertTo-B4Text (Get-B4Value $Method @("id", "Id"))
    $state = ConvertTo-B4Text (Get-B4Value $Method @("state", "State"))
    $odataType = ConvertTo-B4Text (Get-B4Value $Method @("@odata.type", "ODataType"))

    $idLower = $id.ToLowerInvariant()
    $stateLower = $state.ToLowerInvariant()

    $enabled = [bool]($stateLower -eq "enabled")

    $class = "Other"
    $reason = "Review configuration."

    if ($idLower -match "fido2" -or $idLower -match "windowshelloforbusiness" -or $idLower -match "certificate" -or $idLower -match "temporaryaccesspass" -or $idLower -match "microsoftauthenticator") {
        $class = "Strong"
        $reason = "Modern or strong authentication method."
    }
    elseif ($idLower -match "sms" -or $idLower -match "voice" -or $idLower -match "email") {
        $class = "Review"
        $reason = "Recovery or weaker method. Keep limited and justified."
    }

    return [PSCustomObject]@{
        id            = $id
        state         = $state
        enabled       = $enabled
        method_class  = $class
        odata_type    = $odataType
        review_reason = $reason
    }
}

function Invoke-ZTVP-B4 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== B4 - Password and Account Protection Baseline Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        $authz = Get-B4SafeGraph "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
        $methodsPolicy = Get-B4SafeGraph "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"

        if (-not $authz.Readable) {
            $findings += New-ZTVPFinding -Title "SSPR evidence unavailable" -Detail "Authorization policy could not be read."
            $recommendations += New-ZTVPRecommendation -Title "Fix SSPR evidence visibility" -Detail "Confirm Graph permissions allow reading authorization policy."
        }

        if (-not $methodsPolicy.Readable) {
            $findings += New-ZTVPFinding -Title "Authentication Methods Policy unavailable" -Detail "Authentication Methods Policy could not be read."
            $recommendations += New-ZTVPRecommendation -Title "Fix Authentication Methods Policy visibility" -Detail "Confirm Graph permissions allow reading authenticationMethodsPolicy."
        }

        $ssprAllowed = $null

        if ($authz.Readable) {
            $ssprAllowed = ConvertTo-B4Bool (Get-B4Value $authz.Value @("allowedToUseSSPR", "AllowedToUseSSPR"))
        }

        $methodConfigs = @()

        if ($methodsPolicy.Readable) {
            $methodConfigs = @(Get-B4AuthenticationMethodConfigurations -Policy $methodsPolicy.Value)
        }

        $methodEvidence = @()

        foreach ($method in @($methodConfigs)) {
            if ($null -ne $method) {
                $methodEvidence += ConvertTo-B4MethodEvidence -Method $method
            }
        }

        $enabledMethods = @($methodEvidence | Where-Object { $_.enabled -eq $true })
        $strongMethods = @($enabledMethods | Where-Object { $_.method_class -eq "Strong" })
        $reviewMethods = @($enabledMethods | Where-Object { $_.method_class -eq "Review" })

        if ($ssprAllowed -eq $false) {
            $findings += New-ZTVPFinding -Title "SSPR is not enabled for users" -Detail "Users are not allowed to use self-service password reset."
            $recommendations += New-ZTVPRecommendation -Title "Enable or justify SSPR posture" -Detail "Enable SSPR where appropriate, or document the controlled alternative recovery process."
        }
        elseif ($ssprAllowed -eq $true) {
            $recommendations += New-ZTVPRecommendation -Title "Validate SSPR recovery controls" -Detail "SSPR is allowed. Confirm recovery methods, registration coverage, and helpdesk process are appropriate."
        }
        else {
            $findings += New-ZTVPFinding -Title "SSPR state is unknown" -Detail "B4 could not confirm whether users can use SSPR."
            $recommendations += New-ZTVPRecommendation -Title "Confirm SSPR state" -Detail "Check SSPR configuration in Entra admin center."
        }

        if ($methodsPolicy.Readable -and $methodEvidence.Count -eq 0) {
            $findings += New-ZTVPFinding -Title "Authentication method configuration evidence is incomplete" -Detail "Authentication Methods Policy was readable, but method configuration entries were not returned in the policy response."
            $recommendations += New-ZTVPRecommendation -Title "Confirm authentication methods manually" -Detail "Check Entra Authentication Methods to confirm enabled methods such as Microsoft Authenticator, FIDO2/passkeys, WHfB, CBA, TAP, SMS, voice, and email."
        }

        if ($reviewMethods.Count -gt 0) {
            $findings += New-ZTVPFinding -Title "Weaker or recovery methods require review" -Detail ("Enabled methods requiring review: " + (($reviewMethods | ForEach-Object { $_.id }) -join ", "))
            $recommendations += New-ZTVPRecommendation -Title "Review weaker or recovery-oriented methods" -Detail "SMS, voice, or email-based methods should be limited, justified, and monitored."
        }

        $status = "PASS"
        $risk = "LOW"

        if (-not $authz.Readable -or -not $methodsPolicy.Readable) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }
        elseif ($ssprAllowed -eq $false) {
            $status = "FAIL"
            $risk = "HIGH"
        }
        elseif ($methodEvidence.Count -eq 0 -or $ssprAllowed -eq $null) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }
        elseif ($reviewMethods.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }

        if ($status -eq "PASS") {
            $summary = "Password and account recovery baseline appears controlled. SSPR is allowed and authentication method policy evidence was collected."
            $gap = "No major password or account recovery baseline gap was detected."
        }
        elseif ($status -eq "PARTIAL") {
            $summary = "Password and account recovery baseline needs review. SSPR is allowed, but authentication method evidence or weaker recovery methods require validation."
            $gap = "Password and account recovery posture is partially aligned and needs validation."
        }
        else {
            $summary = "Password and account recovery baseline has a gap. SSPR or recovery control posture is not adequately confirmed."
            $gap = "Password and account recovery posture is not aligned."
        }

        $overview = @(
            "SSPR allowed: $ssprAllowed"
            "Authentication Methods Policy readable: $($methodsPolicy.Readable)"
            "Methods assessed: $($methodEvidence.Count)"
            "Enabled methods: $($enabledMethods.Count)"
            "Strong enabled methods: $($strongMethods.Count)"
            "Methods requiring review: $($reviewMethods.Count)"
        ) -join "; "

        $currentState = @(
            "Users allowed to use SSPR: $ssprAllowed."
            "Authentication Methods Policy readable: $($methodsPolicy.Readable)."
            "Authentication methods assessed: $($methodEvidence.Count)."
            "Enabled authentication methods: $($enabledMethods.Count)."
            "Strong enabled methods: $($strongMethods.Count)."
            "Enabled methods requiring review: $($reviewMethods.Count)."
        ) -join " "

        $resultArgs = @{
            ScenarioId      = "B4"
            ScenarioName    = "Password and Account Protection Baseline Review"
            Category        = "Baseline Security"
            Status          = $status
            Risk            = $risk
            Findings        = $findings
            Recommendations = $recommendations
            Evidence        = [PSCustomObject]@{
                executive_summary = $summary
                password_account_overview = $overview

                users_allowed_to_use_sspr = $ssprAllowed
                authentication_methods_policy_readable = $methodsPolicy.Readable

                authentication_method_count = $methodEvidence.Count
                enabled_authentication_method_count = $enabledMethods.Count
                enabled_strong_authentication_method_count = $strongMethods.Count
                enabled_review_authentication_method_count = $reviewMethods.Count

                authentication_methods = $methodEvidence
                enabled_authentication_methods = $enabledMethods
                enabled_strong_authentication_methods = $strongMethods
                enabled_review_authentication_methods = $reviewMethods
            }
            CurrentState    = $currentState
            ZeroTrustTarget = "Password recovery should be controlled. Modern authentication methods should be available, and weaker recovery methods should be limited and justified."
            GapSummary      = $gap
        }

        return New-ZTVPResult @resultArgs
    }
    catch {
        $resultArgs = @{
            ScenarioId      = "B4"
            ScenarioName    = "Password and Account Protection Baseline Review"
            Category        = "Baseline Security"
            Status          = "ERROR"
            Risk            = "CRITICAL"
            Findings        = @(New-ZTVPFinding -Title "Execution error" -Detail $_.Exception.Message)
            Recommendations = @(New-ZTVPRecommendation -Title "Fix B4 execution issue" -Detail "Review Graph permissions for authorization policy and authentication methods policy.")
            Evidence        = $null
            CurrentState    = "B4 could not complete password and account protection assessment."
            ZeroTrustTarget = "Password and account recovery should be controlled and protected."
            GapSummary      = "B4 could not be evaluated because execution failed."
        }

        return New-ZTVPResult @resultArgs
    }
}
