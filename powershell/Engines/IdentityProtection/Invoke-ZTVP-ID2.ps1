Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Identity.SignIns -Force -ErrorAction SilentlyContinue

function ConvertTo-ID2Text {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return $Value.ToString()
}

function Test-ID2ActiveRiskState {
    param([string]$RiskState)

    $state = ConvertTo-ID2Text $RiskState
    $state = $state.ToLowerInvariant()

    return (
        $state -eq "atrisk" -or
        $state -eq "confirmedcompromised"
    )
}

function Test-ID2ClosedRiskState {
    param([string]$RiskState)

    $state = ConvertTo-ID2Text $RiskState
    $state = $state.ToLowerInvariant()

    return (
        $state -eq "remediated" -or
        $state -eq "dismissed" -or
        $state -eq "confirmedsafe" -or
        $state -eq "none"
    )
}

function Get-ID2RiskLevelRank {
    param([string]$RiskLevel)

    $level = ConvertTo-ID2Text $RiskLevel
    $level = $level.ToLowerInvariant()

    switch ($level) {
        "high"   { return 3 }
        "medium" { return 2 }
        "low"    { return 1 }
        default  { return 0 }
    }
}

function Get-ID2ActionSummary {
    param(
        [string]$RiskLevel,
        [string]$RiskState,
        [string]$RiskDetail
    )

    $level = (ConvertTo-ID2Text $RiskLevel).ToLowerInvariant()
    $state = (ConvertTo-ID2Text $RiskState).ToLowerInvariant()
    $detail = (ConvertTo-ID2Text $RiskDetail).ToLowerInvariant()

    if ($state -eq "confirmedcompromised") {
        return "Confirmed compromised. Investigate immediately, revoke sessions, reset password, and review recent sign-ins."
    }

    if ($state -eq "atrisk" -and $level -eq "high") {
        return "High-risk active user. Investigate immediately, revoke sessions, require password reset, and confirm whether the activity is legitimate."
    }

    if ($state -eq "atrisk" -and $level -eq "medium") {
        return "Medium-risk active user. Investigate sign-ins and detections, then remediate with password reset or session revocation if needed."
    }

    if ($state -eq "atrisk" -and $level -eq "low") {
        return "Low-risk active user. Review activity and monitor. Remediate if additional suspicious evidence exists."
    }

    if ($state -eq "remediated") {
        return "Risk is remediated. Confirm remediation was expected and no new risk remains."
    }

    if ($state -eq "dismissed") {
        return "Risk was dismissed. Confirm dismissal was justified and documented."
    }

    if ($state -eq "confirmedsafe") {
        return "User was confirmed safe. No immediate remediation required."
    }

    if ($detail -match "password") {
        return "Password-related risk detail detected. Confirm password reset or secure password change was completed."
    }

    return "Review the user risk state, risk level, and related sign-in/risk detections."
}

function ConvertTo-ID2RiskyUserEvidence {
    param($User)

    $userPrincipalName = ""
    if ($User.UserPrincipalName) {
        $userPrincipalName = $User.UserPrincipalName
    }

    $displayName = ""
    if ($User.DisplayName) {
        $displayName = $User.DisplayName
    }

    $id = ""
    if ($User.Id) {
        $id = $User.Id
    }

    $riskLevel = ConvertTo-ID2Text $User.RiskLevel
    $riskState = ConvertTo-ID2Text $User.RiskState
    $riskDetail = ConvertTo-ID2Text $User.RiskDetail

    $isActive = Test-ID2ActiveRiskState -RiskState $riskState
    $isClosed = Test-ID2ClosedRiskState -RiskState $riskState
    $rank = Get-ID2RiskLevelRank -RiskLevel $riskLevel

    $needsImmediateAction = [bool](
        $isActive -eq $true -and
        (
            $rank -ge 2 -or
            $riskState.ToLowerInvariant() -eq "confirmedcompromised"
        )
    )

    $lastUpdated = ""
    if ($User.RiskLastUpdatedDateTime) {
        $lastUpdated = $User.RiskLastUpdatedDateTime.ToString()
    }

    [PSCustomObject]@{
        id                     = $id
        user_principal_name    = $userPrincipalName
        display_name           = $displayName
        risk_level             = $riskLevel
        risk_state             = $riskState
        risk_detail            = $riskDetail
        risk_last_updated      = $lastUpdated
        is_active_risk         = $isActive
        is_closed_risk         = $isClosed
        risk_level_rank        = $rank
        needs_immediate_action = $needsImmediateAction
        action_summary         = Get-ID2ActionSummary -RiskLevel $riskLevel -RiskState $riskState -RiskDetail $riskDetail
    }
}

function Invoke-ZTVP-ID2 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== ID2 - Risky User Remediation Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        try {
            $riskyUsers = @(Get-MgRiskyUser -All -ErrorAction Stop)
        }
        catch {
            return New-ZTVPResult `
                -ScenarioId "ID2" `
                -ScenarioName "Risky User Remediation Review" `
                -Category "Identity Protection" `
                -Status "ERROR" `
                -Risk "CRITICAL" `
                -Findings @(
                    New-ZTVPFinding `
                        -Title "Risky users could not be collected" `
                        -Detail $_.Exception.Message
                ) `
                -Recommendations @(
                    New-ZTVPRecommendation `
                        -Title "Fix risky user evidence collection" `
                        -Detail "Confirm Microsoft Graph permissions and Entra ID Protection licensing allow reading risky users."
                ) `
                -Evidence $null `
                -CurrentState "Risky user evidence was unavailable." `
                -ZeroTrustTarget "Risky users should be visible, investigated, and remediated according to risk severity." `
                -GapSummary "ID2 could not be evaluated because risky user evidence was unavailable."
        }

        $userEvidence = @()

        foreach ($user in $riskyUsers) {
            $userEvidence += ConvertTo-ID2RiskyUserEvidence -User $user
        }

        $activeUsers = @($userEvidence | Where-Object { $_.is_active_risk -eq $true })
        $closedUsers = @($userEvidence | Where-Object { $_.is_closed_risk -eq $true })

        $activeHighUsers = @(
            $activeUsers |
            Where-Object {
                $_.risk_level.ToLowerInvariant() -eq "high" -or
                $_.risk_state.ToLowerInvariant() -eq "confirmedcompromised"
            }
        )

        $activeMediumUsers = @(
            $activeUsers |
            Where-Object {
                $_.risk_level.ToLowerInvariant() -eq "medium"
            }
        )

        $activeLowUsers = @(
            $activeUsers |
            Where-Object {
                $_.risk_level.ToLowerInvariant() -eq "low"
            }
        )

        $remediatedUsers = @($userEvidence | Where-Object { $_.risk_state.ToLowerInvariant() -eq "remediated" })
        $dismissedUsers = @($userEvidence | Where-Object { $_.risk_state.ToLowerInvariant() -eq "dismissed" })
        $confirmedSafeUsers = @($userEvidence | Where-Object { $_.risk_state.ToLowerInvariant() -eq "confirmedsafe" })

        $needsImmediateActionUsers = @($userEvidence | Where-Object { $_.needs_immediate_action -eq $true })

        if ($activeHighUsers.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Active high-risk or confirmed-compromised users detected" `
                -Detail ("High-risk active users require immediate remediation. Users: " + (($activeHighUsers | Select-Object -First 15 | ForEach-Object { "$($_.user_principal_name) [$($_.risk_level)/$($_.risk_state)]" }) -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Immediately remediate high-risk users" `
                -Detail "Investigate high-risk users, revoke active sessions, require password reset or secure password change, and confirm whether the activity was legitimate."
        }

        if ($activeMediumUsers.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Active medium-risk users detected" `
                -Detail ("Medium-risk active users require review and remediation decision. Users: " + (($activeMediumUsers | Select-Object -First 15 | ForEach-Object { "$($_.user_principal_name) [$($_.risk_level)/$($_.risk_state)]" }) -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review and remediate medium-risk users" `
                -Detail "Investigate medium-risk users and remediate with password reset, session revocation, or dismissal only after validation."
        }

        if ($activeLowUsers.Count -gt 0 -and $activeHighUsers.Count -eq 0 -and $activeMediumUsers.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "Only low-risk active users detected" `
                -Detail ("Low-risk active users should be reviewed but are not treated as critical. Users: " + (($activeLowUsers | Select-Object -First 15 | ForEach-Object { "$($_.user_principal_name) [$($_.risk_level)/$($_.risk_state)]" }) -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review low-risk active users" `
                -Detail "Review low-risk active users and monitor for additional risk detections."
        }

        if ($remediatedUsers.Count -gt 0 -or $dismissedUsers.Count -gt 0 -or $confirmedSafeUsers.Count -gt 0) {
            $recommendations += New-ZTVPRecommendation `
                -Title "Keep remediation decisions documented" `
                -Detail "Remediated, dismissed, or confirmed-safe risky users should have an explainable investigation trail."
        }

        $status = "PASS"
        $risk = "LOW"

        if ($activeHighUsers.Count -gt 0) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif ($activeMediumUsers.Count -gt 0) {
            $status = "FAIL"
            $risk = "HIGH"
        }
        elseif ($activeLowUsers.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }
        elseif ($closedUsers.Count -gt 0) {
            $status = "PASS"
            $risk = "LOW"
        }

        $currentState = @(
            "Risky users assessed: $($userEvidence.Count)."
            "Active risky users: $($activeUsers.Count)."
            "Active high-risk users: $($activeHighUsers.Count)."
            "Active medium-risk users: $($activeMediumUsers.Count)."
            "Active low-risk users: $($activeLowUsers.Count)."
            "Remediated users: $($remediatedUsers.Count)."
            "Dismissed users: $($dismissedUsers.Count)."
            "Confirmed-safe users: $($confirmedSafeUsers.Count)."
            "Users needing immediate action: $($needsImmediateActionUsers.Count)."
        ) -join " "

        $zeroTrustTarget = "Risky users should not remain active and unresolved. High and medium-risk users should be investigated promptly, sessions revoked where needed, and password reset or secure password change performed when appropriate."

        if ($status -eq "PASS") {
            if ($userEvidence.Count -eq 0) {
                $summary = "No risky users were detected."
                $gap = "No active risky user remediation gap was detected."
            }
            else {
                $summary = "No active high or medium-risk users require immediate action. Existing risky user records are remediated, dismissed, confirmed-safe, or low-impact."
                $gap = "No critical risky user remediation gap was detected."
            }
        }
        elseif ($status -eq "PARTIAL") {
            $summary = "Only low-risk active users were detected. These users should be reviewed and monitored."
            $gap = "Risky user posture is partially aligned because low-risk active users still require review."
        }
        else {
            $summary = "Active risky users require remediation. Medium or high-risk users are currently unresolved."
            $gap = "Risky user posture is not aligned because active medium or high-risk users require action."
        }

        return New-ZTVPResult `
            -ScenarioId "ID2" `
            -ScenarioName "Risky User Remediation Review" `
            -Category "Identity Protection" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary = $summary

                risky_user_count = $userEvidence.Count
                active_risky_user_count = $activeUsers.Count
                active_high_risk_user_count = $activeHighUsers.Count
                active_medium_risk_user_count = $activeMediumUsers.Count
                active_low_risk_user_count = $activeLowUsers.Count
                remediated_user_count = $remediatedUsers.Count
                dismissed_user_count = $dismissedUsers.Count
                confirmed_safe_user_count = $confirmedSafeUsers.Count
                users_needing_immediate_action_count = $needsImmediateActionUsers.Count

                risky_users = $userEvidence
                active_risky_users = $activeUsers
                active_high_risk_users = $activeHighUsers
                active_medium_risk_users = $activeMediumUsers
                active_low_risk_users = $activeLowUsers
                remediated_users = $remediatedUsers
                dismissed_users = $dismissedUsers
                confirmed_safe_users = $confirmedSafeUsers
                users_needing_immediate_action = $needsImmediateActionUsers
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gap
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "ID2" `
            -ScenarioName "Risky User Remediation Review" `
            -Category "Identity Protection" `
            -Status "ERROR" `
            -Risk "CRITICAL" `
            -Findings @(
                New-ZTVPFinding -Title "Execution error" -Detail $_.Exception.Message
            ) `
            -Recommendations @(
                New-ZTVPRecommendation -Title "Fix ID2 execution issue" -Detail "Review Graph permissions and Identity Protection visibility."
            ) `
            -Evidence $null `
            -CurrentState "ID2 could not complete risky user remediation assessment." `
            -ZeroTrustTarget "Risky users should be visible, investigated, and remediated according to risk severity." `
            -GapSummary "ID2 could not be evaluated because execution failed."
    }
}
