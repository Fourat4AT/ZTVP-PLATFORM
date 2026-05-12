Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Identity.SignIns -Force -ErrorAction SilentlyContinue

function ConvertTo-ID3Text {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return $Value.ToString()
}

function Test-ID3ActiveRiskState {
    param([string]$RiskState)

    $state = (ConvertTo-ID3Text $RiskState).ToLowerInvariant()

    return (
        $state -eq "atrisk" -or
        $state -eq "confirmedcompromised"
    )
}

function Test-ID3ClosedRiskState {
    param([string]$RiskState)

    $state = (ConvertTo-ID3Text $RiskState).ToLowerInvariant()

    return (
        $state -eq "remediated" -or
        $state -eq "dismissed" -or
        $state -eq "confirmedsafe" -or
        $state -eq "none"
    )
}

function Get-ID3RiskLevelRank {
    param([string]$RiskLevel)

    $level = (ConvertTo-ID3Text $RiskLevel).ToLowerInvariant()

    switch ($level) {
        "high"   { return 3 }
        "medium" { return 2 }
        "low"    { return 1 }
        default  { return 0 }
    }
}

function Get-ID3RiskEventName {
    param($Detection)

    $riskType = ConvertTo-ID3Text $Detection.RiskType
    $riskEventType = ConvertTo-ID3Text $Detection.RiskEventType

    if (-not [string]::IsNullOrWhiteSpace($riskType)) {
        return $riskType
    }

    if (-not [string]::IsNullOrWhiteSpace($riskEventType)) {
        return $riskEventType
    }

    return "Unknown"
}

function Get-ID3ActionSummary {
    param(
        [string]$RiskLevel,
        [string]$RiskState,
        [string]$RiskType
    )

    $level = (ConvertTo-ID3Text $RiskLevel).ToLowerInvariant()
    $state = (ConvertTo-ID3Text $RiskState).ToLowerInvariant()

    if ($state -eq "confirmedcompromised") {
        return "Confirmed compromised signal. Investigate user activity immediately, revoke sessions, reset password, and review related sign-ins."
    }

    if ($state -eq "atrisk" -and $level -eq "high") {
        return "High-risk active detection. Investigate immediately and remediate the affected user."
    }

    if ($state -eq "atrisk" -and $level -eq "medium") {
        return "Medium-risk active detection. Review the detection, related sign-ins, device, IP, and user activity."
    }

    if ($state -eq "atrisk" -and $level -eq "low") {
        return "Low-risk active detection. Review and monitor for additional signals."
    }

    if ($state -eq "remediated") {
        return "Detection is remediated. Confirm remediation is expected."
    }

    if ($state -eq "dismissed") {
        return "Detection was dismissed. Confirm dismissal was justified."
    }

    if ($state -eq "confirmedsafe") {
        return "Detection was confirmed safe. No immediate action required."
    }

    return "Review the detection details, affected user, risk level, and risk state."
}

function ConvertTo-ID3DetectionEvidence {
    param($Detection)

    $userPrincipalName = ConvertTo-ID3Text $Detection.UserPrincipalName
    $userDisplayName = ConvertTo-ID3Text $Detection.UserDisplayName
    $userId = ConvertTo-ID3Text $Detection.UserId

    $riskLevel = ConvertTo-ID3Text $Detection.RiskLevel
    $riskState = ConvertTo-ID3Text $Detection.RiskState
    $riskDetail = ConvertTo-ID3Text $Detection.RiskDetail
    $riskEvent = Get-ID3RiskEventName -Detection $Detection

    $activity = ConvertTo-ID3Text $Detection.Activity
    $source = ConvertTo-ID3Text $Detection.Source
    $ipAddress = ConvertTo-ID3Text $Detection.IpAddress
    $tokenIssuerType = ConvertTo-ID3Text $Detection.TokenIssuerType
    $detectionTimingType = ConvertTo-ID3Text $Detection.DetectionTimingType

    $detectedDateTime = ""
    if ($Detection.DetectedDateTime) {
        $detectedDateTime = $Detection.DetectedDateTime.ToString()
    }

    $lastUpdatedDateTime = ""
    if ($Detection.LastUpdatedDateTime) {
        $lastUpdatedDateTime = $Detection.LastUpdatedDateTime.ToString()
    }

    $isActive = Test-ID3ActiveRiskState -RiskState $riskState
    $isClosed = Test-ID3ClosedRiskState -RiskState $riskState
    $rank = Get-ID3RiskLevelRank -RiskLevel $riskLevel

    $needsImmediateAction = [bool](
        $isActive -eq $true -and
        (
            $rank -ge 2 -or
            $riskState.ToLowerInvariant() -eq "confirmedcompromised"
        )
    )

    [PSCustomObject]@{
        id                     = ConvertTo-ID3Text $Detection.Id
        user_principal_name    = $userPrincipalName
        user_display_name      = $userDisplayName
        user_id                = $userId

        risk_event_type        = $riskEvent
        risk_level             = $riskLevel
        risk_state             = $riskState
        risk_detail            = $riskDetail

        activity               = $activity
        source                 = $source
        ip_address             = $ipAddress
        token_issuer_type      = $tokenIssuerType
        detection_timing_type  = $detectionTimingType

        detected_datetime      = $detectedDateTime
        last_updated_datetime  = $lastUpdatedDateTime

        is_active_detection    = $isActive
        is_closed_detection    = $isClosed
        risk_level_rank        = $rank
        needs_immediate_action = $needsImmediateAction
        action_summary         = Get-ID3ActionSummary -RiskLevel $riskLevel -RiskState $riskState -RiskType $riskEvent
    }
}

function Invoke-ZTVP-ID3 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== ID3 - Risk Detection Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        try {
            $detections = @(Get-MgRiskDetection -All -ErrorAction Stop)
        }
        catch {
            return New-ZTVPResult `
                -ScenarioId "ID3" `
                -ScenarioName "Risk Detection Review" `
                -Category "Identity Protection" `
                -Status "ERROR" `
                -Risk "CRITICAL" `
                -Findings @(
                    New-ZTVPFinding `
                        -Title "Risk detections could not be collected" `
                        -Detail $_.Exception.Message
                ) `
                -Recommendations @(
                    New-ZTVPRecommendation `
                        -Title "Fix risk detection evidence collection" `
                        -Detail "Confirm Microsoft Graph permissions and Entra ID Protection licensing allow reading risk detections."
                ) `
                -Evidence $null `
                -CurrentState "Risk detection evidence was unavailable." `
                -ZeroTrustTarget "Risk detections should be visible, reviewed, and remediated according to risk severity." `
                -GapSummary "ID3 could not be evaluated because risk detection evidence was unavailable."
        }

        $detectionEvidence = @()

        foreach ($detection in $detections) {
            $detectionEvidence += ConvertTo-ID3DetectionEvidence -Detection $detection
        }

        $activeDetections = @($detectionEvidence | Where-Object { $_.is_active_detection -eq $true })
        $closedDetections = @($detectionEvidence | Where-Object { $_.is_closed_detection -eq $true })

        $activeHighDetections = @(
            $activeDetections |
            Where-Object {
                $_.risk_level.ToLowerInvariant() -eq "high" -or
                $_.risk_state.ToLowerInvariant() -eq "confirmedcompromised"
            }
        )

        $activeMediumDetections = @(
            $activeDetections |
            Where-Object { $_.risk_level.ToLowerInvariant() -eq "medium" }
        )

        $activeLowDetections = @(
            $activeDetections |
            Where-Object { $_.risk_level.ToLowerInvariant() -eq "low" }
        )

        $needsImmediateActionDetections = @(
            $detectionEvidence |
            Where-Object { $_.needs_immediate_action -eq $true }
        )

        $affectedUsers = @(
            $detectionEvidence |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.user_principal_name) } |
            Select-Object -ExpandProperty user_principal_name -Unique
        )

        $eventTypes = @(
            $detectionEvidence |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.risk_event_type) } |
            Select-Object -ExpandProperty risk_event_type -Unique
        )

        if ($activeHighDetections.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Active high-risk detections detected" `
                -Detail ("High-risk active detections require immediate investigation. Sample: " + (($activeHighDetections | Select-Object -First 15 | ForEach-Object { "$($_.user_principal_name) [$($_.risk_event_type)/$($_.risk_level)/$($_.risk_state)]" }) -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Investigate high-risk detections immediately" `
                -Detail "Review affected users, related sign-ins, IP addresses, devices, and detection types. Revoke sessions and reset passwords where appropriate."
        }

        if ($activeMediumDetections.Count -gt 0) {
            $findings += New-ZTVPFinding `
                -Title "Active medium-risk detections detected" `
                -Detail ("Medium-risk active detections require review. Sample: " + (($activeMediumDetections | Select-Object -First 15 | ForEach-Object { "$($_.user_principal_name) [$($_.risk_event_type)/$($_.risk_level)/$($_.risk_state)]" }) -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review medium-risk detections" `
                -Detail "Review medium-risk detections and decide whether to remediate, dismiss, or confirm safe based on evidence."
        }

        if ($activeLowDetections.Count -gt 0 -and $activeHighDetections.Count -eq 0 -and $activeMediumDetections.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "Only low-risk active detections detected" `
                -Detail ("Low-risk detections should be reviewed and monitored. Sample: " + (($activeLowDetections | Select-Object -First 15 | ForEach-Object { "$($_.user_principal_name) [$($_.risk_event_type)/$($_.risk_level)/$($_.risk_state)]" }) -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Monitor low-risk detections" `
                -Detail "Review low-risk detections and monitor for additional signals."
        }

        if ($closedDetections.Count -gt 0) {
            $recommendations += New-ZTVPRecommendation `
                -Title "Keep risk detection decisions documented" `
                -Detail "Remediated, dismissed, or confirmed-safe detections should have a clear investigation trail."
        }

        $status = "PASS"
        $risk = "LOW"

        if ($activeHighDetections.Count -gt 0) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif ($activeMediumDetections.Count -gt 0) {
            $status = "FAIL"
            $risk = "HIGH"
        }
        elseif ($activeLowDetections.Count -gt 0) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }

        $currentState = @(
            "Risk detections assessed: $($detectionEvidence.Count)."
            "Active detections: $($activeDetections.Count)."
            "Active high-risk detections: $($activeHighDetections.Count)."
            "Active medium-risk detections: $($activeMediumDetections.Count)."
            "Active low-risk detections: $($activeLowDetections.Count)."
            "Closed detections: $($closedDetections.Count)."
            "Affected users: $($affectedUsers.Count)."
            "Risk event types: $($eventTypes.Count)."
            "Detections needing immediate action: $($needsImmediateActionDetections.Count)."
        ) -join " "

        $zeroTrustTarget = "Identity Protection risk detections should be visible, reviewed, and remediated based on severity. Active high or medium-risk detections should not remain unresolved."

        if ($status -eq "PASS") {
            if ($detectionEvidence.Count -eq 0) {
                $summary = "No risk detections were detected."
                $gap = "No active risk detection gap was detected."
            }
            else {
                $summary = "No active high or medium-risk detections require immediate action."
                $gap = "No critical risk detection remediation gap was detected."
            }
        }
        elseif ($status -eq "PARTIAL") {
            $summary = "Only low-risk active detections were detected. These should be reviewed and monitored."
            $gap = "Risk detection posture is partially aligned because low-risk active detections still require review."
        }
        else {
            $summary = "Active risk detections require remediation. Medium or high-risk detections are currently unresolved."
            $gap = "Risk detection posture is not aligned because active medium or high-risk detections require action."
        }

        return New-ZTVPResult `
            -ScenarioId "ID3" `
            -ScenarioName "Risk Detection Review" `
            -Category "Identity Protection" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary = $summary

                risk_detection_count = $detectionEvidence.Count
                active_detection_count = $activeDetections.Count
                active_high_risk_detection_count = $activeHighDetections.Count
                active_medium_risk_detection_count = $activeMediumDetections.Count
                active_low_risk_detection_count = $activeLowDetections.Count
                closed_detection_count = $closedDetections.Count
                affected_user_count = $affectedUsers.Count
                risk_event_type_count = $eventTypes.Count
                detections_needing_immediate_action_count = $needsImmediateActionDetections.Count

                risk_detections = $detectionEvidence
                active_detections = $activeDetections
                active_high_risk_detections = $activeHighDetections
                active_medium_risk_detections = $activeMediumDetections
                active_low_risk_detections = $activeLowDetections
                closed_detections = $closedDetections
                affected_users = $affectedUsers
                risk_event_types = $eventTypes
                detections_needing_immediate_action = $needsImmediateActionDetections
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gap
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "ID3" `
            -ScenarioName "Risk Detection Review" `
            -Category "Identity Protection" `
            -Status "ERROR" `
            -Risk "CRITICAL" `
            -Findings @(
                New-ZTVPFinding -Title "Execution error" -Detail $_.Exception.Message
            ) `
            -Recommendations @(
                New-ZTVPRecommendation -Title "Fix ID3 execution issue" -Detail "Review Graph permissions and Identity Protection visibility."
            ) `
            -Evidence $null `
            -CurrentState "ID3 could not complete risk detection assessment." `
            -ZeroTrustTarget "Risk detections should be visible, reviewed, and remediated according to risk severity." `
            -GapSummary "ID3 could not be evaluated because execution failed."
    }
}
