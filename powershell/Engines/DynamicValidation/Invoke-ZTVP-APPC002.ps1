param(
    [Parameter(Mandatory=$true)]
    [string]$ExternalTargetEmail,

    [ValidateSet("Mailbox forwarding only","Inbox rule only","Both recommended")]
    [string]$TestMode = "Both recommended",

    [int]$MailboxWaitMinutes = 10,

    [string]$ExchangeAdminUPN = ""
)

$ErrorActionPreference = "Stop"

function Write-ZTVPJson {
    param(
        [string]$Path,
        [object]$Object
    )

    $Object |
        ConvertTo-Json -Depth 100 |
        Set-Content -Path $Path -Encoding UTF8
}

function New-ZTVPResult {
    param(
        [object]$State,
        [string]$Status,
        [string]$Risk,
        [string]$Summary,
        [string]$FinalClaim,
        [string]$EvidenceQuality,
        [object[]]$Warnings,
        [object]$MailboxReadiness,
        [object]$MailboxForwardingAttempt,
        [object]$InboxRuleAttempt,
        [object]$FinalForwardingState,
        [object]$ArtifactCleanup,
        [object]$Metrics
    )

    return [PSCustomObject]@{
        scenario_id = "APP-C-002"
        display_id = "APP-DV-002"
        scenario_name = "Exchange External Mail Forwarding Exposure Validation"
        pillar = "Applications"
        scope = "Cloud"
        generated_at = (Get-Date).ToString("s")
        tenant_id = $State.tenant_id
        connected_account = $State.connected_account

        control_tested = "Exchange Online mailboxes should not be able to create silent automatic external forwarding or redirect paths unless explicitly approved."
        expected_result = "Mailbox-level external forwarding and inbox-rule external redirect or forwarding should be blocked or rejected."
        failure_condition = "The controlled decoy mailbox successfully configures external mailbox forwarding or an inbox rule redirect/forwarding action to an external address."
        test_method = "Create a controlled Exchange Online mailbox, attempt mailbox-level forwarding and inbox-rule forwarding to an external target, collect Exchange evidence, clean forwarding artifacts, then delete the decoy during final cleanup."

        status = $Status
        risk = $Risk
        executive_summary = $Summary
        final_claim = $FinalClaim
        evidence_quality = $EvidenceQuality
        warnings = @($Warnings)

        decoy_mailbox = [PSCustomObject]@{
            id = $State.decoy_user.id
            user_principal_name = $State.decoy_user.user_principal_name
            display_name = $State.decoy_user.display_name
            assigned_license = $State.assigned_license.sku_part_number
        }

        external_target = $ExternalTargetEmail
        test_mode = $TestMode

        mailbox_readiness = $MailboxReadiness
        mailbox_forwarding_attempt = $MailboxForwardingAttempt
        inbox_rule_attempt = $InboxRuleAttempt
        final_forwarding_state = $FinalForwardingState
        forwarding_artifact_cleanup = $ArtifactCleanup
        metrics = $Metrics

        recommendations = @(
            "Keep automatic external forwarding disabled unless there is a documented business exception.",
            "Review Exchange Online outbound spam policies and remote domain forwarding settings.",
            "Monitor mailbox forwarding settings and inbox rule creation events.",
            "Use approved shared mailboxes, transport rules, or secure collaboration paths instead of silent external forwarding.",
            "Repeat this validation after remediation to prove the controlled forwarding path is blocked."
        )

        limitations = @(
            "This version validates whether forwarding can be configured. It does not send test email and does not prove external delivery.",
            "Some Exchange Online controls block delivery after configuration is accepted. ZTVP treats accepted forwarding configuration as an exposure requiring review.",
            "The validation only tests the controlled decoy mailbox, not every mailbox in the tenant."
        )
    }
}

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "APP-C-002"
$statePath = Join-Path $scenarioDir "appc002-state.json"
$reportPath = Join-Path $reportRoot "APP-C-002-result.json"

if (-not (Test-Path $statePath)) {
    throw "No active APP-C-002 state exists. Create the decoy mailbox first."
}

if ([string]::IsNullOrWhiteSpace($ExternalTargetEmail) -or $ExternalTargetEmail -notmatch "^[^@\s]+@[^@\s]+\.[^@\s]+$") {
    throw "ExternalTargetEmail must be a valid external email address."
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

# APP-C-002 auto-fill ExchangeAdminUPN from active state
if ([string]::IsNullOrWhiteSpace($ExchangeAdminUPN)) {
    $ExchangeAdminUPN = [string]$state.connected_account
}

$upn = [string]$state.decoy_user.user_principal_name
$runId = [string]$state.run_id

$warnings = @()

$mailboxReadiness = [PSCustomObject]@{
    ready = $false
    checked_at = $null
    primary_smtp_address = $null
    recipient_type_details = $null
    error = $null
}

$mailboxForwardingAttempt = [PSCustomObject]@{
    attempted = $false
    accepted = $false
    error_message = $null
    forwarding_smtp_address_after_attempt = $null
    deliver_to_mailbox_and_forward_after_attempt = $null
}

$inboxRuleAttempt = [PSCustomObject]@{
    attempted = $false
    accepted = $false
    rule_name = $null
    used_mail_contact_fallback = $false
    temporary_mail_contact = $null
    error_message = $null
}

$finalForwardingState = [PSCustomObject]@{
    forwarding_smtp_address = $null
    forwarding_address = $null
    deliver_to_mailbox_and_forward = $null
}

$artifactCleanup = [PSCustomObject]@{
    status = "NotStarted"
    actions = @()
    errors = @()
}

$module = Get-Module -ListAvailable -Name ExchangeOnlineManagement |
    Sort-Object Version -Descending |
    Select-Object -First 1

if (-not $module) {
    $warnings += "ExchangeOnlineManagement module is not installed. Install it with: Install-Module ExchangeOnlineManagement -Scope CurrentUser"

    $metrics = [PSCustomObject]@{
        mailbox_ready = $false
        mailbox_forwarding_allowed = $false
        inbox_rule_allowed = $false
        forwarding_artifacts_cleanup_completed = $true
        exchange_module_available = $false
        test_mode = $TestMode
    }

    $result = New-ZTVPResult `
        -State $state `
        -Status "PARTIAL_EXCHANGE_MODULE_MISSING" `
        -Risk "MEDIUM" `
        -Summary "The Exchange Online PowerShell module is not installed, so ZTVP could not run the forwarding validation." `
        -FinalClaim "Install ExchangeOnlineManagement and rerun the validation." `
        -EvidenceQuality "Partial - Exchange module missing." `
        -Warnings $warnings `
        -MailboxReadiness $mailboxReadiness `
        -MailboxForwardingAttempt $mailboxForwardingAttempt `
        -InboxRuleAttempt $inboxRuleAttempt `
        -FinalForwardingState $finalForwardingState `
        -ArtifactCleanup $artifactCleanup `
        -Metrics $metrics

    Write-ZTVPJson -Path $reportPath -Object $result
    Write-Host "PARTIAL_EXCHANGE_MODULE_MISSING"
    exit 0
}

Import-Module ExchangeOnlineManagement -ErrorAction Stop

try {
    if ([string]::IsNullOrWhiteSpace($ExchangeAdminUPN)) {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop | Out-Null
    }
    else {
        Connect-ExchangeOnline -UserPrincipalName $ExchangeAdminUPN -ShowBanner:$false -ErrorAction Stop | Out-Null
    }
}
catch {
    $warnings += "Could not connect to Exchange Online: $($_.Exception.Message)"

    $metrics = [PSCustomObject]@{
        mailbox_ready = $false
        mailbox_forwarding_allowed = $false
        inbox_rule_allowed = $false
        forwarding_artifacts_cleanup_completed = $true
        exchange_module_available = $true
        test_mode = $TestMode
    }

    $result = New-ZTVPResult `
        -State $state `
        -Status "PARTIAL_EXCHANGE_CONNECTION_FAILED" `
        -Risk "MEDIUM" `
        -Summary "ZTVP could not connect to Exchange Online PowerShell." `
        -FinalClaim "The validation could not continue until Exchange Online PowerShell authentication succeeds." `
        -EvidenceQuality "Partial - Exchange connection failed." `
        -Warnings $warnings `
        -MailboxReadiness $mailboxReadiness `
        -MailboxForwardingAttempt $mailboxForwardingAttempt `
        -InboxRuleAttempt $inboxRuleAttempt `
        -FinalForwardingState $finalForwardingState `
        -ArtifactCleanup $artifactCleanup `
        -Metrics $metrics

    Write-ZTVPJson -Path $reportPath -Object $result
    Write-Host "PARTIAL_EXCHANGE_CONNECTION_FAILED"
    exit 0
}

$mailbox = $null
$deadline = (Get-Date).AddMinutes($MailboxWaitMinutes)
$lastMailboxError = $null

while ((Get-Date) -lt $deadline) {
    try {
        $mailbox = Get-Mailbox -Identity $upn -ErrorAction Stop

        $mailboxReadiness = [PSCustomObject]@{
            ready = $true
            checked_at = (Get-Date).ToString("s")
            primary_smtp_address = [string]$mailbox.PrimarySmtpAddress
            recipient_type_details = [string]$mailbox.RecipientTypeDetails
            error = $null
        }

        break
    }
    catch {
        $lastMailboxError = $_.Exception.Message
        Start-Sleep -Seconds 30
    }
}

if ($null -eq $mailbox) {
    $warnings += "Mailbox was not ready within $MailboxWaitMinutes minutes. Last error: $lastMailboxError"

    $mailboxReadiness = [PSCustomObject]@{
        ready = $false
        checked_at = (Get-Date).ToString("s")
        primary_smtp_address = $null
        recipient_type_details = $null
        error = $lastMailboxError
    }

    $metrics = [PSCustomObject]@{
        mailbox_ready = $false
        mailbox_forwarding_allowed = $false
        inbox_rule_allowed = $false
        forwarding_artifacts_cleanup_completed = $true
        exchange_module_available = $true
        test_mode = $TestMode
    }

    $result = New-ZTVPResult `
        -State $state `
        -Status "PARTIAL_MAILBOX_NOT_READY" `
        -Risk "MEDIUM" `
        -Summary "The decoy user was licensed, but the Exchange mailbox was not ready before the test timeout." `
        -FinalClaim "The forwarding validation could not run until the mailbox is provisioned. Wait and rerun the validation with the same decoy." `
        -EvidenceQuality "Partial - mailbox not ready." `
        -Warnings $warnings `
        -MailboxReadiness $mailboxReadiness `
        -MailboxForwardingAttempt $mailboxForwardingAttempt `
        -InboxRuleAttempt $inboxRuleAttempt `
        -FinalForwardingState $finalForwardingState `
        -ArtifactCleanup $artifactCleanup `
        -Metrics $metrics

    Write-ZTVPJson -Path $reportPath -Object $result

    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}

    Write-Host "PARTIAL_MAILBOX_NOT_READY"
    exit 0
}

$ruleName = "ZTVP APP-C-002 External Forward Test $runId"
$contactName = "ZTVP APP-C-002 External Target $runId"
$contactAlias = "ztvpappc002target" + ($runId.Replace("-", ""))
$contactCreated = $false
$contactIdentity = $null

try {
    if ($TestMode -eq "Mailbox forwarding only" -or $TestMode -eq "Both recommended") {
        $mailboxForwardingAttempt.attempted = $true

        try {
            $smtpTarget = "smtp:$ExternalTargetEmail"

            Set-Mailbox `
                -Identity $upn `
                -ForwardingSmtpAddress $smtpTarget `
                -DeliverToMailboxAndForward $true `
                -ErrorAction Stop

            Start-Sleep -Seconds 4

            $afterMailbox = Get-Mailbox -Identity $upn -ErrorAction Stop

            $smtpAfter = [string]$afterMailbox.ForwardingSmtpAddress
            $deliverAfter = [string]$afterMailbox.DeliverToMailboxAndForward

            $mailboxForwardingAttempt.forwarding_smtp_address_after_attempt = $smtpAfter
            $mailboxForwardingAttempt.deliver_to_mailbox_and_forward_after_attempt = $deliverAfter
            $mailboxForwardingAttempt.accepted = ($smtpAfter.ToLower().Contains($ExternalTargetEmail.ToLower()))
        }
        catch {
            $mailboxForwardingAttempt.error_message = $_.Exception.Message
        }
    }

    if ($TestMode -eq "Inbox rule only" -or $TestMode -eq "Both recommended") {
        $inboxRuleAttempt.attempted = $true
        $inboxRuleAttempt.rule_name = $ruleName

        try {
            New-InboxRule `
                -Mailbox $upn `
                -Name $ruleName `
                -RedirectTo $ExternalTargetEmail `
                -StopProcessingRules $true `
                -ErrorAction Stop | Out-Null

            $inboxRuleAttempt.accepted = $true
        }
        catch {
            $directError = $_.Exception.Message
            $inboxRuleAttempt.error_message = $directError

            try {
                $contact = New-MailContact `
                    -Name $contactName `
                    -Alias $contactAlias `
                    -ExternalEmailAddress $ExternalTargetEmail `
                    -ErrorAction Stop

                $contactCreated = $true
                $contactIdentity = [string]$contact.Identity

                New-InboxRule `
                    -Mailbox $upn `
                    -Name $ruleName `
                    -RedirectTo $contact.Identity `
                    -StopProcessingRules $true `
                    -ErrorAction Stop | Out-Null

                $inboxRuleAttempt.accepted = $true
                $inboxRuleAttempt.used_mail_contact_fallback = $true
                $inboxRuleAttempt.temporary_mail_contact = $contactIdentity
                $inboxRuleAttempt.error_message = $null
            }
            catch {
                $inboxRuleAttempt.error_message = "Direct rule failed: $directError | Mail contact fallback failed: $($_.Exception.Message)"
            }
        }
    }
}
catch {
    $warnings += "Unexpected validation error: $($_.Exception.Message)"
}
finally {
    $cleanupActions = @()
    $cleanupErrors = @()

    try {
        Set-Mailbox `
            -Identity $upn `
            -ForwardingSmtpAddress $null `
            -ForwardingAddress $null `
            -DeliverToMailboxAndForward $false `
            -ErrorAction Stop

        $cleanupActions += "Cleared mailbox-level forwarding settings."
    }
    catch {
        $cleanupErrors += "Could not clear mailbox forwarding settings: $($_.Exception.Message)"
    }

    try {
        $rules = @(Get-InboxRule -Mailbox $upn -ErrorAction Stop | Where-Object { $_.Name -eq $ruleName })

        foreach ($rule in $rules) {
            Remove-InboxRule `
                -Mailbox $upn `
                -Identity $rule.Identity `
                -Confirm:$false `
                -ErrorAction Stop

            $cleanupActions += "Removed inbox rule: $ruleName"
        }
    }
    catch {
        $cleanupErrors += "Could not remove inbox rule during cleanup: $($_.Exception.Message)"
    }

    if ($contactCreated -and -not [string]::IsNullOrWhiteSpace($contactIdentity)) {
        try {
            Remove-MailContact `
                -Identity $contactIdentity `
                -Confirm:$false `
                -ErrorAction Stop

            $cleanupActions += "Removed temporary mail contact."
        }
        catch {
            $cleanupErrors += "Could not remove temporary mail contact: $($_.Exception.Message)"
        }
    }

    try {
        $finalMailbox = Get-Mailbox -Identity $upn -ErrorAction Stop

        $finalForwardingState = [PSCustomObject]@{
            forwarding_smtp_address = [string]$finalMailbox.ForwardingSmtpAddress
            forwarding_address = [string]$finalMailbox.ForwardingAddress
            deliver_to_mailbox_and_forward = [string]$finalMailbox.DeliverToMailboxAndForward
        }
    }
    catch {
        $cleanupErrors += "Could not read final forwarding state: $($_.Exception.Message)"
    }

    $cleanupStatus = if ($cleanupErrors.Count -eq 0) { "Completed" } else { "Failed" }

    $artifactCleanup = [PSCustomObject]@{
        status = $cleanupStatus
        actions = @($cleanupActions)
        errors = @($cleanupErrors)
    }
}

$mailboxForwardingAllowed = ($mailboxForwardingAttempt.accepted -eq $true)
$inboxRuleAllowed = ($inboxRuleAttempt.accepted -eq $true)
$artifactsCleaned = ($artifactCleanup.status -eq "Completed")

$status = "PASS_EXTERNAL_MAIL_FORWARDING_BLOCKED"
$risk = "LOW"
$summary = "Exchange Online did not accept mailbox-level external forwarding or inbox-rule external forwarding for the controlled decoy mailbox."
$finalClaim = "The controlled decoy mailbox could not create an automatic external forwarding path during this validation."
$evidenceQuality = "Strong - Exchange Online rejected or did not persist the tested forwarding configuration paths."

if ($mailboxForwardingAllowed -or $inboxRuleAllowed) {
    $status = "FAIL_EXTERNAL_MAIL_FORWARDING_ALLOWED"
    $risk = "HIGH"
    $summary = "Exchange Online accepted at least one automatic external forwarding configuration for the controlled decoy mailbox."
    $finalClaim = "The controlled decoy mailbox was able to configure an automatic external forwarding path. ZTVP removed the test forwarding artifact after evidence collection."
    $evidenceQuality = "Strong - Exchange Online accepted and persisted at least one tested forwarding configuration path."
}

if (-not $artifactsCleaned) {
    $warnings += "Forwarding artifact cleanup did not fully complete. Run cleanup and review Exchange manually if needed."
}

$metrics = [PSCustomObject]@{
    mailbox_ready = $true
    mailbox_forwarding_allowed = $mailboxForwardingAllowed
    inbox_rule_allowed = $inboxRuleAllowed
    forwarding_artifacts_cleanup_completed = $artifactsCleaned
    exchange_module_available = $true
    test_mode = $TestMode
}

$result = New-ZTVPResult `
    -State $state `
    -Status $status `
    -Risk $risk `
    -Summary $summary `
    -FinalClaim $finalClaim `
    -EvidenceQuality $evidenceQuality `
    -Warnings $warnings `
    -MailboxReadiness $mailboxReadiness `
    -MailboxForwardingAttempt $mailboxForwardingAttempt `
    -InboxRuleAttempt $inboxRuleAttempt `
    -FinalForwardingState $finalForwardingState `
    -ArtifactCleanup $artifactCleanup `
    -Metrics $metrics

Write-ZTVPJson -Path $reportPath -Object $result

$state.forwarding_artifacts.mailbox_forwarding_configured = $mailboxForwardingAllowed
$state.forwarding_artifacts.inbox_rule_created = $inboxRuleAllowed
$state.forwarding_artifacts.inbox_rule_name = $ruleName
$state.forwarding_artifacts.external_target = $ExternalTargetEmail
$state.cleanup.status = "ForwardingArtifactsCleaned_DecoyPending"

Write-ZTVPJson -Path $statePath -Object $state

try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}

Write-Host ""
Write-Host "APP-C-002 validation completed."
Write-Host "Status: $status"
Write-Host "Risk: $risk"
Write-Host "Mailbox forwarding allowed: $mailboxForwardingAllowed"
Write-Host "Inbox rule allowed: $inboxRuleAllowed"
Write-Host "Forwarding artifacts cleanup: $($artifactCleanup.status)"
Write-Host "Report saved to: $reportPath"
Write-Host ""
