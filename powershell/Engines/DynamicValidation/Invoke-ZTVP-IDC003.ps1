param(
    [string]$Protocols = "SMTP,IMAP,POP",
    [int]$MailboxWaitMinutes = 10,
    [int]$LookbackMinutes = 240
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$RequiredScopes = @(
    "AuditLog.Read.All",
    "Directory.Read.All",
    "User.Read.All",
    "User.ReadWrite.All"
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


function Get-ZTVPMailboxReadiness {
    param([string]$UserId)

    $encodedUserId = [System.Uri]::EscapeDataString($UserId)
    $errors = @()
    $user = $null
    $licenseDetails = $null

    try {
        # Keep this query simple. Some tenants reject heavier user $select payloads.
        $userUri = "https://graph.microsoft.com/v1.0/users/$encodedUserId?`$select=id,userPrincipalName,mail,proxyAddresses,assignedLicenses"
        $user = Invoke-MgGraphRequest -Method GET -Uri $userUri
    }
    catch {
        $errors += "User read failed: $($_.Exception.Message)"
    }

    try {
        # More reliable than assignedPlans for checking service-plan provisioning.
        $licenseUri = "https://graph.microsoft.com/v1.0/users/$encodedUserId/licenseDetails"
        $licenseDetails = Invoke-MgGraphRequest -Method GET -Uri $licenseUri
    }
    catch {
        $errors += "License details read failed: $($_.Exception.Message)"
    }

    $mail = $null
    $proxyAddresses = @()

    if ($null -ne $user) {
        $mail = [string](Get-ZTVPValue -Object $user -Name "mail")
        $proxyAddresses = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $user -Name "proxyAddresses"))
    }

    $smtpProxyPresent = $false

    foreach ($proxy in $proxyAddresses) {
        if ([string]$proxy -match "^SMTP:|^smtp:") {
            $smtpProxyPresent = $true
        }
    }

    $exchangePlans = @()
    $exchangePlanReady = $false
    $exchangePlanDetected = $false

    if ($null -ne $licenseDetails) {
        $licenseRows = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $licenseDetails -Name "value"))

        foreach ($license in $licenseRows) {
            $skuPartNumber = [string](Get-ZTVPValue -Object $license -Name "skuPartNumber")
            $servicePlans = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $license -Name "servicePlans"))

            foreach ($plan in $servicePlans) {
                $planName = [string](Get-ZTVPValue -Object $plan -Name "servicePlanName")
                $planStatus = [string](Get-ZTVPValue -Object $plan -Name "provisioningStatus")

                if ($planName -match "EXCHANGE") {
                    $exchangePlanDetected = $true

                    $exchangePlans += [PSCustomObject]@{
                        skuPartNumber = $skuPartNumber
                        servicePlanName = $planName
                        provisioningStatus = $planStatus
                    }

                    if ($planStatus -match "Success|Enabled") {
                        $exchangePlanReady = $true
                    }
                }
            }
        }
    }

    $readable = ($null -ne $user -or $null -ne $licenseDetails)
    $ready = ($exchangePlanReady -eq $true -or $smtpProxyPresent -eq $true -or -not [string]::IsNullOrWhiteSpace($mail))

    return [PSCustomObject]@{
        readable = $readable
        mail = $mail
        smtp_proxy_present = $smtpProxyPresent
        exchange_plan_detected = $exchangePlanDetected
        exchange_plan_enabled = $exchangePlanReady
        exchange_plans = @($exchangePlans)
        ready = $ready
        error = if ($errors.Count -gt 0) { ($errors -join " | ") } else { $null }
    }
}

function Wait-ZTVPMailboxReadiness
 {
    param(
        [string]$UserId,
        [int]$WaitMinutes
    )

    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    $checks = @()
    $last = $null

    do {
        $last = Get-ZTVPMailboxReadiness -UserId $UserId
        $checks += [PSCustomObject]@{
            checked_at = (Get-Date).ToString("s")
            ready = $last.ready
            mail = $last.mail
            exchange_plan_enabled = $last.exchange_plan_enabled
            error = $last.error
        }

        if ($last.ready -eq $true) {
            break
        }

        if ((Get-Date) -ge $deadline) {
            break
        }

        Start-Sleep -Seconds 30
    }
    while ($true)

    return [PSCustomObject]@{
        final = $last
        checks = @($checks)
    }
}

function New-ZTVPTextReaderWriter {
    param([System.IO.Stream]$Stream)

    $reader = New-Object System.IO.StreamReader($Stream, [System.Text.Encoding]::ASCII)
    $writer = New-Object System.IO.StreamWriter($Stream, [System.Text.Encoding]::ASCII)
    $writer.NewLine = "`r`n"
    $writer.AutoFlush = $true

    return [PSCustomObject]@{
        reader = $reader
        writer = $writer
    }
}

function Read-ZTVPSmtpResponse {
    param([System.IO.StreamReader]$Reader)

    $lines = @()
    $code = ""

    while ($true) {
        $line = $Reader.ReadLine()

        if ($null -eq $line) {
            break
        }

        $lines += $line

        if ($line.Length -ge 3 -and [string]::IsNullOrWhiteSpace($code)) {
            $code = $line.Substring(0, 3)
        }

        if ($line.Length -lt 4 -or $line[3] -ne '-') {
            break
        }
    }

    return [PSCustomObject]@{
        code = $code
        lines = @($lines)
        raw = ($lines -join "`n")
    }
}

function Invoke-ZTVPSmtpAuthAttempt {
    param(
        [string]$UserPrincipalName,
        [string]$Password
    )

    $client = $null

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.ReceiveTimeout = 20000
        $client.SendTimeout = 20000
        $client.Connect("smtp.office365.com", 587)

        $stream = $client.GetStream()
        $rw = New-ZTVPTextReaderWriter -Stream $stream
        $reader = $rw.reader
        $writer = $rw.writer

        $greeting = Read-ZTVPSmtpResponse -Reader $reader

        $writer.WriteLine("EHLO ztvp.local")
        $ehlo1 = Read-ZTVPSmtpResponse -Reader $reader

        $writer.WriteLine("STARTTLS")
        $startTls = Read-ZTVPSmtpResponse -Reader $reader

        if ($startTls.code -ne "220") {
            throw "SMTP STARTTLS was not accepted: $($startTls.raw)"
        }

        $ssl = New-Object System.Net.Security.SslStream($stream, $false)
        $ssl.AuthenticateAsClient("smtp.office365.com")

        $rw2 = New-ZTVPTextReaderWriter -Stream $ssl
        $reader = $rw2.reader
        $writer = $rw2.writer

        $writer.WriteLine("EHLO ztvp.local")
        $ehlo2 = Read-ZTVPSmtpResponse -Reader $reader

        $writer.WriteLine("AUTH LOGIN")
        $authPrompt = Read-ZTVPSmtpResponse -Reader $reader

        $user64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($UserPrincipalName))
        $pass64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Password))

        $writer.WriteLine($user64)
        $userPrompt = Read-ZTVPSmtpResponse -Reader $reader

        $writer.WriteLine($pass64)
        $authResult = Read-ZTVPSmtpResponse -Reader $reader

        try { $writer.WriteLine("QUIT") | Out-Null } catch {}

        $success = ($authResult.code -eq "235")
        $blocked = (-not $success)

        return [PSCustomObject]@{
            protocol = "SMTP"
            target = "smtp.office365.com:587"
            attempted = $true
            success = $success
            blocked_or_denied = $blocked
            outcome = if ($success) { "Authenticated" } else { "RejectedOrBlocked" }
            status_code = $authResult.code
            server_response = $authResult.raw
            evidence_summary = if ($success) { "SMTP AUTH accepted the decoy username/password." } else { "SMTP AUTH rejected or blocked the decoy username/password." }
        }
    }
    catch {
        return [PSCustomObject]@{
            protocol = "SMTP"
            target = "smtp.office365.com:587"
            attempted = $true
            success = $false
            blocked_or_denied = $false
            outcome = "Error"
            status_code = $null
            server_response = $_.Exception.Message
            evidence_summary = "SMTP AUTH test could not complete."
        }
    }
    finally {
        if ($client) { try { $client.Close() } catch {} }
    }
}

function Invoke-ZTVPImapAuthAttempt {
    param(
        [string]$UserPrincipalName,
        [string]$Password
    )

    $client = $null

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.ReceiveTimeout = 20000
        $client.SendTimeout = 20000
        $client.Connect("outlook.office365.com", 993)

        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false)
        $ssl.AuthenticateAsClient("outlook.office365.com")

        $rw = New-ZTVPTextReaderWriter -Stream $ssl
        $reader = $rw.reader
        $writer = $rw.writer

        $greeting = $reader.ReadLine()

        $safeUser = $UserPrincipalName.Replace('\', '\\').Replace('"', '\"')
        $safePass = $Password.Replace('\', '\\').Replace('"', '\"')

        $writer.WriteLine("A1 LOGIN `"$safeUser`" `"$safePass`"")

        $lines = @()

        for ($i = 0; $i -lt 50; $i++) {
            $line = $reader.ReadLine()

            if ($null -eq $line) { break }

            $lines += $line

            if ($line -match "^A1\s+") { break }
        }

        try { $writer.WriteLine("A2 LOGOUT") | Out-Null } catch {}

        $raw = $lines -join "`n"
        $success = ($raw -match "^A1\s+OK")
        $blocked = (-not $success)

        return [PSCustomObject]@{
            protocol = "IMAP"
            target = "outlook.office365.com:993"
            attempted = $true
            success = $success
            blocked_or_denied = $blocked
            outcome = if ($success) { "Authenticated" } else { "RejectedOrBlocked" }
            status_code = $null
            server_response = $raw
            evidence_summary = if ($success) { "IMAP LOGIN accepted the decoy username/password." } else { "IMAP LOGIN rejected or blocked the decoy username/password." }
        }
    }
    catch {
        return [PSCustomObject]@{
            protocol = "IMAP"
            target = "outlook.office365.com:993"
            attempted = $true
            success = $false
            blocked_or_denied = $false
            outcome = "Error"
            status_code = $null
            server_response = $_.Exception.Message
            evidence_summary = "IMAP test could not complete."
        }
    }
    finally {
        if ($client) { try { $client.Close() } catch {} }
    }
}

function Invoke-ZTVPPopAuthAttempt {
    param(
        [string]$UserPrincipalName,
        [string]$Password
    )

    $client = $null

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.ReceiveTimeout = 20000
        $client.SendTimeout = 20000
        $client.Connect("outlook.office365.com", 995)

        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false)
        $ssl.AuthenticateAsClient("outlook.office365.com")

        $rw = New-ZTVPTextReaderWriter -Stream $ssl
        $reader = $rw.reader
        $writer = $rw.writer

        $greeting = $reader.ReadLine()

        $writer.WriteLine("USER $UserPrincipalName")
        $userResult = $reader.ReadLine()

        $writer.WriteLine("PASS $Password")
        $passResult = $reader.ReadLine()

        try { $writer.WriteLine("QUIT") | Out-Null } catch {}

        $raw = @($greeting, $userResult, $passResult) -join "`n"
        $success = ($passResult -match "^\+OK")
        $blocked = (-not $success)

        return [PSCustomObject]@{
            protocol = "POP"
            target = "outlook.office365.com:995"
            attempted = $true
            success = $success
            blocked_or_denied = $blocked
            outcome = if ($success) { "Authenticated" } else { "RejectedOrBlocked" }
            status_code = $null
            server_response = $raw
            evidence_summary = if ($success) { "POP PASS accepted the decoy username/password." } else { "POP PASS rejected or blocked the decoy username/password." }
        }
    }
    catch {
        return [PSCustomObject]@{
            protocol = "POP"
            target = "outlook.office365.com:995"
            attempted = $true
            success = $false
            blocked_or_denied = $false
            outcome = "Error"
            status_code = $null
            server_response = $_.Exception.Message
            evidence_summary = "POP test could not complete."
        }
    }
    finally {
        if ($client) { try { $client.Close() } catch {} }
    }
}

function Get-ZTVPSignInsForUser {
    param(
        [string]$TargetUpn,
        [string]$TargetUserId,
        [datetime]$StartUtcDate
    )

    $all = @()
    $startUtc = $StartUtcDate.ToString("o")
    $safeUpn = $TargetUpn.Replace("'", "''")

    $filter = "createdDateTime ge $startUtc and userPrincipalName eq '$safeUpn'"
    $encodedFilter = [System.Uri]::EscapeDataString($filter)

    $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$encodedFilter"

    try {
        $all += @(Invoke-ZTVPPagedGraphQuery -Uri $uri -MaxPages 10)
    }
    catch {}

    if (-not [string]::IsNullOrWhiteSpace($TargetUserId)) {
        $filter2 = "createdDateTime ge $startUtc and userId eq '$TargetUserId'"
        $encodedFilter2 = [System.Uri]::EscapeDataString($filter2)
        $uri2 = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$encodedFilter2"

        try {
            $all += @(Invoke-ZTVPPagedGraphQuery -Uri $uri2 -MaxPages 10)
        }
        catch {}
    }

    try {
        $recent = @(Invoke-ZTVPPagedGraphQuery -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000" -MaxPages 10)
        $targetLower = $TargetUpn.Trim().ToLower()

        $all += @(
            $recent | Where-Object {
                ([string](Get-ZTVPValue -Object $_ -Name "userPrincipalName")).Trim().ToLower() -eq $targetLower
            }
        )
    }
    catch {}

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

    return $deduped
}

function Convert-ZTVPLegacySignInEvidence {
    param(
        [object[]]$SignIns,
        [datetime]$StartUtcDate
    )

    $rows = @()

    foreach ($signIn in $SignIns) {
        $createdRaw = [string](Get-ZTVPValue -Object $signIn -Name "createdDateTime")
        $statusObj = Get-ZTVPValue -Object $signIn -Name "status"
        $statusCode = Get-ZTVPValue -Object $statusObj -Name "errorCode"
        $failureReason = [string](Get-ZTVPValue -Object $statusObj -Name "failureReason")
        $additionalDetails = [string](Get-ZTVPValue -Object $statusObj -Name "additionalDetails")
        $clientAppUsed = [string](Get-ZTVPValue -Object $signIn -Name "clientAppUsed")
        $appDisplayName = [string](Get-ZTVPValue -Object $signIn -Name "appDisplayName")
        $resourceDisplayName = [string](Get-ZTVPValue -Object $signIn -Name "resourceDisplayName")
        $authProtocol = [string](Get-ZTVPValue -Object $signIn -Name "authenticationProtocol")
        $caStatus = [string](Get-ZTVPValue -Object $signIn -Name "conditionalAccessStatus")
        $policies = Get-ZTVPValue -Object $signIn -Name "appliedConditionalAccessPolicies"

        $success = ($statusCode -eq 0 -or [string]$statusCode -eq "0")
        $combined = "$clientAppUsed $appDisplayName $resourceDisplayName $authProtocol $failureReason $additionalDetails"

        $legacyEvidence = (
            $combined -match "IMAP" -or
            $combined -match "POP" -or
            $combined -match "SMTP" -or
            $combined -match "Authenticated SMTP" -or
            $combined -match "Exchange ActiveSync" -or
            $combined -match "ActiveSync" -or
            $combined -match "Other clients" -or
            $combined -match "MAPI"
        )

        $policyObjects = @()
        $legacyBlockPolicyApplied = $false
        $legacyBlockPolicyNames = @()

        foreach ($policy in @(ConvertTo-ZTVPArray $policies)) {
            if ($null -eq $policy) { continue }

            $policyName = [string](Get-ZTVPValue -Object $policy -Name "displayName")
            $policyResult = [string](Get-ZTVPValue -Object $policy -Name "result")
            $grantControls = @(ConvertTo-ZTVPArray (Get-ZTVPValue -Object $policy -Name "enforcedGrantControls"))

            $policyLooksLegacy = ($policyName -match "Legacy|Basic")
            $policyHasBlock = (($grantControls -join ",") -match "Block|block")
            $resultLower = $policyResult.Trim().ToLower()
            $isApplied = ($resultLower -ne "notapplied" -and $resultLower -notmatch "reportonly" -and -not [string]::IsNullOrWhiteSpace($resultLower))

            if ($policyLooksLegacy -and $policyHasBlock -and $isApplied) {
                $legacyBlockPolicyApplied = $true
                $legacyBlockPolicyNames += $policyName
                $legacyEvidence = $true
            }

            $policyObjects += [PSCustomObject]@{
                displayName = $policyName
                result = $policyResult
                enforcedGrantControls = @($grantControls)
                legacyDetected = $policyLooksLegacy
                blockGrantDetected = $policyHasBlock
                legacyBlockPolicyApplied = ($policyLooksLegacy -and $policyHasBlock -and $isApplied)
            }
        }

        $blocked = (
            $success -ne $true -and
            (
                $legacyBlockPolicyApplied -eq $true -or
                $caStatus -match "failure" -or
                $failureReason -match "blocked|Conditional Access|does not allow token issuance|access policy"
            )
        )

        if ($legacyEvidence -ne $true -and $blocked -ne $true) {
            continue
        }

        $rows += [PSCustomObject]@{
            CreatedDateTime = $createdRaw
            UserPrincipalName = Get-ZTVPValue -Object $signIn -Name "userPrincipalName"
            AppDisplayName = $appDisplayName
            ResourceDisplayName = $resourceDisplayName
            ClientAppUsed = $clientAppUsed
            AuthenticationProtocol = $authProtocol
            ConditionalAccessStatus = $caStatus
            StatusCode = $statusCode
            FailureReason = $failureReason
            AdditionalDetails = $additionalDetails
            Success = $success
            Blocked = $blocked
            LegacyBlockPolicyApplied = $legacyBlockPolicyApplied
            LegacyBlockPolicyNames = @($legacyBlockPolicyNames | Sort-Object -Unique)
            ConditionalAccessPolicies = @($policyObjects)
            IpAddress = Get-ZTVPValue -Object $signIn -Name "ipAddress"
        }
    }

    return $rows
}

$ctx = Ensure-ZTVPGraphConnection -Scopes $RequiredScopes

$stateDir = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-003"
$statePath = Join-Path $stateDir "decoy-state.json"
$secretPrivatePath = Join-Path $stateDir "decoy-secret-private.json"

if (-not (Test-Path $statePath)) {
    throw "No active ID-C-003 decoy state was found. Generate a licensed decoy first."
}

if (-not (Test-Path $secretPrivatePath)) {
    throw "Private local protocol-test secret was not found. Generate a new decoy or reset this run."
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json
$secret = Get-Content $secretPrivatePath -Raw | ConvertFrom-Json

$targetUpn = [string]$state.decoy_user.user_principal_name
$targetUserId = [string]$state.decoy_user.id
$password = [string]$secret.temporary_password

Write-Host ""
Write-Host "========================================="
Write-Host "ZTVP ID-C-003 - Controlled Legacy Authentication Exposure Validation"
Write-Host "========================================="
Write-Host ""
Write-Host "Target user: $targetUpn"
Write-Host "Mailbox wait minutes: $MailboxWaitMinutes"
Write-Host "Protocols: $Protocols"
Write-Host ""

$mailboxWait = Wait-ZTVPMailboxReadiness -UserId $targetUserId -WaitMinutes $MailboxWaitMinutes
$mailboxReady = [bool]$mailboxWait.final.ready

Write-Host "Mailbox readiness: $mailboxReady"

$protocolList = @(
    $Protocols.Split(",") |
    ForEach-Object { $_.Trim().ToUpper() } |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Sort-Object -Unique
)

$attempts = @()
$protocolTestsSkippedBecauseMailboxNotReady = $false

if ($mailboxReady -eq $true) {
    foreach ($protocol in $protocolList) {
        if ($protocol -eq "SMTP") {
            Write-Host "Testing SMTP AUTH..."
            $attempts += Invoke-ZTVPSmtpAuthAttempt -UserPrincipalName $targetUpn -Password $password
        }
        elseif ($protocol -eq "IMAP") {
            Write-Host "Testing IMAP LOGIN..."
            $attempts += Invoke-ZTVPImapAuthAttempt -UserPrincipalName $targetUpn -Password $password
        }
        elseif ($protocol -eq "POP") {
            Write-Host "Testing POP USER/PASS..."
            $attempts += Invoke-ZTVPPopAuthAttempt -UserPrincipalName $targetUpn -Password $password
        }
    }
}
else {
    $protocolTestsSkippedBecauseMailboxNotReady = $true
    Write-Host "Skipping SMTP/IMAP/POP tests because mailbox readiness was not confirmed."
}

$startUtcDate = (Get-Date).ToUniversalTime().AddMinutes(-1 * $LookbackMinutes)

Start-Sleep -Seconds 15

$rawSignIns = @(Get-ZTVPSignInsForUser -TargetUpn $targetUpn -TargetUserId $targetUserId -StartUtcDate $startUtcDate)
$signInEvidence = @(Convert-ZTVPLegacySignInEvidence -SignIns $rawSignIns -StartUtcDate $startUtcDate)

$successfulAttempts = @($attempts | Where-Object { $_.success -eq $true })
$blockedAttempts = @($attempts | Where-Object { $_.blocked_or_denied -eq $true })
$errorAttempts = @($attempts | Where-Object { $_.outcome -eq "Error" })

$signInBlocked = @($signInEvidence | Where-Object { $_.Blocked -eq $true -or $_.LegacyBlockPolicyApplied -eq $true })
$legacyPolicyNames = @()

foreach ($row in $signInEvidence) {
    if ($row.LegacyBlockPolicyNames) {
        $legacyPolicyNames += @($row.LegacyBlockPolicyNames)
    }
}

$legacyPolicyNames = @(
    $legacyPolicyNames |
    Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
    Sort-Object -Unique
)


$warnings = @()

if ($successfulAttempts.Count -gt 0) {
    $status = "FAIL_LEGACY_AUTH_ALLOWED"
    $risk = "HIGH"
    $summary = "At least one legacy mail protocol accepted the decoy username/password."
    $finalClaim = "Legacy username/password authentication succeeded for the controlled licensed decoy mailbox. This is a high-risk exposure."
}
elseif ($mailboxReady -ne $true) {
    $status = "PARTIAL_MAILBOX_NOT_READY"
    $risk = "MEDIUM"
    $summary = "The decoy license was assigned, but Exchange mailbox readiness was not confirmed before protocol testing."
    $finalClaim = "This run cannot prove legacy-authentication blocking because the mailbox was not ready. Wait for Exchange provisioning, then re-run validation with the same active decoy or generate a fresh decoy."
}
elseif ($signInBlocked.Count -gt 0 -and $legacyPolicyNames.Count -gt 0) {
    $status = "PASS_LEGACY_AUTH_BLOCKED_STRONG"
    $risk = "LOW"
    $summary = "Legacy authentication did not succeed and Microsoft Entra sign-in evidence identified a blocking legacy-authentication policy."
    $finalClaim = "The tenant blocked the controlled legacy-authentication attempt and no legacy protocol accepted the decoy password."
}
elseif ($blockedAttempts.Count -gt 0) {
    $status = "PASS_LEGACY_AUTH_BLOCKED"
    $risk = "LOW"
    $summary = "Legacy authentication did not succeed. One or more tested protocols rejected or blocked username/password authentication."
    $finalClaim = "The controlled decoy could not authenticate through the tested legacy mail protocols."
}
elseif ($attempts.Count -eq 0) {
    $status = "PARTIAL_NO_PROTOCOLS_TESTED"
    $risk = "MEDIUM"
    $summary = "No legacy mail protocols were tested."
    $finalClaim = "No protocol authentication attempt was executed."
}
else {
    $status = "PARTIAL_INCONCLUSIVE"
    $risk = "MEDIUM"
    $summary = "The protocol attempts did not succeed, but the result was inconclusive because no clear block or Entra attribution was observed."
    $finalClaim = "The run did not prove legacy-authentication success, but enforcement attribution is incomplete."
}

if ($errorAttempts.Count -gt 0) {
    $warnings += "One or more protocol attempts ended in a connection or protocol error. Review protocol attempt details."
}

if ($mailboxReady -ne $true) {
    $warnings += "Mailbox readiness was not confirmed. Exchange mailbox provisioning may need more time after license assignment."
}

if ($legacyPolicyNames.Count -eq 0 -and $signInEvidence.Count -eq 0) {
    $warnings += "No matching Microsoft Entra legacy sign-in evidence was found yet. Sign-in logs can be delayed or the protocol may have been blocked before Entra produced detailed telemetry."
}

$result = [PSCustomObject]@{
    scenario_id = "ID-C-003"
    scenario_name = "Controlled Legacy Authentication Exposure Validation"
    pillar = "Identity"
    scope = "Cloud"
    generated_at = (Get-Date).ToString("s")
    tenant_id = $ctx.TenantId
    connected_account = $ctx.Account

    control_tested = "A licensed mailbox user should not be able to authenticate through legacy username/password mail protocols."
    expected_result = "SMTP AUTH, IMAP, and POP username/password authentication should be rejected or blocked."
    failure_condition = "Any tested legacy mail protocol accepts the decoy username/password."
    test_method = "Fresh licensed decoy user, Exchange-capable license assignment, mailbox readiness check, protocol authentication-only attempts, and Microsoft Entra sign-in evidence collection."
    final_claim = $finalClaim

    status = $status
    risk = $risk
    executive_summary = $summary
    warnings = @($warnings)

    decoy_user = [PSCustomObject]@{
        id = $targetUserId
        user_principal_name = $targetUpn
        assigned_license = $state.license.sku_part_number
    }

    mailbox_readiness = $mailboxWait
    protocol_attempts = @($attempts)

    policy_attribution = [PSCustomObject]@{
        legacy_block_policy_applied = ($legacyPolicyNames.Count -gt 0)
        legacy_block_policy_names = @($legacyPolicyNames)
        sign_in_blocked_evidence_count = $signInBlocked.Count
    }

    metrics = [PSCustomObject]@{
        mailbox_ready = $mailboxReady
        protocols_tested = $attempts.Count
        protocol_success_count = $successfulAttempts.Count
        protocol_blocked_or_denied_count = $blockedAttempts.Count
        protocol_error_count = $errorAttempts.Count
        protocol_tests_skipped_because_mailbox_not_ready = $protocolTestsSkippedBecauseMailboxNotReady
        entra_signins_retrieved = $rawSignIns.Count
        legacy_signin_evidence_count = $signInEvidence.Count
        entra_blocked_evidence_count = $signInBlocked.Count
        legacy_block_policy_names_count = $legacyPolicyNames.Count
    }

    evidence = @($signInEvidence)
}

$reportPath = Join-Path (Get-Location) "powershell\Reports\Dynamic\ID-C-003-result.json"

$result |
    ConvertTo-Json -Depth 100 |
    Set-Content -Path $reportPath -Encoding UTF8

Write-Host ""
Write-Host "========================================="
Write-Host "ID-C-003 COMPLETED"
Write-Host "========================================="
Write-Host ""
Write-Host "Status: $status"
Write-Host "Risk: $risk"
Write-Host "Mailbox ready: $mailboxReady"
Write-Host "Protocols tested: $($attempts.Count)"
Write-Host "Protocol successes: $($successfulAttempts.Count)"
Write-Host "Protocol blocked/denied: $($blockedAttempts.Count)"
Write-Host "Entra evidence rows: $($signInEvidence.Count)"
Write-Host "Report saved to: $reportPath"
Write-Host ""
