param(
    [string]$ExchangeAdminUPN = "",
    [string]$StatePathOverride = ""
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$GraphScopes = @(
    "User.ReadWrite.All",
    "User.DeleteRestore.All",
    "Directory.ReadWrite.All"
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
        Connect-MgGraph -Scopes $Scopes -ContextScope CurrentUser -NoWelcome | Out-Null
    }
}

function Write-ZTVPJson {
    param([string]$Path, [object]$Object)

    $Object |
        ConvertTo-Json -Depth 100 |
        Set-Content -Path $Path -Encoding UTF8
}

function Test-ZTVPNotFound {
    param([string]$Message)

    return (
        $Message -match "404" -or
        $Message -match "not found" -or
        $Message -match "notfound" -or
        $Message -match "not found on" -or
        $Message -match "does not exist" -or
        $Message -match "doesn't exist" -or
        $Message -match "could not be found" -or
        $Message -match "couldn't be found" -or
        $Message -match "introuvable" -or
        $Message -match "n.existe pas" -or
        $Message -match "n’existe pas" -or
        $Message -match "ManagementObjectNotFoundException" -or
        $Message -match "ResourceNotFound"
    )
}

$reportRoot = Join-Path (Get-Location) "powershell\Reports\Dynamic"
$scenarioDir = Join-Path $reportRoot "APP-C-002"
$historyDir = Join-Path $scenarioDir "history"
$defaultStatePath = Join-Path $scenarioDir "appc002-state.json"
$statePath = $defaultStatePath
$usingStatePathOverride = -not [string]::IsNullOrWhiteSpace($StatePathOverride)

if ($usingStatePathOverride) {
    $statePath = $StatePathOverride
}

$cleanupPath = Join-Path $scenarioDir "appc002-cleanup-result.json"

New-Item -ItemType Directory -Path $historyDir -Force | Out-Null

if (-not (Test-Path $statePath)) {
    $result = [PSCustomObject]@{
        scenario_id = "APP-C-002"
        cleanup_status = "AlreadyClean"
        message = "No active APP-C-002 state file was found."
        cleaned_at = (Get-Date).ToString("s")
    }

    Write-ZTVPJson -Path $cleanupPath -Object $result
    Write-Host "No active APP-C-002 state file was found."
    exit 0
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

# APP-C-002 auto-fill ExchangeAdminUPN from active state
if ([string]::IsNullOrWhiteSpace($ExchangeAdminUPN)) {
    $ExchangeAdminUPN = [string]$state.connected_account
}


$userId = [string]$state.decoy_user.id
$userUpn = [string]$state.decoy_user.user_principal_name
$skuId = [string]$state.assigned_license.sku_id
$runId = [string]$state.run_id
$ruleName = [string]$state.forwarding_artifacts.inbox_rule_name
$contactName = "ZTVP APP-C-002 External Target $runId"

$actions = @()
$errors = @()

$module = Get-Module -ListAvailable -Name ExchangeOnlineManagement |
    Sort-Object Version -Descending |
    Select-Object -First 1

if ($module) {
    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($ExchangeAdminUPN)) {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop | Out-Null
        }
        else {
            Connect-ExchangeOnline -UserPrincipalName $ExchangeAdminUPN -ShowBanner:$false -ErrorAction Stop | Out-Null
        }

        try {
            Set-Mailbox `
                -Identity $userUpn `
                -ForwardingSmtpAddress $null `
                -ForwardingAddress $null `
                -DeliverToMailboxAndForward $false `
                -ErrorAction Stop

            $actions += "Cleared mailbox-level forwarding settings."
        }
        catch {
            $msg = $_.Exception.Message

            if (Test-ZTVPNotFound -Message $msg) {
                $actions += "Mailbox was already unavailable."
            }
            else {
                $errors += "Could not clear mailbox forwarding settings: $msg"
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($ruleName)) {
            try {
                $rules = @(Get-InboxRule -Mailbox $userUpn -ErrorAction Stop | Where-Object { $_.Name -eq $ruleName })

                foreach ($rule in $rules) {
                    Remove-InboxRule `
                        -Mailbox $userUpn `
                        -Identity $rule.Identity `
                        -Confirm:$false `
                        -ErrorAction Stop

                    $actions += "Removed inbox rule: $ruleName"
                }
            }
            catch {
                $msg = $_.Exception.Message

                if (Test-ZTVPNotFound -Message $msg) {
                    $actions += "Inbox rule or mailbox was already unavailable."
                }
                else {
                    $errors += "Could not remove inbox rule: $msg"
                }
            }
        }

        try {
            $contact = Get-MailContact -Identity $contactName -ErrorAction Stop
            Remove-MailContact `
                -Identity $contact.Identity `
                -Confirm:$false `
                -ErrorAction Stop

            $actions += "Removed temporary mail contact: $contactName"
        }
        catch {
            $msg = $_.Exception.Message

            if (Test-ZTVPNotFound -Message $msg) {
                $actions += "Temporary mail contact was already unavailable."
            }
            else {
                $errors += "Could not remove temporary mail contact: $msg"
            }
        }

        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
    catch {
        $errors += "Exchange cleanup connection failed: $($_.Exception.Message)"
    }
}
else {
    $errors += "ExchangeOnlineManagement module is missing. User cleanup will continue, but Exchange artifact cleanup could not be verified."
}

Ensure-ZTVPGraphConnection -Scopes $GraphScopes

if (-not [string]::IsNullOrWhiteSpace($userId)) {
    if (-not [string]::IsNullOrWhiteSpace($skuId)) {
        try {
            $licenseBody = @{
                addLicenses = @()
                removeLicenses = @($skuId)
            } | ConvertTo-Json -Depth 10

            Invoke-MgGraphRequest `
                -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/users/$userId/assignLicense" `
                -Body $licenseBody `
                -ContentType "application/json" | Out-Null

            $actions += "Removed assigned Exchange-capable license."
        }
        catch {
            $msg = $_.Exception.Message

            if (Test-ZTVPNotFound -Message $msg) {
                $actions += "Decoy user was already unavailable before license removal."
            }
            else {
                $errors += "License removal failed: $msg"
            }
        }
    }

    try {
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/users/$userId" | Out-Null
        $actions += "Deleted decoy user: $userUpn"
    }
    catch {
        $msg = $_.Exception.Message

        if (Test-ZTVPNotFound -Message $msg) {
            $actions += "Decoy user was already deleted."
        }
        else {
            $errors += "Decoy user deletion failed: $msg"
        }
    }

    try {
        Start-Sleep -Seconds 3
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/directory/deletedItems/$userId" | Out-Null
        $actions += "Permanently deleted decoy user from Entra deleted users: $userUpn"
    }
    catch {
        $msg = $_.Exception.Message

        if (Test-ZTVPNotFound -Message $msg) {
            $actions += "Decoy user was not present in Entra deleted users."
        }
        else {
            $errors += "Permanent deleted-user purge failed: $msg"
        }
    }
}

$status = if ($errors.Count -eq 0) { "Completed" } else { "Failed" }

$archivePath = if ($usingStatePathOverride) { $statePath } else { Join-Path $historyDir "appc002-state-$runId.json" }

if (-not $usingStatePathOverride) {
    try {
        $state | ConvertTo-Json -Depth 100 | Set-Content -Path $archivePath -Encoding UTF8
    }
    catch {}
}

if ($status -eq "Completed" -and -not $usingStatePathOverride) {
    Remove-Item $statePath -Force -ErrorAction SilentlyContinue
}

$result = [PSCustomObject]@{
    scenario_id = "APP-C-002"
    run_id = $runId
    cleaned_at = (Get-Date).ToString("s")
    cleanup_status = $status
    actions = @($actions)
    errors = @($errors)
    state_file_deleted = (-not (Test-Path $defaultStatePath))
    used_state_path = $statePath
}

Write-ZTVPJson -Path $cleanupPath -Object $result

Write-Host ""
Write-Host "APP-C-002 cleanup completed"
Write-Host "Status: $status"
Write-Host "Actions: $($actions -join '; ')"
Write-Host "Errors: $($errors -join '; ')"
Write-Host ""
