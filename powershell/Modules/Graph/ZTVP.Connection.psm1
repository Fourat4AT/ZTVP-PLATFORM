function Get-ZTVPGraphStatus {
    $context = Get-MgContext

    if (-not $context) {
        return [PSCustomObject]@{
            Connected = $false
            Account   = $null
            TenantId  = $null
        }
    }

    [PSCustomObject]@{
        Connected = $true
        Account   = $context.Account
        TenantId  = $context.TenantId
    }
}

function Ensure-ZTVPGraphConnection {
    $status = Get-ZTVPGraphStatus
    if ($status.Connected) { return $status }
    throw "Microsoft Graph is not connected. Run connect_graph.ps1 first."
}

Export-ModuleMember -Function Get-ZTVPGraphStatus, Ensure-ZTVPGraphConnection
