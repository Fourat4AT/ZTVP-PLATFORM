function Get-ZTVPGraphContext {
    $context = Get-MgContext
    if (-not $context) {
        throw "Microsoft Graph is not connected. Run connect_graph.ps1 first."
    }
    return $context
}

function Get-ZTVPUsers {
    Get-ZTVPGraphContext | Out-Null

    $users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled
    return $users
}

function Get-ZTVPDirectoryRoles {
    Get-ZTVPGraphContext | Out-Null

    $roles = Get-MgDirectoryRole -All
    return $roles
}

function Get-ZTVPRoleMembers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RoleId
    )

    Get-ZTVPGraphContext | Out-Null

    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $RoleId -All
    return $members
}

Export-ModuleMember -Function Get-ZTVPGraphContext, Get-ZTVPUsers, Get-ZTVPDirectoryRoles, Get-ZTVPRoleMembers