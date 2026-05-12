Import-Module "$PSScriptRoot\ZTVP.MFA.psm1" -Force

function Get-ZTVPPrivilegedAccounts {
    $targetRoles = @(
        "Global Administrator",
        "Privileged Role Administrator",
        "Security Administrator",
        "Conditional Access Administrator",
        "Authentication Administrator",
        "User Administrator",
        "Helpdesk Administrator"
    )

    $roles = Get-MgDirectoryRole -All
    $matchedRoles = $roles | Where-Object { $_.DisplayName -in $targetRoles }

    $adminUsers = @()
    $seen = @{}

    foreach ($role in $matchedRoles) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All

        foreach ($member in $members) {
            $upn = $null
            $displayName = $null

            if ($member.AdditionalProperties.ContainsKey("userPrincipalName")) {
                $upn = $member.AdditionalProperties["userPrincipalName"]
            }

            if ($member.AdditionalProperties.ContainsKey("displayName")) {
                $displayName = $member.AdditionalProperties["displayName"]
            }

            if ([string]::IsNullOrWhiteSpace($upn)) {
                continue
            }

            $key = $upn.ToLowerInvariant()
            if ($seen.ContainsKey($key)) {
                continue
            }

            $seen[$key] = $true
            $mfa = Get-ZTVPUserMfaState -UserPrincipalName $upn

            $adminUsers += [PSCustomObject]@{
                userPrincipalName = $upn
                displayName       = $displayName
                role              = $role.DisplayName
                mfa_enabled       = $mfa.mfa_enabled
                mfa_methods       = $mfa.mfa_methods
                mfa_known         = $mfa.mfa_known
                weak_mfa          = $mfa.weak_mfa
                mfa_error         = $mfa.mfa_error
                excluded_from_ca  = $null
            }
        }
    }

    return $adminUsers
}

Export-ModuleMember -Function Get-ZTVPPrivilegedAccounts