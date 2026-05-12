function Get-ZTVPConditionalAccessPolicies {
    $caPolicies = @()

    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All

        foreach ($policy in $policies) {
            $coversAdmins = $false
            $allowsExclusions = $false

            $users = $policy.Conditions.Users

            if ($users.IncludeUsers -and ($users.IncludeUsers -contains "All")) {
                $coversAdmins = $true
            }

            if ($users.IncludeRoles -and $users.IncludeRoles.Count -gt 0) {
                $coversAdmins = $true
            }

            if ($users.ExcludeUsers -and $users.ExcludeUsers.Count -gt 0) {
                $allowsExclusions = $true
            }

            if ($users.ExcludeRoles -and $users.ExcludeRoles.Count -gt 0) {
                $allowsExclusions = $true
            }

            $caPolicies += [PSCustomObject]@{
                name              = $policy.DisplayName
                enabled           = ($policy.State -eq "enabled")
                covers_admins     = [bool]$coversAdmins
                allows_exclusions = [bool]$allowsExclusions
            }
        }
    }
    catch {
        Write-Warning "Conditional Access policies could not be retrieved."
        Write-Warning $_.Exception.Message
    }

    return $caPolicies
}

Export-ModuleMember -Function Get-ZTVPConditionalAccessPolicies
