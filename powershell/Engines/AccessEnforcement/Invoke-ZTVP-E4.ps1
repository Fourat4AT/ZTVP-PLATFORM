Import-Module "$PSScriptRoot\..\..\Modules\Common\ZTVP.Result.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\..\..\Modules\Graph\ZTVP.Connection.psm1" -Force -DisableNameChecking
Import-Module Microsoft.Graph.Identity.SignIns -Force -ErrorAction SilentlyContinue

function Convert-ZTVPE4ToArray {
    param($Value)

    $result = @()

    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $result += $item
        }
    }

    return $result
}

function Convert-ZTVPE4ToLowerArray {
    param($Value)

    $result = @()

    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $result += $item.ToString().ToLowerInvariant()
        }
    }

    return $result
}

function Get-ZTVPE4PolicyStateLabel {
    param([string]$State)

    switch ($State) {
        "enabled" { return "Enabled" }
        "enabledForReportingButNotEnforced" { return "Report-only" }
        "disabled" { return "Disabled" }
        default { return $State }
    }
}

function Get-ZTVPE4PropertyValue {
    param(
        $Object,
        [string[]]$Names
    )

    if ($null -eq $Object) {
        return $null
    }

    foreach ($name in $Names) {
        if ($Object.PSObject.Properties[$name]) {
            return $Object.$name
        }

        if ($Object.AdditionalProperties -and $Object.AdditionalProperties.ContainsKey($name)) {
            return $Object.AdditionalProperties[$name]
        }
    }

    return $null
}

function Get-ZTVPE4CidrFromRange {
    param($Range)

    if ($null -eq $Range) {
        return $null
    }

    $cidr = Get-ZTVPE4PropertyValue -Object $Range -Names @("CidrAddress", "cidrAddress")

    if (-not [string]::IsNullOrWhiteSpace($cidr)) {
        return $cidr
    }

    $text = $Range.ToString()

    if ($text -match "\d+\.\d+\.\d+\.\d+\/\d+" -or $text -match ":.*\/\d+") {
        return $text
    }

    return $null
}

function Get-ZTVPE4CidrPrefix {
    param([string]$Cidr)

    if ([string]::IsNullOrWhiteSpace($Cidr)) {
        return $null
    }

    if ($Cidr -notmatch "/") {
        if ($Cidr -match ":") {
            return 128
        }

        return 32
    }

    $parts = $Cidr.Split("/")
    $prefixText = $parts[$parts.Count - 1]

    $prefix = 0

    if ([int]::TryParse($prefixText, [ref]$prefix)) {
        return $prefix
    }

    return $null
}

function Get-ZTVPE4IpRisk {
    param([string]$Cidr)

    $prefix = Get-ZTVPE4CidrPrefix -Cidr $Cidr

    if ($null -eq $prefix) {
        return "UNKNOWN"
    }

    if ($Cidr -match ":") {
        if ($prefix -le 32) {
            return "CRITICAL"
        }
        elseif ($prefix -le 48) {
            return "HIGH"
        }

        return "LOW"
    }

    if ($prefix -le 8) {
        return "CRITICAL"
    }
    elseif ($prefix -le 16) {
        return "HIGH"
    }
    elseif ($prefix -le 24) {
        return "MEDIUM"
    }

    return "LOW"
}

function Get-ZTVPE4LocationType {
    param($Location)

    $odataType = Get-ZTVPE4PropertyValue -Object $Location -Names @("@odata.type")

    if ($odataType -match "ipNamedLocation") {
        return "IP"
    }

    if ($odataType -match "countryNamedLocation") {
        return "Country"
    }

    $ipRanges = Convert-ZTVPE4ToArray -Value (Get-ZTVPE4PropertyValue -Object $Location -Names @("IpRanges", "ipRanges"))
    $countries = Convert-ZTVPE4ToArray -Value (Get-ZTVPE4PropertyValue -Object $Location -Names @("CountriesAndRegions", "countriesAndRegions"))

    if ($ipRanges.Count -gt 0) {
        return "IP"
    }

    if ($countries.Count -gt 0) {
        return "Country"
    }

    return "Unknown"
}

function Get-ZTVPE4NamedLocationEvidence {
    param($Location)

    $type = Get-ZTVPE4LocationType -Location $Location

    $isTrusted = $false
    $trustedValue = Get-ZTVPE4PropertyValue -Object $Location -Names @("IsTrusted", "isTrusted")

    if ($trustedValue -eq $true) {
        $isTrusted = $true
    }

    $ipRangesRaw = Convert-ZTVPE4ToArray -Value (Get-ZTVPE4PropertyValue -Object $Location -Names @("IpRanges", "ipRanges"))
    $countriesRaw = Convert-ZTVPE4ToArray -Value (Get-ZTVPE4PropertyValue -Object $Location -Names @("CountriesAndRegions", "countriesAndRegions"))
    $includeUnknown = Get-ZTVPE4PropertyValue -Object $Location -Names @("IncludeUnknownCountriesAndRegions", "includeUnknownCountriesAndRegions")

    $cidrs = @()
    $countries = @()

    foreach ($range in $ipRangesRaw) {
        $cidr = Get-ZTVPE4CidrFromRange -Range $range

        if (-not [string]::IsNullOrWhiteSpace($cidr)) {
            $cidrs += $cidr
        }
    }

    foreach ($country in $countriesRaw) {
        if ($null -ne $country -and -not [string]::IsNullOrWhiteSpace($country.ToString())) {
            $countries += $country.ToString()
        }
    }

    $ipRisk = "LOW"
    $criticalCidrs = @()
    $highCidrs = @()
    $mediumCidrs = @()

    foreach ($cidr in $cidrs) {
        $risk = Get-ZTVPE4IpRisk -Cidr $cidr

        if ($risk -eq "CRITICAL") {
            $criticalCidrs += $cidr
            $ipRisk = "CRITICAL"
        }
        elseif ($risk -eq "HIGH") {
            $highCidrs += $cidr

            if ($ipRisk -ne "CRITICAL") {
                $ipRisk = "HIGH"
            }
        }
        elseif ($risk -eq "MEDIUM") {
            $mediumCidrs += $cidr

            if ($ipRisk -notin @("CRITICAL","HIGH")) {
                $ipRisk = "MEDIUM"
            }
        }
    }

    $isEmptyIpLocation = [bool]($type -eq "IP" -and $cidrs.Count -eq 0)

    return [PSCustomObject]@{
        id                         = $Location.Id
        name                       = $Location.DisplayName
        type                       = $type
        trusted                    = $isTrusted
        ip_ranges                  = $cidrs
        countries                  = $countries
        include_unknown_countries  = [bool]($includeUnknown -eq $true)
        ip_risk                    = $ipRisk
        empty_ip_location          = $isEmptyIpLocation
        critical_ip_ranges         = $criticalCidrs
        high_ip_ranges             = $highCidrs
        medium_ip_ranges           = $mediumCidrs
        has_critical_ip_range      = [bool]($criticalCidrs.Count -gt 0)
        has_high_ip_range          = [bool]($highCidrs.Count -gt 0)
        has_medium_ip_range        = [bool]($mediumCidrs.Count -gt 0)
    }
}

function Resolve-ZTVPE4LocationReference {
    param(
        [string]$Reference,
        $LocationMap
    )

    if ([string]::IsNullOrWhiteSpace($Reference)) {
        return "Unknown"
    }

    $key = $Reference.ToLowerInvariant()

    if ($key -eq "all") {
        return "All locations"
    }

    if ($key -eq "alltrusted") {
        return "All trusted locations"
    }

    if ($LocationMap.ContainsKey($key)) {
        return $LocationMap[$key].name
    }

    return $Reference
}

function Test-ZTVPE4AllTrustedReference {
    param([string]$Reference)

    if ([string]::IsNullOrWhiteSpace($Reference)) {
        return $false
    }

    return ($Reference.ToLowerInvariant() -eq "alltrusted")
}




function Test-ZTVPE4ActualTrustedReference {
    param(
        [string]$Reference,
        $LocationMap,
        [int]$TrustedLocationCount
    )

    if ([string]::IsNullOrWhiteSpace($Reference)) {
        return $false
    }

    $key = $Reference.ToLowerInvariant()

    # All trusted locations is only an active trusted-network exclusion
    # if at least one trusted location is actually populated/useful.
    if ($key -eq "alltrusted") {
        return ($TrustedLocationCount -gt 0)
    }

    if ($LocationMap.ContainsKey($key)) {
        $location = $LocationMap[$key]

        if ($location.trusted -ne $true) {
            return $false
        }

        # Empty IP named locations should not be treated as active trusted-network bypasses.
        if ($location.type -eq "IP" -and $location.empty_ip_location -eq $true) {
            return $false
        }

        return $true
    }

    return $false
}

function Test-ZTVPE4LocationReferenceIsCountry {
    param(
        [string]$Reference,
        $LocationMap
    )

    if ([string]::IsNullOrWhiteSpace($Reference)) {
        return $false
    }

    $key = $Reference.ToLowerInvariant()

    if ($LocationMap.ContainsKey($key) -and $LocationMap[$key].type -eq "Country") {
        return $true
    }

    return $false
}

function Test-ZTVPE4PolicyBlocksAccess {
    param($Policy)

    if ($null -eq $Policy -or $null -eq $Policy.GrantControls) {
        return $false
    }

    $builtIn = Convert-ZTVPE4ToLowerArray -Value $Policy.GrantControls.BuiltInControls

    return ($builtIn -contains "block")
}

function Invoke-ZTVP-E4 {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== E4 - Named Location and Trusted Network Review ===" -ForegroundColor Cyan

    try {
        Ensure-ZTVPGraphConnection | Out-Null

        $findings = @()
        $recommendations = @()

        try {
            $namedLocationsRaw = @(Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop)
            $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        }
        catch {
            return New-ZTVPResult `
                -ScenarioId "E4" `
                -ScenarioName "Named Location and Trusted Network Review" `
                -Category "Access Enforcement" `
                -Status "ERROR" `
                -Risk "CRITICAL" `
                -Findings @(
                    New-ZTVPFinding `
                        -Title "Named location or Conditional Access evidence unavailable" `
                        -Detail $_.Exception.Message
                ) `
                -Recommendations @(
                    New-ZTVPRecommendation `
                        -Title "Fix Graph collection" `
                        -Detail "Grant or consent permissions to read Conditional Access named locations and policies, then rerun E4."
                ) `
                -Evidence $null `
                -CurrentState "Named locations or Conditional Access policies could not be collected." `
                -ZeroTrustTarget "Named locations and trusted networks should be precise, documented, and not used as broad access bypasses." `
                -GapSummary "The scenario could not be evaluated because Graph evidence was unavailable."
        }

        $namedLocations = @()
        $locationMap = @{}

        foreach ($location in $namedLocationsRaw) {
            $evidence = Get-ZTVPE4NamedLocationEvidence -Location $location
            $namedLocations += $evidence

            if (-not [string]::IsNullOrWhiteSpace($evidence.id)) {
                $locationMap[$evidence.id.ToLowerInvariant()] = $evidence
            }
        }

        $trustedLocations = @($namedLocations | Where-Object { $_.trusted -eq $true })
        $trustedEmptyIpLocations = @($trustedLocations | Where-Object { $_.type -eq "IP" -and $_.empty_ip_location -eq $true })
        $trustedNonEmptyLocations = @($trustedLocations | Where-Object { -not ($_.type -eq "IP" -and $_.empty_ip_location -eq $true) })

        $trustedLocationCount = $trustedLocations.Count
        $trustedEmptyIpLocationCount = $trustedEmptyIpLocations.Count
        $trustedNonEmptyLocationCount = $trustedNonEmptyLocations.Count

        $policyUsage = @()
        $countryBlockPolicies = @()

        foreach ($policy in $policies) {
            if ($null -eq $policy) {
                continue
            }

            $state = ""
            if ($null -ne $policy.State) {
                $state = $policy.State.ToString()
            }

            $includeLocations = @()
            $excludeLocations = @()

            if ($policy.Conditions -and $policy.Conditions.Locations) {
                $includeLocations = @(Convert-ZTVPE4ToLowerArray -Value $policy.Conditions.Locations.IncludeLocations)
                $excludeLocations = @(Convert-ZTVPE4ToLowerArray -Value $policy.Conditions.Locations.ExcludeLocations)
            }

            $includeNames = @($includeLocations | ForEach-Object { Resolve-ZTVPE4LocationReference -Reference $_ -LocationMap $locationMap })
            $excludeNames = @($excludeLocations | ForEach-Object { Resolve-ZTVPE4LocationReference -Reference $_ -LocationMap $locationMap })

            $referencesAllTrusted = $false
            $excludesActualTrusted = $false

            foreach ($ref in $excludeLocations) {
                if (Test-ZTVPE4AllTrustedReference -Reference $ref) {
                    $referencesAllTrusted = $true
                }

                if (Test-ZTVPE4ActualTrustedReference -Reference $ref -LocationMap $locationMap -TrustedLocationCount $trustedNonEmptyLocationCount) {
                    $excludesActualTrusted = $true
                }
            }

            $excludedCountryNames = @()

            foreach ($ref in $excludeLocations) {
                if (Test-ZTVPE4LocationReferenceIsCountry -Reference $ref -LocationMap $locationMap) {
                    $excludedCountryNames += (Resolve-ZTVPE4LocationReference -Reference $ref -LocationMap $locationMap)
                }
            }

            $isBlockPolicy = Test-ZTVPE4PolicyBlocksAccess -Policy $policy
            $includesAllLocations = ($includeLocations -contains "all")

            $isCountryBlockPolicy = [bool](
                $isBlockPolicy -eq $true -and
                $includesAllLocations -eq $true -and
                $excludedCountryNames.Count -gt 0
            )

            $usage = [PSCustomObject]@{
                name                                  = $policy.DisplayName
                state                                 = $state
                state_label                           = Get-ZTVPE4PolicyStateLabel -State $state
                enabled                               = ($state -eq "enabled")
                report_only                           = ($state -eq "enabledForReportingButNotEnforced")
                disabled                              = ($state -eq "disabled")
                is_block_policy                       = $isBlockPolicy
                include_location_names                = $includeNames
                exclude_location_names                = $excludeNames
                excluded_country_locations            = $excludedCountryNames
                references_all_trusted_locations      = $referencesAllTrusted
                excludes_actual_trusted_locations     = $excludesActualTrusted
                references_all_trusted_but_none_exist = [bool]($referencesAllTrusted -eq $true -and $trustedLocationCount -eq 0)
                references_all_trusted_but_only_empty_exist = [bool]($referencesAllTrusted -eq $true -and $trustedLocationCount -gt 0 -and $trustedNonEmptyLocationCount -eq 0)
                country_based_block_policy            = $isCountryBlockPolicy
            }

            if ($includeLocations.Count -gt 0 -or $excludeLocations.Count -gt 0) {
                $policyUsage += $usage
            }

            if ($isCountryBlockPolicy) {
                $countryBlockPolicies += $usage
            }
        }

        $ipLocations = @($namedLocations | Where-Object { $_.type -eq "IP" })
        $countryLocations = @($namedLocations | Where-Object { $_.type -eq "Country" })

        $emptyIpLocations = @($ipLocations | Where-Object { $_.empty_ip_location -eq $true })
        $criticalTrustedIpLocations = @($trustedLocations | Where-Object { $_.has_critical_ip_range -eq $true })
        $highTrustedIpLocations = @($trustedLocations | Where-Object { $_.has_high_ip_range -eq $true })
        $mediumTrustedIpLocations = @($trustedLocations | Where-Object { $_.has_medium_ip_range -eq $true })
        $unknownCountryLocations = @($countryLocations | Where-Object { $_.include_unknown_countries -eq $true })

        $enabledCountryBlockPolicies = @($countryBlockPolicies | Where-Object { $_.enabled -eq $true })
        $reportOnlyCountryBlockPolicies = @($countryBlockPolicies | Where-Object { $_.report_only -eq $true })

        $enabledPoliciesExcludingActualTrusted = @($policyUsage | Where-Object { $_.enabled -eq $true -and $_.excludes_actual_trusted_locations -eq $true })
        $reportOnlyPoliciesExcludingActualTrusted = @($policyUsage | Where-Object { $_.report_only -eq $true -and $_.excludes_actual_trusted_locations -eq $true })

        $enabledPoliciesReferencingAllTrustedButNone = @($policyUsage | Where-Object { $_.enabled -eq $true -and $_.references_all_trusted_but_none_exist -eq $true })
        $reportOnlyPoliciesReferencingAllTrustedButNone = @($policyUsage | Where-Object { $_.report_only -eq $true -and $_.references_all_trusted_but_none_exist -eq $true })

        $enabledPoliciesReferencingAllTrustedButOnlyEmpty = @($policyUsage | Where-Object { $_.enabled -eq $true -and $_.references_all_trusted_but_only_empty_exist -eq $true })
        $reportOnlyPoliciesReferencingAllTrustedButOnlyEmpty = @($policyUsage | Where-Object { $_.report_only -eq $true -and $_.references_all_trusted_but_only_empty_exist -eq $true })

        if ($enabledCountryBlockPolicies.Count -gt 0) {
            $affected = $enabledCountryBlockPolicies | ForEach-Object { "$($_.name) [Allowed country/location: $($_.excluded_country_locations -join ", ")]" }

            $findings += New-ZTVPFinding `
                -Title "Country-based location control detected" `
                -Detail ("An enabled Conditional Access location policy blocks all locations except the configured allowed country/location. Policies: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Maintain country-based access control" `
                -Detail "Keep the allowed-country named location documented and periodically review whether users should be allowed from additional countries."
        }
        elseif ($reportOnlyCountryBlockPolicies.Count -gt 0) {
            $affected = $reportOnlyCountryBlockPolicies | ForEach-Object { "$($_.name) [Allowed country/location: $($_.excluded_country_locations -join ", ")]" }

            $findings += New-ZTVPFinding `
                -Title "Country-based location control is report-only" `
                -Detail ("A country-based block policy exists but is report-only and does not enforce access restrictions. Policies: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Enable country-based location control after validation" `
                -Detail "Review report-only impact, then enable the block policy if the business requirement is to block access outside the allowed country."
        }
        elseif ($countryLocations.Count -gt 0) {
            $affected = $countryLocations | ForEach-Object { $_.name }

            $findings += New-ZTVPFinding `
                -Title "Country named location exists but no enabled country block policy was detected" `
                -Detail ("Country named locations exist, but no enabled policy was detected that blocks all locations except those country locations. Locations: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Create or enable country-based block policy if required" `
                -Detail "If the tenant should block access from outside the approved country, use a Conditional Access policy with Include: All locations, Exclude: approved country named location, Grant: Block."
        }

        if ($emptyIpLocations.Count -gt 0) {
            $affected = $emptyIpLocations | ForEach-Object { $_.name }

            $findings += New-ZTVPFinding `
                -Title "IP named locations have no IP ranges" `
                -Detail ("Some IP named locations do not contain IP ranges. These may be stale placeholders, incomplete company/VPN/SAW locations, or unused named locations. Locations: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Populate or remove empty IP named locations" `
                -Detail "If the company has stable office, VPN, or admin workstation public egress IPs, populate those named locations. If not, remove stale empty IP named locations."
        }

        if ($trustedLocationCount -eq 0 -and ($enabledPoliciesReferencingAllTrustedButNone.Count -gt 0 -or $reportOnlyPoliciesReferencingAllTrustedButNone.Count -gt 0)) {
            $affected = @($enabledPoliciesReferencingAllTrustedButNone + $reportOnlyPoliciesReferencingAllTrustedButNone | ForEach-Object { $_.name } | Sort-Object -Unique)

            $findings += New-ZTVPFinding `
                -Title "Policies reference All trusted locations, but no trusted locations exist" `
                -Detail ("Conditional Access policies reference All trusted locations, but the tenant has no trusted named locations configured. This is a configuration mismatch, not an active trusted-network bypass. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Decide whether trusted IP locations are part of the design" `
                -Detail "If trusted network exceptions are needed, define narrow company/VPN/SAW public egress IP ranges and mark only those as trusted. If trusted locations are not used, remove All trusted locations exclusions from policies."
        }

        if ($trustedLocationCount -gt 0 -and $trustedNonEmptyLocationCount -eq 0 -and ($enabledPoliciesReferencingAllTrustedButOnlyEmpty.Count -gt 0 -or $reportOnlyPoliciesReferencingAllTrustedButOnlyEmpty.Count -gt 0)) {
            $affected = @($enabledPoliciesReferencingAllTrustedButOnlyEmpty + $reportOnlyPoliciesReferencingAllTrustedButOnlyEmpty | ForEach-Object { $_.name } | Sort-Object -Unique)

            $findings += New-ZTVPFinding `
                -Title "Policies reference All trusted locations, but trusted IP locations are empty" `
                -Detail ("Conditional Access policies reference All trusted locations, but all trusted IP named locations are empty. This is an incomplete trusted-location design, not a confirmed active network bypass. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Populate or clean up trusted IP location references" `
                -Detail "If trusted network exceptions are intended, populate trusted named locations with narrow company/VPN/SAW public egress IP ranges. If not intended, remove All trusted locations exclusions from policies."
        }

        if ($criticalTrustedIpLocations.Count -gt 0) {
            $affected = $criticalTrustedIpLocations | ForEach-Object { "$($_.name) [$($_.critical_ip_ranges -join ", ")]" }

            $findings += New-ZTVPFinding `
                -Title "Trusted location contains extremely broad IP ranges" `
                -Detail ("Trusted named locations contain extremely broad IP ranges. Locations: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Reduce extremely broad trusted IP ranges" `
                -Detail "Remove or narrow broad trusted IP ranges. Trusted network definitions should be limited to known corporate egress ranges and documented."
        }

        if ($highTrustedIpLocations.Count -gt 0) {
            $affected = $highTrustedIpLocations | ForEach-Object { "$($_.name) [$($_.high_ip_ranges -join ", ")]" }

            $findings += New-ZTVPFinding `
                -Title "Trusted location contains broad IP ranges" `
                -Detail ("Trusted named locations contain broad IP ranges that should be reviewed. Locations: " + ($affected -join " | "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review broad trusted IP ranges" `
                -Detail "Validate that broad trusted ranges are required, owned, documented, and not shared with unmanaged networks."
        }

        if ($unknownCountryLocations.Count -gt 0) {
            $affected = $unknownCountryLocations | ForEach-Object { $_.name }

            $findings += New-ZTVPFinding `
                -Title "Country named locations include unknown countries" `
                -Detail ("Some country named locations include unknown countries or regions. Locations: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review unknown country handling" `
                -Detail "Avoid including unknown countries unless there is a clear business reason."
        }

        if ($enabledPoliciesExcludingActualTrusted.Count -gt 0) {
            $affected = $enabledPoliciesExcludingActualTrusted | ForEach-Object { $_.name }

            $findings += New-ZTVPFinding `
                -Title "Enabled policies exclude actual trusted locations" `
                -Detail ("Enabled Conditional Access policies exclude trusted named locations that currently exist. Policies: " + ($affected -join ", "))

            $recommendations += New-ZTVPRecommendation `
                -Title "Review active trusted-location exclusions" `
                -Detail "Confirm each trusted-location exclusion is required, narrow, documented, and not used as a broad bypass for MFA, device, or risk controls."
        }

        if ($namedLocations.Count -gt 0 -and $findings.Count -eq 0) {
            $findings += New-ZTVPFinding `
                -Title "No high-risk named location issue detected" `
                -Detail "Named locations were collected and no major named-location or trusted-network issue was detected."

            $recommendations += New-ZTVPRecommendation `
                -Title "Continue named location governance" `
                -Detail "Review named locations periodically and validate that location-based controls remain accurate."
        }

        $status = "PASS"
        $risk = "LOW"

        if ($criticalTrustedIpLocations.Count -gt 0) {
            $status = "FAIL"
            $risk = "CRITICAL"
        }
        elseif (
            $highTrustedIpLocations.Count -gt 0 -or
            $unknownCountryLocations.Count -gt 0 -or
            $enabledPoliciesExcludingActualTrusted.Count -gt 0 -or
            ($countryLocations.Count -gt 0 -and $enabledCountryBlockPolicies.Count -eq 0 -and $reportOnlyCountryBlockPolicies.Count -gt 0)
        ) {
            $status = "PARTIAL"
            $risk = "HIGH"
        }
        elseif (
            $mediumTrustedIpLocations.Count -gt 0 -or
            $emptyIpLocations.Count -gt 0 -or
            $enabledPoliciesReferencingAllTrustedButNone.Count -gt 0 -or
            $reportOnlyPoliciesReferencingAllTrustedButNone.Count -gt 0 -or
            $enabledPoliciesReferencingAllTrustedButOnlyEmpty.Count -gt 0 -or
            $reportOnlyPoliciesReferencingAllTrustedButOnlyEmpty.Count -gt 0 -or
            $reportOnlyPoliciesExcludingActualTrusted.Count -gt 0 -or
            ($countryLocations.Count -gt 0 -and $enabledCountryBlockPolicies.Count -eq 0)
        ) {
            $status = "PARTIAL"
            $risk = "MEDIUM"
        }

        $countryStrategy = "Not detected"
        if ($enabledCountryBlockPolicies.Count -gt 0) {
            $countryStrategy = "Enabled country-based block control detected"
        }
        elseif ($reportOnlyCountryBlockPolicies.Count -gt 0) {
            $countryStrategy = "Country-based block control exists but is report-only"
        }
        elseif ($countryLocations.Count -gt 0) {
            $countryStrategy = "Country named location exists without enabled block control"
        }

        $ipStrategy = "No company IP trust strategy detected"

        if ($trustedLocationCount -gt 0 -and $trustedNonEmptyLocationCount -gt 0) {
            $ipStrategy = "Trusted IP locations configured and populated"
        }
        elseif ($trustedLocationCount -gt 0 -and $trustedNonEmptyLocationCount -eq 0) {
            $ipStrategy = "Trusted IP location objects exist but they are empty"
        }
        elseif ($ipLocations.Count -gt 0 -and $emptyIpLocations.Count -eq 0) {
            $ipStrategy = "IP named locations configured but not trusted"
        }
        elseif ($ipLocations.Count -gt 0 -and $emptyIpLocations.Count -gt 0) {
            $ipStrategy = "IP named locations exist but some are empty"
        }

        $currentState = @(
            "Named locations assessed: $($namedLocations.Count)."
            "Country strategy: $countryStrategy."
            "IP strategy: $ipStrategy."
            "Trusted locations: $($trustedLocationCount)."
            "Trusted populated locations: $($trustedNonEmptyLocationCount)."
            "Trusted empty IP locations: $($trustedEmptyIpLocationCount)."
            "IP named locations: $($ipLocations.Count)."
            "Empty IP named locations: $($emptyIpLocations.Count)."
            "Country named locations: $($countryLocations.Count)."
            "Enabled country-based block policies: $($enabledCountryBlockPolicies.Count)."
            "Report-only country-based block policies: $($reportOnlyCountryBlockPolicies.Count)."
            "Policies using locations: $($policyUsage.Count)."
            "Policies referencing All trusted locations while none exist: $($enabledPoliciesReferencingAllTrustedButNone.Count + $reportOnlyPoliciesReferencingAllTrustedButNone.Count)."
            "Policies referencing All trusted locations while trusted IPs are empty: $($enabledPoliciesReferencingAllTrustedButOnlyEmpty.Count + $reportOnlyPoliciesReferencingAllTrustedButOnlyEmpty.Count)."
        ) -join " "

        $zeroTrustTarget = "Named locations should support an intentional access strategy. Country-based restrictions may be used to block access outside approved countries. IP named locations should be populated only when the organization has stable office, VPN, or admin workstation public egress IPs. Trusted locations should be narrow, documented, and not used as broad access bypasses."

        if ($status -eq "PASS") {
            $gapSummary = "Named location posture appears aligned with the current location strategy."
            $executiveSummary = "Named location posture appears controlled. The tenant location strategy is intentional and no major named-location hygiene issue was detected."
        }
        elseif ($status -eq "PARTIAL") {
            $gapSummary = "Named location posture requires review because location strategy, empty IP named locations, trusted-location references, or policy usage need cleanup."
            $executiveSummary = "Named location posture is partially controlled. Country-based controls may exist, but IP named locations, trusted-location references, or policy usage require review."
        }
        else {
            $gapSummary = "Named location posture is not aligned because trusted IP ranges are extremely broad and can create major Conditional Access bypass risk."
            $executiveSummary = "Critical trusted network risk detected. One or more trusted named locations contain extremely broad IP ranges."
        }

        return New-ZTVPResult `
            -ScenarioId "E4" `
            -ScenarioName "Named Location and Trusted Network Review" `
            -Category "Access Enforcement" `
            -Status $status `
            -Risk $risk `
            -Findings $findings `
            -Recommendations $recommendations `
            -Evidence ([PSCustomObject]@{
                executive_summary                                      = $executiveSummary
                country_strategy                                       = $countryStrategy
                ip_strategy                                            = $ipStrategy

                named_location_count                                   = $namedLocations.Count
                trusted_location_count                                 = $trustedLocationCount
                trusted_non_empty_location_count                       = $trustedNonEmptyLocationCount
                trusted_empty_ip_location_count                        = $trustedEmptyIpLocationCount
                ip_named_location_count                                = $ipLocations.Count
                empty_ip_named_location_count                          = $emptyIpLocations.Count
                country_named_location_count                           = $countryLocations.Count

                enabled_country_block_policy_count                     = $enabledCountryBlockPolicies.Count
                report_only_country_block_policy_count                 = $reportOnlyCountryBlockPolicies.Count

                critical_trusted_ip_location_count                     = $criticalTrustedIpLocations.Count
                high_trusted_ip_location_count                         = $highTrustedIpLocations.Count
                medium_trusted_ip_location_count                       = $mediumTrustedIpLocations.Count
                unknown_country_location_count                         = $unknownCountryLocations.Count
                policy_location_usage_count                            = $policyUsage.Count

                enabled_policy_excluding_actual_trusted_location_count = $enabledPoliciesExcludingActualTrusted.Count
                report_only_policy_excluding_actual_trusted_location_count = $reportOnlyPoliciesExcludingActualTrusted.Count
                enabled_policy_referencing_all_trusted_but_none_count  = $enabledPoliciesReferencingAllTrustedButNone.Count
                report_only_policy_referencing_all_trusted_but_none_count = $reportOnlyPoliciesReferencingAllTrustedButNone.Count
                enabled_policy_referencing_all_trusted_but_only_empty_count = $enabledPoliciesReferencingAllTrustedButOnlyEmpty.Count
                report_only_policy_referencing_all_trusted_but_only_empty_count = $reportOnlyPoliciesReferencingAllTrustedButOnlyEmpty.Count

                enabled_country_block_policies                         = $enabledCountryBlockPolicies
                report_only_country_block_policies                     = $reportOnlyCountryBlockPolicies
                empty_ip_named_locations                               = $emptyIpLocations
                critical_trusted_ip_locations                          = $criticalTrustedIpLocations
                high_trusted_ip_locations                              = $highTrustedIpLocations
                medium_trusted_ip_locations                            = $mediumTrustedIpLocations
                unknown_country_locations                              = $unknownCountryLocations
                enabled_policies_excluding_actual_trusted_locations    = $enabledPoliciesExcludingActualTrusted
                report_only_policies_excluding_actual_trusted_locations = $reportOnlyPoliciesExcludingActualTrusted
                enabled_policies_referencing_all_trusted_but_none      = $enabledPoliciesReferencingAllTrustedButNone
                report_only_policies_referencing_all_trusted_but_none  = $reportOnlyPoliciesReferencingAllTrustedButNone
                enabled_policies_referencing_all_trusted_but_only_empty = $enabledPoliciesReferencingAllTrustedButOnlyEmpty
                report_only_policies_referencing_all_trusted_but_only_empty = $reportOnlyPoliciesReferencingAllTrustedButOnlyEmpty
                named_locations                                        = $namedLocations
                policy_location_usage                                  = $policyUsage
            }) `
            -CurrentState $currentState `
            -ZeroTrustTarget $zeroTrustTarget `
            -GapSummary $gapSummary
    }
    catch {
        return New-ZTVPResult `
            -ScenarioId "E4" `
            -ScenarioName "Named Location and Trusted Network Review" `
            -Category "Access Enforcement" `
            -Status "ERROR" `
            -Risk "CRITICAL" `
            -Findings @(
                New-ZTVPFinding `
                    -Title "Execution error" `
                    -Detail $_.Exception.Message
            ) `
            -Recommendations @(
                New-ZTVPRecommendation `
                    -Title "Fix execution issue" `
                    -Detail "Review Graph connection, permissions, named location collection, and Conditional Access policy collection."
            ) `
            -Evidence $null `
            -CurrentState "The engine could not complete named location and trusted network assessment." `
            -ZeroTrustTarget "Named locations and trusted networks should be limited, documented, and not used as broad access bypasses." `
            -GapSummary "The scenario could not be evaluated because execution failed."
    }
}

