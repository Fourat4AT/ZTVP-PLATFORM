function Get-ZTVPUserMfaState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    try {
        $methods = @(Get-MgUserAuthenticationMethod -UserId $UserPrincipalName -ErrorAction Stop)

        $methodNames = @()

        foreach ($method in $methods) {
            $odataType = $null

            if ($method.AdditionalProperties -and $method.AdditionalProperties.ContainsKey('@odata.type')) {
                $odataType = [string]$method.AdditionalProperties['@odata.type']
            }
            elseif ($method.PSObject.Properties['ODataType']) {
                $odataType = [string]$method.ODataType
            }

            switch -Wildcard ($odataType) {
                "*phoneAuthenticationMethod" {
                    $methodNames += "phone"
                }
                "*microsoftAuthenticatorAuthenticationMethod" {
                    $methodNames += "microsoft_authenticator"
                }
                "*fido2AuthenticationMethod" {
                    $methodNames += "fido2"
                }
                "*softwareOathAuthenticationMethod" {
                    $methodNames += "software_oath"
                }
                "*windowsHelloForBusinessAuthenticationMethod" {
                    $methodNames += "windows_hello"
                }
                "*emailAuthenticationMethod" {
                    $methodNames += "email"
                }
                "*temporaryAccessPassAuthenticationMethod" {
                    $methodNames += "temporary_access_pass"
                }
            }
        }

        $methodNames = @($methodNames | Select-Object -Unique)

        $weak = $false
        if ($methodNames -contains "phone" -or $methodNames -contains "email" -or $methodNames -contains "software_oath") {
            $weak = $true
        }

        return [PSCustomObject]@{
            mfa_enabled = ($methodNames.Count -gt 0)
            mfa_methods = $methodNames
            mfa_known   = $true
            weak_mfa    = $weak
            mfa_error   = $null
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ([string]::IsNullOrWhiteSpace($msg)) {
            $msg = ($_ | Out-String).Trim()
        }
        if ([string]::IsNullOrWhiteSpace($msg)) {
            $msg = "Unknown MFA lookup error"
        }

        return [PSCustomObject]@{
            mfa_enabled = $null
            mfa_methods = @()
            mfa_known   = $false
            weak_mfa    = $false
            mfa_error   = $msg
        }
    }
}

Export-ModuleMember -Function Get-ZTVPUserMfaState