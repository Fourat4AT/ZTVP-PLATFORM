
        # ============================================================
        # Baseline Security - Cloud scenarios
        # ============================================================

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B1"
            Name         = "Tenant Security Defaults and Baseline Control Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate whether the tenant has a baseline protection model through Security Defaults or enabled custom Conditional Access controls."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B1.ps1"
            FunctionName = "Invoke-ZTVP-B1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B2"
            Name         = "Default User Permissions and App Registration Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review default user permissions such as app registration, group creation, and directory self-service capabilities."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B2.ps1"
            FunctionName = "Invoke-ZTVP-B2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B3"
            Name         = "User Consent and Enterprise App Baseline Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review user consent, admin consent workflow, and enterprise application consent baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B3.ps1"
            FunctionName = "Invoke-ZTVP-B3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B4"
            Name         = "Password and Account Protection Baseline Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review password protection, account protection, lockout, and self-service password reset baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B4.ps1"
            FunctionName = "Invoke-ZTVP-B4"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B5"
            Name         = "User Account Hygiene Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review stale, disabled, guest, unlicensed, and potentially unmanaged user account hygiene indicators."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B5.ps1"
            FunctionName = "Invoke-ZTVP-B5"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B1"
            Name         = "Tenant Security Defaults and Baseline Control Review"
            CategoryId   = "BASELINESECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate whether the tenant has a baseline protection model through Security Defaults or enabled custom Conditional Access controls."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B1.ps1"
            FunctionName = "Invoke-ZTVP-B1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B2"
            Name         = "Default User Permissions and App Registration Review"
            CategoryId   = "BASELINESECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review default user permissions such as app registration, group creation, and directory self-service capabilities."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B2.ps1"
            FunctionName = "Invoke-ZTVP-B2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B3"
            Name         = "User Consent and Enterprise App Baseline Review"
            CategoryId   = "BASELINESECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review user consent, admin consent workflow, and enterprise application consent baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B3.ps1"
            FunctionName = "Invoke-ZTVP-B3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B4"
            Name         = "Password and Account Protection Baseline Review"
            CategoryId   = "BASELINESECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review password protection, account protection, lockout, and self-service password reset baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B4.ps1"
            FunctionName = "Invoke-ZTVP-B4"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B5"
            Name         = "User Account Hygiene Review"
            CategoryId   = "BASELINESECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review stale, disabled, guest, unlicensed, and potentially unmanaged user account hygiene indicators."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B5.ps1"
            FunctionName = "Invoke-ZTVP-B5"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B1"
            Name         = "Tenant Security Defaults and Baseline Control Review"
            CategoryId   = "BASELINE_SECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate whether the tenant has a baseline protection model through Security Defaults or enabled custom Conditional Access controls."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B1.ps1"
            FunctionName = "Invoke-ZTVP-B1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B2"
            Name         = "Default User Permissions and App Registration Review"
            CategoryId   = "BASELINE_SECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review default user permissions such as app registration, group creation, and directory self-service capabilities."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B2.ps1"
            FunctionName = "Invoke-ZTVP-B2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B3"
            Name         = "User Consent and Enterprise App Baseline Review"
            CategoryId   = "BASELINE_SECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review user consent, admin consent workflow, and enterprise application consent baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B3.ps1"
            FunctionName = "Invoke-ZTVP-B3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B4"
            Name         = "Password and Account Protection Baseline Review"
            CategoryId   = "BASELINE_SECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review password protection, account protection, lockout, and self-service password reset baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B4.ps1"
            FunctionName = "Invoke-ZTVP-B4"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B5"
            Name         = "User Account Hygiene Review"
            CategoryId   = "BASELINE_SECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review stale, disabled, guest, unlicensed, and potentially unmanaged user account hygiene indicators."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B5.ps1"
            FunctionName = "Invoke-ZTVP-B5"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B1"
            Name         = "Tenant Security Defaults and Baseline Control Review"
            CategoryId   = "IDENTITYBASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate whether the tenant has a baseline protection model through Security Defaults or enabled custom Conditional Access controls."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B1.ps1"
            FunctionName = "Invoke-ZTVP-B1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B2"
            Name         = "Default User Permissions and App Registration Review"
            CategoryId   = "IDENTITYBASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review default user permissions such as app registration, group creation, and directory self-service capabilities."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B2.ps1"
            FunctionName = "Invoke-ZTVP-B2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B3"
            Name         = "User Consent and Enterprise App Baseline Review"
            CategoryId   = "IDENTITYBASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review user consent, admin consent workflow, and enterprise application consent baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B3.ps1"
            FunctionName = "Invoke-ZTVP-B3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B4"
            Name         = "Password and Account Protection Baseline Review"
            CategoryId   = "IDENTITYBASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review password protection, account protection, lockout, and self-service password reset baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B4.ps1"
            FunctionName = "Invoke-ZTVP-B4"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B5"
            Name         = "User Account Hygiene Review"
            CategoryId   = "IDENTITYBASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review stale, disabled, guest, unlicensed, and potentially unmanaged user account hygiene indicators."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B5.ps1"
            FunctionName = "Invoke-ZTVP-B5"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B1"
            Name         = "Tenant Security Defaults and Baseline Control Review"
            CategoryId   = "IDENTITY_BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate whether the tenant has a baseline protection model through Security Defaults or enabled custom Conditional Access controls."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B1.ps1"
            FunctionName = "Invoke-ZTVP-B1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B2"
            Name         = "Default User Permissions and App Registration Review"
            CategoryId   = "IDENTITY_BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review default user permissions such as app registration, group creation, and directory self-service capabilities."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B2.ps1"
            FunctionName = "Invoke-ZTVP-B2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B3"
            Name         = "User Consent and Enterprise App Baseline Review"
            CategoryId   = "IDENTITY_BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review user consent, admin consent workflow, and enterprise application consent baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B3.ps1"
            FunctionName = "Invoke-ZTVP-B3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B4"
            Name         = "Password and Account Protection Baseline Review"
            CategoryId   = "IDENTITY_BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review password protection, account protection, lockout, and self-service password reset baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B4.ps1"
            FunctionName = "Invoke-ZTVP-B4"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B5"
            Name         = "User Account Hygiene Review"
            CategoryId   = "IDENTITY_BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review stale, disabled, guest, unlicensed, and potentially unmanaged user account hygiene indicators."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B5.ps1"
            FunctionName = "Invoke-ZTVP-B5"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B1"
            Name         = "Tenant Security Defaults and Baseline Control Review"
            CategoryId   = "IDENTITYBASELINESECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate whether the tenant has a baseline protection model through Security Defaults or enabled custom Conditional Access controls."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B1.ps1"
            FunctionName = "Invoke-ZTVP-B1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B2"
            Name         = "Default User Permissions and App Registration Review"
            CategoryId   = "IDENTITYBASELINESECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review default user permissions such as app registration, group creation, and directory self-service capabilities."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B2.ps1"
            FunctionName = "Invoke-ZTVP-B2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B3"
            Name         = "User Consent and Enterprise App Baseline Review"
            CategoryId   = "IDENTITYBASELINESECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review user consent, admin consent workflow, and enterprise application consent baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B3.ps1"
            FunctionName = "Invoke-ZTVP-B3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B4"
            Name         = "Password and Account Protection Baseline Review"
            CategoryId   = "IDENTITYBASELINESECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review password protection, account protection, lockout, and self-service password reset baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B4.ps1"
            FunctionName = "Invoke-ZTVP-B4"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B5"
            Name         = "User Account Hygiene Review"
            CategoryId   = "IDENTITYBASELINESECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review stale, disabled, guest, unlicensed, and potentially unmanaged user account hygiene indicators."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B5.ps1"
            FunctionName = "Invoke-ZTVP-B5"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B1"
            Name         = "Tenant Security Defaults and Baseline Control Review"
            CategoryId   = "IDENTITY_BASELINE_SECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate whether the tenant has a baseline protection model through Security Defaults or enabled custom Conditional Access controls."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B1.ps1"
            FunctionName = "Invoke-ZTVP-B1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B2"
            Name         = "Default User Permissions and App Registration Review"
            CategoryId   = "IDENTITY_BASELINE_SECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review default user permissions such as app registration, group creation, and directory self-service capabilities."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B2.ps1"
            FunctionName = "Invoke-ZTVP-B2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B3"
            Name         = "User Consent and Enterprise App Baseline Review"
            CategoryId   = "IDENTITY_BASELINE_SECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review user consent, admin consent workflow, and enterprise application consent baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B3.ps1"
            FunctionName = "Invoke-ZTVP-B3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B4"
            Name         = "Password and Account Protection Baseline Review"
            CategoryId   = "IDENTITY_BASELINE_SECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review password protection, account protection, lockout, and self-service password reset baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B4.ps1"
            FunctionName = "Invoke-ZTVP-B4"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B5"
            Name         = "User Account Hygiene Review"
            CategoryId   = "IDENTITY_BASELINE_SECURITY"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review stale, disabled, guest, unlicensed, and potentially unmanaged user account hygiene indicators."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B5.ps1"
            FunctionName = "Invoke-ZTVP-B5"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B1"
            Name         = "Tenant Security Defaults and Baseline Control Review"
            CategoryId   = "5"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate whether the tenant has a baseline protection model through Security Defaults or enabled custom Conditional Access controls."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B1.ps1"
            FunctionName = "Invoke-ZTVP-B1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B2"
            Name         = "Default User Permissions and App Registration Review"
            CategoryId   = "5"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review default user permissions such as app registration, group creation, and directory self-service capabilities."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B2.ps1"
            FunctionName = "Invoke-ZTVP-B2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B3"
            Name         = "User Consent and Enterprise App Baseline Review"
            CategoryId   = "5"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review user consent, admin consent workflow, and enterprise application consent baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B3.ps1"
            FunctionName = "Invoke-ZTVP-B3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B4"
            Name         = "Password and Account Protection Baseline Review"
            CategoryId   = "5"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review password protection, account protection, lockout, and self-service password reset baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B4.ps1"
            FunctionName = "Invoke-ZTVP-B4"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B5"
            Name         = "User Account Hygiene Review"
            CategoryId   = "5"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review stale, disabled, guest, unlicensed, and potentially unmanaged user account hygiene indicators."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B5.ps1"
            FunctionName = "Invoke-ZTVP-B5"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B1"
            Name         = "Tenant Security Defaults and Baseline Control Review"
            CategoryId   = "Baseline Security"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate whether the tenant has a baseline protection model through Security Defaults or enabled custom Conditional Access controls."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B1.ps1"
            FunctionName = "Invoke-ZTVP-B1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B2"
            Name         = "Default User Permissions and App Registration Review"
            CategoryId   = "Baseline Security"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review default user permissions such as app registration, group creation, and directory self-service capabilities."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B2.ps1"
            FunctionName = "Invoke-ZTVP-B2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B3"
            Name         = "User Consent and Enterprise App Baseline Review"
            CategoryId   = "Baseline Security"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review user consent, admin consent workflow, and enterprise application consent baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B3.ps1"
            FunctionName = "Invoke-ZTVP-B3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B4"
            Name         = "Password and Account Protection Baseline Review"
            CategoryId   = "Baseline Security"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review password protection, account protection, lockout, and self-service password reset baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B4.ps1"
            FunctionName = "Invoke-ZTVP-B4"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B5"
            Name         = "User Account Hygiene Review"
            CategoryId   = "Baseline Security"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review stale, disabled, guest, unlicensed, and potentially unmanaged user account hygiene indicators."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B5.ps1"
            FunctionName = "Invoke-ZTVP-B5"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        # ============================================================
        # Baseline Security - Cloud scenarios
        # ============================================================

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B1"
            Name         = "Tenant Security Defaults and Baseline Control Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate whether the tenant has a baseline protection model through Security Defaults or enabled custom Conditional Access controls."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B1.ps1"
            FunctionName = "Invoke-ZTVP-B1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B2"
            Name         = "Default User Permissions and App Registration Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review default user permissions such as app registration, group creation, and directory self-service capabilities."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B2.ps1"
            FunctionName = "Invoke-ZTVP-B2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B3"
            Name         = "User Consent and Enterprise App Baseline Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review user consent, admin consent workflow, and enterprise application consent baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B3.ps1"
            FunctionName = "Invoke-ZTVP-B3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B4"
            Name         = "Password and Account Protection Baseline Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review password protection, account protection, lockout, and self-service password reset baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B4.ps1"
            FunctionName = "Invoke-ZTVP-B4"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B5"
            Name         = "User Account Hygiene Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review stale, disabled, guest, unlicensed, and potentially unmanaged user account hygiene indicators."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B5.ps1"
            FunctionName = "Invoke-ZTVP-B5"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }


        # ============================================================
        # Baseline Security - Cloud scenarios
        # ============================================================

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B1"
            Name         = "Tenant Security Defaults and Baseline Control Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate whether the tenant has a baseline protection model through Security Defaults or enabled custom Conditional Access controls."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B1.ps1"
            FunctionName = "Invoke-ZTVP-B1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B2"
            Name         = "Default User Permissions and App Registration Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review default user permissions such as app registration, group creation, and directory self-service capabilities."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B2.ps1"
            FunctionName = "Invoke-ZTVP-B2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B3"
            Name         = "User Consent and Enterprise App Baseline Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review user consent, admin consent workflow, and enterprise application consent baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B3.ps1"
            FunctionName = "Invoke-ZTVP-B3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B4"
            Name         = "Password and Account Protection Baseline Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review password protection, account protection, lockout, and self-service password reset baseline posture."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B4.ps1"
            FunctionName = "Invoke-ZTVP-B4"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }

        $scenarios += [PSCustomObject]@{
            ScenarioId   = "B5"
            Name         = "User Account Hygiene Review"
            CategoryId   = "BASELINE"
            CategoryName = "Baseline Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review stale, disabled, guest, unlicensed, and potentially unmanaged user account hygiene indicators."
            EnginePath   = ".\powershell\Engines\BaselineSecurity\Invoke-ZTVP-B5.ps1"
            FunctionName = "Invoke-ZTVP-B5"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Medium"
            Phase        = "Phase 1"
        }


function Get-ZTVPPillars {
    return @(
        [PSCustomObject]@{ Id = "IDENTITY"; Name = "Identity" }
        [PSCustomObject]@{ Id = "DEVICE";   Name = "Devices" }
        [PSCustomObject]@{ Id = "APPS";     Name = "Applications" }
        [PSCustomObject]@{ Id = "DATA";     Name = "Data" }
        [PSCustomObject]@{ Id = "NETWORK";  Name = "Network" }
        [PSCustomObject]@{ Id = "OPS";      Name = "Operations / Monitoring" }
    )
}

function Get-ZTVPCategories {
    return @(
        [PSCustomObject]@{ Id = "AUTH";   Name = "Authentication Security";        PillarId = "IDENTITY" }
        [PSCustomObject]@{ Id = "ACCESS"; Name = "Access Enforcement";             PillarId = "IDENTITY" }
        [PSCustomObject]@{ Id = "PRIV";   Name = "Privileged Access";              PillarId = "IDENTITY" }
        [PSCustomObject]@{ Id = "APP";    Name = "Application Access";             PillarId = "APPS" }
        [PSCustomObject]@{ Id = "IDPROT"; Name = "Identity Protection";            PillarId = "IDENTITY" }
        [PSCustomObject]@{ Id = "MON";    Name = "Monitoring and Validation";      PillarId = "OPS" }
        [PSCustomObject]@{ Id = "BASE";   Name = "Baseline Security";              PillarId = "IDENTITY" }
    )
}

function Get-ZTVPCategoriesByPillar {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PillarId
    )

    return @(Get-ZTVPCategories | Where-Object { $_.PillarId -eq $PillarId })
}

function Get-ZTVPScenarios {
    return @(
        [PSCustomObject]@{
            ScenarioId   = "A1"
            Name         = "Advanced MFA Enforcement"
            CategoryId   = "AUTH"
            CategoryName = "Authentication Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate strong MFA enforcement for privileged accounts."
            EnginePath   = ".\powershell\Engines\Authentication\Invoke-ZTVP-A1.ps1"
            FunctionName = "Invoke-ZTVP-A1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Critical"
            Phase        = "Phase 1"
        }
        [PSCustomObject]@{
            ScenarioId   = "A2"
            Name         = "Phishing-Resistant Authentication Readiness"
            CategoryId   = "AUTH"
            CategoryName = "Authentication Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate whether privileged accounts are ready for phishing-resistant authentication methods such as FIDO2/passkeys, Windows Hello for Business, or certificate-based authentication."
            EnginePath   = ".\powershell\Engines\Authentication\Invoke-ZTVP-A2.ps1"
            FunctionName = "Invoke-ZTVP-A2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Critical"
            Phase        = "Phase 1"
        }
        [PSCustomObject]@{
            ScenarioId   = "A3"
            Name         = "Workforce MFA Registration Coverage"
            CategoryId   = "AUTH"
            CategoryName = "Authentication Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate MFA registration coverage for all enabled standard users, excluding privileged users already assessed by A1 and A2."
            EnginePath   = ".\powershell\Engines\Authentication\Invoke-ZTVP-A3.ps1"
            FunctionName = "Invoke-ZTVP-A3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }
        [PSCustomObject]@{
            ScenarioId   = "A4"
            Name         = "Break-Glass Account Authentication Hygiene"
            CategoryId   = "AUTH"
            CategoryName = "Authentication Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate emergency access accounts, emergency groups, cloud-only status, privileged roles, authentication methods, and Conditional Access exclusions."
            EnginePath   = ".\powershell\Engines\Authentication\Invoke-ZTVP-A4.ps1"
            FunctionName = "Invoke-ZTVP-A4"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Critical"
            Phase        = "Phase 1"
        }
        [PSCustomObject]@{
            ScenarioId   = "A5"
            Name         = "Legacy Authentication Bypass Exposure"
            CategoryId   = "AUTH"
            CategoryName = "Authentication Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Check whether legacy authentication can bypass modern controls such as MFA and Conditional Access by validating Conditional Access policy state, legacy client targeting, exclusions, and recent legacy sign-in evidence."
            EnginePath   = ".\powershell\Engines\Authentication\Invoke-ZTVP-A5.ps1"
            FunctionName = "Invoke-ZTVP-A5"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }
        [PSCustomObject]@{
            ScenarioId   = "OP-ID-A1"
            Name         = "Domain Password Policy Review"
            CategoryId   = "AUTH"
            CategoryName = "Authentication Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review the on-premises Active Directory password and lockout policy baseline."
            EnginePath   = $null
            FunctionName = $null
            Implemented  = $false
            Scope        = "On-Premises"
            Priority     = "High"
            Phase        = "Phase 2"
        }

        [PSCustomObject]@{
            ScenarioId   = "OP-ID-A2"
            Name         = "Stale Privileged Account Review"
            CategoryId   = "AUTH"
            CategoryName = "Authentication Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Identify enabled on-premises privileged accounts that are stale, unused, or have old passwords."
            EnginePath   = $null
            FunctionName = $null
            Implemented  = $false
            Scope        = "On-Premises"
            Priority     = "High"
            Phase        = "Phase 2"
        }

# >>> ZTVP POP1 DIRECT SCENARIO
[PSCustomObject]@{
    ScenarioId   = "POP1"
    Name         = "Privileged AD Group Membership Review"
    PillarName   = "Identity"
    CategoryId   = "PRIV"
    CategoryName = "Privileged Access"
    Scope        = "On-Premises"
    Priority     = "Critical"
    Phase        = "Phase 1"
    Objective    = "Review powerful Active Directory groups, nested privileged memberships, disabled privileged accounts, service-like privileged accounts, stale privileged users, and populated operator groups."
    Implemented  = $true
    EnginePath   = ".\powershell\Engines\PrivilegedAccess\Invoke-ZTVP-POP1.ps1"
    FunctionName = "Invoke-ZTVP-POP1"
}
# <<< ZTVP POP1 DIRECT SCENARIO



        [PSCustomObject]@{
            ScenarioId   = "A6"
            Name         = "MFA Enforcement Through Conditional Access"
            CategoryId   = "AUTH"
            CategoryName = "Authentication Security"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate whether MFA is actually enforced by enabled Conditional Access policies, including policy state, All users coverage, admin role coverage, exclusions, and authentication strength usage."
            EnginePath   = ".\powershell\Engines\AccessEnforcement\Invoke-ZTVP-A6.ps1"
            FunctionName = "Invoke-ZTVP-A6"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Critical"
            Phase        = "Phase 1"
        }
[PSCustomObject]@{
            ScenarioId   = "E1"
            Name         = "Conditional Access Policy State Review"
            CategoryId   = "ACCESS"
            CategoryName = "Access Enforcement"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review Conditional Access policy states and identify enabled, report-only, disabled, and exclusion-bearing policies that affect enforcement confidence."
            EnginePath   = ".\powershell\Engines\AccessEnforcement\Invoke-ZTVP-E1.ps1"
            FunctionName = "Invoke-ZTVP-E1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

[PSCustomObject]@{
            ScenarioId   = "E2"
            Name         = "Admin Conditional Access Exclusion Review"
            CategoryId   = "ACCESS"
            CategoryName = "Access Enforcement"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Identify Conditional Access exclusions that affect privileged users, privileged roles, or groups containing privileged users."
            EnginePath   = ".\powershell\Engines\AccessEnforcement\Invoke-ZTVP-E2.ps1"
            FunctionName = "Invoke-ZTVP-E2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Critical"
            Phase        = "Phase 1"
        }
        [PSCustomObject]@{
            ScenarioId   = "E3"
            Name         = "Report-Only Policy Dependency Review"
            CategoryId   = "ACCESS"
            CategoryName = "Access Enforcement"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Detect whether important security controls depend on Conditional Access policies that are only in report-only mode and not enforcing protection."
            EnginePath   = ".\powershell\Engines\AccessEnforcement\Invoke-ZTVP-E3.ps1"
            FunctionName = "Invoke-ZTVP-E3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }
        [PSCustomObject]@{
            ScenarioId   = "E4"
            Name         = "Named Location and Trusted Network Review"
            CategoryId   = "ACCESS"
            CategoryName = "Access Enforcement"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review named locations and trusted networks for risky, outdated, overly broad, or undocumented access assumptions."
            EnginePath   = ".\powershell\Engines\AccessEnforcement\Invoke-ZTVP-E4.ps1"
            FunctionName = "Invoke-ZTVP-E4"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }
        [PSCustomObject]@{
            ScenarioId   = "E5"
            Name         = "Admin Access Policy Presence Review"
            CategoryId   = "ACCESS"
            CategoryName = "Access Enforcement"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Check whether confirmed dedicated Conditional Access protection exists for privileged roles and admin portals."
            EnginePath   = ".\powershell\Engines\AccessEnforcement\Invoke-ZTVP-E5.ps1"
            FunctionName = "Invoke-ZTVP-E5"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        
        [PSCustomObject]@{
            ScenarioId   = "P1"
            Name         = "Privileged Role Assignment and JIT Review"
            CategoryId   = "PRIV"
            CategoryName = "Privileged Access"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review active privileged role assignments, PIM/JIT eligibility evidence, standing access, and least-privilege exposure."
            EnginePath   = ".\powershell\Engines\PrivilegedAccess\Invoke-ZTVP-P1.ps1"
            FunctionName = "Invoke-ZTVP-P1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Critical"
            Phase        = "Phase 1"
        }
[PSCustomObject]@{
            ScenarioId   = "P2"
            Name         = "Global Administrator Count and Hygiene Review"
            CategoryId   = "PRIV"
            CategoryName = "Privileged Access"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review Global Administrator membership, break-glass coverage, service principal exposure, and PIM/JIT alignment."
            EnginePath   = ".\powershell\Engines\PrivilegedAccess\Invoke-ZTVP-P2.ps1"
            FunctionName = "Invoke-ZTVP-P2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Critical"
            Phase        = "Phase 1"
        }
[PSCustomObject]@{
            ScenarioId   = "P3"
            Name         = "Privileged Service Principal Role Review"
            CategoryId   = "PRIV"
            CategoryName = "Privileged Access"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Identify service principals, apps, groups, or non-human identities holding privileged directory roles."
            EnginePath   = ".\powershell\Engines\PrivilegedAccess\Invoke-ZTVP-P3.ps1"
            FunctionName = "Invoke-ZTVP-P3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Critical"
            Phase        = "Phase 1"
        }






        [PSCustomObject]@{
            ScenarioId   = "APP1"
            Name         = "High-Risk Delegated Consent Exposure"
            CategoryId   = "APP"
            CategoryName = "Application Access"
            PillarId     = "APPS"
            PillarName   = "Applications"
            Objective    = "Identify risky delegated permissions granted to enterprise applications."
            EnginePath   = $null
            FunctionName = $null
            Implemented  = $false
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

        









        [PSCustomObject]@{
            ScenarioId   = "M1"
            Name         = "Privileged Sign-In Monitoring"
            CategoryId   = "MON"
            CategoryName = "Monitoring and Validation"
            PillarId     = "OPS"
            PillarName   = "Operations / Monitoring"
            Objective    = "Validate monitoring visibility for privileged sign-in activity."
            EnginePath   = $null
            FunctionName = $null
            Implemented  = $false
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }


[PSCustomObject]@{
            ScenarioId   = "ID1"
            Name         = "Risk-Based Conditional Access"
            CategoryId   = "IDPROT"
            CategoryName = "Identity Protection"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Assess whether user risk and sign-in risk signals are enforced through Conditional Access."
            EnginePath   = ".\powershell\Engines\IdentityProtection\Invoke-ZTVP-ID1.ps1"
            FunctionName = "Invoke-ZTVP-ID1"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Critical"
            Phase        = "Phase 1"
        }

[PSCustomObject]@{
            ScenarioId   = "ID2"
            Name         = "Risky User Remediation Review"
            CategoryId   = "IDPROT"
            CategoryName = "Identity Protection"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Identify active risky users and determine whether high or medium-risk users require remediation."
            EnginePath   = ".\powershell\Engines\IdentityProtection\Invoke-ZTVP-ID2.ps1"
            FunctionName = "Invoke-ZTVP-ID2"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "Critical"
            Phase        = "Phase 1"
        }

[PSCustomObject]@{
            ScenarioId   = "ID3"
            Name         = "Risk Detection Review"
            CategoryId   = "IDPROT"
            CategoryName = "Identity Protection"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review Identity Protection risk detections, affected users, risk event types, and unresolved high-risk signals."
            EnginePath   = ".\powershell\Engines\IdentityProtection\Invoke-ZTVP-ID3.ps1"
            FunctionName = "Invoke-ZTVP-ID3"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

[PSCustomObject]@{
            ScenarioId   = "ID4"
            Name         = "Identity Protection Exclusion Review"
            CategoryId   = "IDPROT"
            CategoryName = "Identity Protection"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Review exclusions in user risk and sign-in risk policies that may weaken Identity Protection enforcement."
            EnginePath   = ".\powershell\Engines\IdentityProtection\Invoke-ZTVP-ID4.ps1"
            FunctionName = "Invoke-ZTVP-ID4"
            Implemented  = $true
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }

[PSCustomObject]@{
            ScenarioId   = "ID5"
            Name         = "Identity Protection Evidence Availability Review"
            CategoryId   = "IDPROT"
            CategoryName = "Identity Protection"
            PillarId     = "IDENTITY"
            PillarName   = "Identity"
            Objective    = "Validate whether risky user and risk detection evidence is available through licensing and Microsoft Graph permissions."
            EnginePath   = ".\powershell\Engines\IdentityProtection\Invoke-ZTVP-ID5.ps1"
            FunctionName = "Invoke-ZTVP-ID5"
            Implemented  = $false
            Scope        = "Cloud"
            Priority     = "High"
            Phase        = "Phase 1"
        }










    )
}

function Get-ZTVPScenariosByCategory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CategoryId
    )

    return @(Get-ZTVPScenarios | Where-Object { $_.CategoryId -eq $CategoryId })
}













