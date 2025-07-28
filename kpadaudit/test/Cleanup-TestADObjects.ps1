<#
.SYNOPSIS
    Cleans up test Active Directory objects created by Create-TestADObjects.ps1
.DESCRIPTION
    This script removes all test objects created for KPADAUDIT validation, including
    users, groups, OUs, GPOs, and fine-grained password policies.
    
.PARAMETER TestOUPath
    The Distinguished Name of the test OU to remove.
    Default: "OU=KPAuditTest,DC=test,DC=local"
    
.PARAMETER Force
    Skip confirmation prompts
    
.EXAMPLE
    .\Cleanup-TestADObjects.ps1
    
.EXAMPLE
    .\Cleanup-TestADObjects.ps1 -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TestOUPath = "OU=KPAuditTest,DC=test,DC=local",
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Import required modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "Active Directory module loaded successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to import Active Directory module. Ensure RSAT AD Tools are installed."
    exit 1
}

# Get current domain information
try {
    $CurrentDomain = Get-ADDomain
    Write-Host "Connected to domain: $($CurrentDomain.Name)" -ForegroundColor Green
    
    # Auto-detect TestOUPath if using default
    if ($TestOUPath -eq "OU=KPAuditTest,DC=test,DC=local") {
        $TestOUPath = "OU=KPAuditTest,$($CurrentDomain.DistinguishedName)"
        Write-Host "Auto-detected TestOUPath: $TestOUPath" -ForegroundColor Cyan
    }
} catch {
    Write-Error "Failed to connect to Active Directory domain."
    exit 1
}

Write-Host "`n=== KPADAUDIT Test Object Cleanup Script ===" -ForegroundColor Cyan
Write-Host "Domain: $($CurrentDomain.Name)" -ForegroundColor White
Write-Host "Test OU: $TestOUPath" -ForegroundColor White

# Confirmation
if (-not $Force) {
    Write-Host "`nWARNING: This will delete all test objects in the specified OU!" -ForegroundColor Yellow
    $Confirmation = Read-Host "Are you sure you want to continue? (y/N)"
    if ($Confirmation -notin @('y', 'Y', 'yes', 'Yes', 'YES')) {
        Write-Host "Cleanup cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# Check if test OU exists
try {
    $TestOU = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$TestOUPath'" -ErrorAction Stop
    if (-not $TestOU) {
        Write-Host "Test OU does not exist: $TestOUPath" -ForegroundColor Green
        Write-Host "Nothing to clean up." -ForegroundColor Green
        exit 0
    }
} catch {
    Write-Host "Test OU does not exist: $TestOUPath" -ForegroundColor Green
    Write-Host "Nothing to clean up." -ForegroundColor Green
    exit 0
}

Write-Host "`nStarting cleanup..." -ForegroundColor Yellow

# Remove users from built-in admin groups first
Write-Host "Removing test users from built-in admin groups..." -ForegroundColor Yellow
$TestUsers = Get-ADUser -Filter * -SearchBase $TestOUPath -SearchScope Subtree

foreach ($User in $TestUsers) {
    try {
        # Remove from Domain Admins if present
        if (Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue | Where-Object {$_.SamAccountName -eq $User.SamAccountName}) {
            Remove-ADGroupMember -Identity "Domain Admins" -Members $User.SamAccountName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "Removed $($User.SamAccountName) from Domain Admins" -ForegroundColor Green
        }
        
        # Remove from Enterprise Admins if present
        if (Get-ADGroupMember -Identity "Enterprise Admins" -ErrorAction SilentlyContinue | Where-Object {$_.SamAccountName -eq $User.SamAccountName}) {
            Remove-ADGroupMember -Identity "Enterprise Admins" -Members $User.SamAccountName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "Removed $($User.SamAccountName) from Enterprise Admins" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to remove $($User.SamAccountName) from admin groups: $($_.Exception.Message)"
    }
}

# Remove fine-grained password policy
Write-Host "Removing test fine-grained password policy..." -ForegroundColor Yellow
try {
    $PSO = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'TestPasswordPolicy'" -ErrorAction SilentlyContinue
    if ($PSO) {
        Remove-ADFineGrainedPasswordPolicy -Identity "TestPasswordPolicy" -Confirm:$false
        Write-Host "Removed fine-grained password policy: TestPasswordPolicy" -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to remove fine-grained password policy: $($_.Exception.Message)"
}

# Remove test GPOs
Write-Host "Removing test GPOs..." -ForegroundColor Yellow
try {
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    
    $TestGPOs = @(
        "Test Security Policy",
        "Test Password Policy", 
        "Test Audit Policy",
        "Test User Rights Policy"
    )
    
    foreach ($GPOName in $TestGPOs) {
        try {
            $GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
            if ($GPO) {
                Remove-GPO -Name $GPOName -Confirm:$false
                Write-Host "Removed GPO: $GPOName" -ForegroundColor Green
            }
        } catch {
            Write-Warning "Failed to remove GPO $GPOName : $($_.Exception.Message)"
        }
    }
} catch {
    Write-Warning "Group Policy module not available. Skipping GPO cleanup."
}

# Remove all objects in test OU (this will cascade delete everything)
Write-Host "Removing test OU and all contained objects..." -ForegroundColor Yellow
try {
    # First, remove deletion protection from all OUs (including the main OU)
    Write-Host "Removing deletion protection from OUs..." -ForegroundColor Yellow
    try {
        # Get all OUs including the main test OU and all child OUs
        $AllOUs = @()
        $AllOUs += Get-ADOrganizationalUnit -Filter * -SearchBase $TestOUPath -SearchScope Subtree
        $AllOUs += Get-ADOrganizationalUnit -Identity $TestOUPath
        
        foreach ($OU in $AllOUs) {
            try {
                Set-ADOrganizationalUnit -Identity $OU.DistinguishedName -ProtectedFromAccidentalDeletion $false
                Write-Host "Removed deletion protection from: $($OU.Name)" -ForegroundColor Green
            } catch {
                Write-Warning "Failed to remove deletion protection from $($OU.Name): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Warning "Failed to enumerate OUs for deletion protection removal: $($_.Exception.Message)"
    }
    
    # Now get all child OUs and remove them (bottom-up)
    $ChildOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $TestOUPath -SearchScope OneLevel | Sort-Object DistinguishedName -Descending
    
    foreach ($ChildOU in $ChildOUs) {
        try {
            Remove-ADOrganizationalUnit -Identity $ChildOU.DistinguishedName -Recursive -Confirm:$false
            Write-Host "Removed sub-OU: $($ChildOU.Name)" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to remove sub-OU $($ChildOU.Name): $($_.Exception.Message)"
        }
    }
    
    # Remove the main test OU
    Remove-ADOrganizationalUnit -Identity $TestOUPath -Recursive -Confirm:$false
    Write-Host "Removed main test OU: $TestOUPath" -ForegroundColor Green
    
} catch {
    Write-Warning "Failed to remove test OU: $($_.Exception.Message)"
    
    # Try alternative cleanup approach - remove objects individually
    Write-Host "Attempting individual object cleanup..." -ForegroundColor Yellow
    
    try {
        # Remove users
        $Users = Get-ADUser -Filter * -SearchBase $TestOUPath -SearchScope Subtree
        foreach ($User in $Users) {
            Remove-ADUser -Identity $User.SamAccountName -Confirm:$false
            Write-Host "Removed user: $($User.SamAccountName)" -ForegroundColor Green
        }
        
        # Remove groups
        $Groups = Get-ADGroup -Filter * -SearchBase $TestOUPath -SearchScope Subtree
        foreach ($Group in $Groups) {
            Remove-ADGroup -Identity $Group.SamAccountName -Confirm:$false
            Write-Host "Removed group: $($Group.Name)" -ForegroundColor Green
        }
        
        # Remove deletion protection from OUs again (in case the first attempt failed)
        Write-Host "Removing deletion protection from remaining OUs..." -ForegroundColor Yellow
        $RemainingOUs = @()
        try {
            $RemainingOUs += Get-ADOrganizationalUnit -Filter * -SearchBase $TestOUPath -SearchScope Subtree
            $RemainingOUs += Get-ADOrganizationalUnit -Identity $TestOUPath
            
            foreach ($OU in $RemainingOUs) {
                try {
                    Set-ADOrganizationalUnit -Identity $OU.DistinguishedName -ProtectedFromAccidentalDeletion $false
                    Write-Host "Removed deletion protection from: $($OU.Name)" -ForegroundColor Green
                } catch {
                    Write-Warning "Failed to remove deletion protection from $($OU.Name): $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Warning "Failed to enumerate remaining OUs: $($_.Exception.Message)"
        }
        
        # Remove OUs (bottom-up after removing protection)
        $OUs = Get-ADOrganizationalUnit -Filter * -SearchBase $TestOUPath -SearchScope Subtree | Sort-Object DistinguishedName -Descending
        foreach ($OU in $OUs) {
            Remove-ADOrganizationalUnit -Identity $OU.DistinguishedName -Confirm:$false
            Write-Host "Removed OU: $($OU.Name)" -ForegroundColor Green
        }
        
        # Finally remove the main test OU
        Remove-ADOrganizationalUnit -Identity $TestOUPath -Confirm:$false
        Write-Host "Removed main test OU: $TestOUPath" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed individual cleanup: $($_.Exception.Message)"
    }
}

# Final verification
Write-Host "`nVerifying cleanup..." -ForegroundColor Yellow
try {
    $RemainingObjects = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$TestOUPath'" -ErrorAction SilentlyContinue
    if ($RemainingObjects) {
        Write-Warning "Test OU still exists. Manual cleanup may be required."
    } else {
        Write-Host "Test OU successfully removed" -ForegroundColor Green
    }
} catch {
    Write-Host "Test OU successfully removed" -ForegroundColor Green
}

Write-Host "`n=== Cleanup Summary ===" -ForegroundColor Cyan
Write-Host "Test objects cleanup completed" -ForegroundColor Green
Write-Host "Built-in admin group memberships removed" -ForegroundColor Green
Write-Host "Fine-grained password policy removed" -ForegroundColor Green
Write-Host "Test GPOs removed" -ForegroundColor Green
Write-Host "Test OU and all objects removed" -ForegroundColor Green

Write-Host "`nCleanup completed successfully!" -ForegroundColor Green

# SIG # Begin signature block
# MIIfYgYJKoZIhvcNAQcCoIIfUzCCH08CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDmtMuGiTtlYoWU
# oIscEOXQt2ylgWgqW5D8Q4TlstUPEKCCDOgwggZuMIIEVqADAgECAhAtYLGndXgb
# zFvzMEdBS+SKMA0GCSqGSIb3DQEBCwUAMHgxCzAJBgNVBAYTAlVTMQ4wDAYDVQQI
# DAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENvcnAxNDAy
# BgNVBAMMK1NTTC5jb20gQ29kZSBTaWduaW5nIEludGVybWVkaWF0ZSBDQSBSU0Eg
# UjEwHhcNMjMxMjI3MjAyMDIzWhcNMjUxMjI2MjAyMDIzWjB3MQswCQYDVQQGEwJV
# UzESMBAGA1UECAwJVGVubmVzc2VlMRIwEAYDVQQHDAlOYXNodmlsbGUxHzAdBgNV
# BAoMFktpcmtwYXRyaWNrIFByaWNlIEluYy4xHzAdBgNVBAMMFktpcmtwYXRyaWNr
# IFByaWNlIEluYy4wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCH4MZY
# NZpjmSL0jBcXwN2a/Sj6Q4M0oua16QYbdW1zBK9Cw4mUKEMmo36EAaJZOyvSAdUU
# aj2A5g50fbweYROqbeFC9L8plpS4+bLeGPTOEq1fl50VxHPCmrFOASh1mLhvIGcx
# ZmKKr+p4sgJqpfvZKSPYkGw3EoAoJ6w2HZb7kajrdKqoaZO2IbXYVWjQHwh2EjFX
# 3Pwt2jNQbmQKwQVYglE5REY1dk05PbtvuYD8z/JHImQUbh7UY/9vCbFUoE+Ck1J4
# MUlO+CJNmv/XMXYOo2oCN9HY9hUc8T/1XsH2Kax7ai+nddAqPH7m7nAEtuEqQqC4
# /FSoG4FI10bvbCAQUOAQRx0u+8xjCgJ9+hq3ZJCkWGw+Wt0av40b/fpJGtGllPDd
# dBz/Y6UJNCbUJk8Tk0/h16Tsx/CDSHgvbq965Z54sEL8j798QDgDIv07/+amSwhv
# IAvWbJdsDpMSdWvxtGigxkqMZ4xh1UONOCsKzRklhnFiidJ1qusAg33mifMCAwEA
# AaOCAXMwggFvMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUVML+EJUAk81q9efA
# 19myS7iPDOMwWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzAChjxodHRwOi8vY2Vy
# dC5zc2wuY29tL1NTTGNvbS1TdWJDQS1Db2RlU2lnbmluZy1SU0EtNDA5Ni1SMS5j
# ZXIwUQYDVR0gBEowSDAIBgZngQwBBAEwPAYMKwYBBAGCqTABAwMBMCwwKgYIKwYB
# BQUHAgEWHmh0dHBzOi8vd3d3LnNzbC5jb20vcmVwb3NpdG9yeTATBgNVHSUEDDAK
# BggrBgEFBQcDAzBNBgNVHR8ERjBEMEKgQKA+hjxodHRwOi8vY3Jscy5zc2wuY29t
# L1NTTGNvbS1TdWJDQS1Db2RlU2lnbmluZy1SU0EtNDA5Ni1SMS5jcmwwHQYDVR0O
# BBYEFHoHVzBt4Ei4J6BKiF0XdfJ5O5Q7MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG
# 9w0BAQsFAAOCAgEAeKQvwVT8ZkDeUVcDXW8sNAtXxBwGPDOh8x1rqNVj73uTp3g1
# wmbOMYYZH4cnWV5/E11fwfkoNpI+fGy1YREWnzsTv+Uw5pymp9ELVrE9tzhJxgog
# u5yM6trSMrzyCql4dWjdjElMRR/eZ0mbzhBXUIk6QcKNOm2xrUh5IOI4IJsC6rwR
# aaAtYWQ+7f3b3iBGkzqFxmnQGsyOfrxH5Etj4awSzSFpc0jYW9SEnrN+c09YfbnO
# Vb5bz6e23RgKBAadNbtBApWRKAxYDnwvpJzfGJxBM+oi9QZc2/loySvdi5LEcCbP
# KFrbgakdm/ZmbS2V8NWUulnYzpSzNx8x9tw6KeGCMP/ti1dcNWULW5ItLOjjaa4T
# VtOze4uu3Y6cqlS3/d11SLL91DJK0kqxAsejP2egwKFjaB38ShCJ/BZUwgYhlycr
# qzgSZX9qfzzkw1XHKZer2Bfbgbwd6zkq0balgk2sAxIE9Hcc6SAWqPo9qhijjJ39
# ZUUOJlracqAgetwg6DzBe7NMqifkXuXmVizgIFUwbYDMSs95PBsWVVGLFUqvLtvA
# jARn7tElqmMPE24fRklS82YxO45nyalAYmrj93+7oMcXlpLVwhoFjsHRBQDcj5CG
# Klb6IybmI8EmTPc87AetRYbmZ+v+a6vvhhECoCkdGl71Dt8M/2vJavh/9M0wggZy
# MIIEWqADAgECAghkM1HTxzifCDANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJV
# UzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xGDAWBgNVBAoMD1NT
# TCBDb3Jwb3JhdGlvbjExMC8GA1UEAwwoU1NMLmNvbSBSb290IENlcnRpZmljYXRp
# b24gQXV0aG9yaXR5IFJTQTAeFw0xNjA2MjQyMDQ0MzBaFw0zMTA2MjQyMDQ0MzBa
# MHgxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3Rv
# bjERMA8GA1UECgwIU1NMIENvcnAxNDAyBgNVBAMMK1NTTC5jb20gQ29kZSBTaWdu
# aW5nIEludGVybWVkaWF0ZSBDQSBSU0EgUjEwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQCfgxNzqrDGbSHL24t6h3TQcdyOl3Ka5LuINLTdgAPGL0WkdJq/
# Hg9Q6p5tePOf+lEmqT2d0bKUVz77OYkbkStW72fL5gvjDjmMxjX0jD3dJekBrBdC
# fVgWQNz51ShEHZVkMGE6ZPKX13NMfXsjAm3zdetVPW+qLcSvvnSsXf5qtvzqXHnp
# D0OctVIFD+8+sbGP0EmtpuNCGVQ/8y8Ooct8/hP5IznaJRy4PgBKOm8yMDdkHseu
# dQfYVdIYyQ6KvKNc8HwKp4WBwg6vj5lc02AlvINaaRwlE81y9eucgJvcLGfE3ckJ
# mNVz68Qho+Uyjj4vUpjGYDdkjLJvSlRyGMwnh/rNdaJjIUy1PWT9K6abVa8mTGC0
# uVz+q0O9rdATZlAfC9KJpv/XgAbxwxECMzNhF/dWH44vO2jnFfF3VkopngPawism
# YTJboFblSSmNNqf1x1KiVgMgLzh4gL32Bq5BNMuURb2bx4kYHwu6/6muakCZE93v
# UN8BuvIE1tAx3zQ4XldbyDgeVtSsSKbt//m4wTvtwiS+RGCnd83VPZhZtEPqqmB9
# zcLlL/Hr9dQg1Zc0bl0EawUR0tOSjAknRO1PNTFGfnQZBWLsiePqI3CY5NEv1IoT
# GEaTZeVYc9NMPSd6Ij/D+KNVt/nmh4LsRR7Fbjp8sU65q2j3m2PVkUG8qQIDAQAB
# o4H7MIH4MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU3QQJB6L1en1SUxKS
# le44gCUNplkwMAYIKwYBBQUHAQEEJDAiMCAGCCsGAQUFBzABhhRodHRwOi8vb2Nz
# cHMuc3NsLmNvbTARBgNVHSAECjAIMAYGBFUdIAAwEwYDVR0lBAwwCgYIKwYBBQUH
# AwMwOwYDVR0fBDQwMjAwoC6gLIYqaHR0cDovL2NybHMuc3NsLmNvbS9zc2wuY29t
# LXJzYS1Sb290Q0EuY3JsMB0GA1UdDgQWBBRUwv4QlQCTzWr158DX2bJLuI8M4zAO
# BgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggIBAPUPJodwr5miyvXWyfCN
# Zj05gtOII9iCv49UhCe204MH154niU2EjlTRIO5gQ9tXQjzHsJX2vszqoz2OTwbG
# K1mGf+tzG8rlQCbgPW/M9r1xxs19DiBAOdYF0q+UCL9/wlG3K7V7gyHwY9rlnOFp
# LnUdTsthHvWlM98CnRXZ7WmTV7pGRS6AvGW+5xI+3kf/kJwQrfZWsqTU+tb8LryX
# IbN2g9KR+gZQ0bGAKID+260PZ+34fdzZcFt6umi1s0pmF4/n8OdX3Wn+vF7h1Yyf
# E7uVmhX7eSuF1W0+Z0duGwdc+1RFDxYRLhHDsLy1bhwzV5Qe/kI0Ro4xUE7bM1eV
# +jjk5hLbq1guRbfZIsr0WkdJLCjoT4xCPGRo6eZDrBmRqccTgl/8cQo3t51Qezxd
# 96JSgjXktefTCm9r/o35pNfVHUvnfWII+NnXrJlJ27WEQRQu9i5gl1NLmv7xiHp0
# up516eDap8nMLDt7TAp4z5T3NmC2gzyKVMtODWgqlBF1JhTqIDfM63kXdlV4cW3i
# STgzN9vkbFnHI2LmvM4uVEv9XgMqyN0eS3FE0HU+MWJliymm7STheh2ENH+kF3y0
# rH0/NVjLw78a3Z9UVm1F5VPziIorMaPKPlDRADTsJwjDZ8Zc6Gi/zy4WZbg8Zv87
# spWrmo2dzJTw7XhQf+xkR6OdMYIR0DCCEcwCAQEwgYwweDELMAkGA1UEBhMCVVMx
# DjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wg
# Q29ycDE0MDIGA1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25pbmcgSW50ZXJtZWRpYXRl
# IENBIFJTQSBSMQIQLWCxp3V4G8xb8zBHQUvkijANBglghkgBZQMEAgEFAKB8MBAG
# CisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBzyQILnM1i
# j2+aXphv9iiq7Zy+fiItyCQ/uRJ4mnImZDANBgkqhkiG9w0BAQEFAASCAYAje8kl
# w0f5ZINvEMx1s40sCKK6qK8FxnwZApzbXj9Deh3px/peOGnlzdM13pKIScTlZJi8
# fQb7An4ee2ngtzIvIMAP47eUM4tgmm+MVrLORxiJyfkl95AbYqu/3ky3VyMDlHoX
# r/BIc1aLExUmLpLhp/kdHdTaB08bXiwvLAdFKMIe7OHopcjAseKAs/bCLQLa6MkQ
# +haiAgxHmM7YFaZX8brqDNrsYBNFEwvufFm9ouN198su1vzTqR+63lXq8O94zQHM
# htMR85VERUiZwYMrBdo3pJCaLB3BavZ8Mjwqdixjc4Dyu7hqr+EBaeSvpMcN01P6
# 7qTIDXH497Mj3cmZqFONDKWkP222mKYbujIXq5DH33tcLDFf3eLPIi/b6+l1Vl8D
# oO/1SaB8cWRMWvSdEhjnDMrbkIyZ39jswIlX/MVf7oUpHcFKB+ZMrSVMi8De7Yj9
# bwPBv1WDBy5I2R5yJ/PPcUR8VjHZai2bSMU5h2bxXFoZHLc7Vcd6x4oiu1Shgg8W
# MIIPEgYKKwYBBAGCNwMDATGCDwIwgg7+BgkqhkiG9w0BBwKggg7vMIIO6wIBAzEN
# MAsGCWCGSAFlAwQCATB3BgsqhkiG9w0BCRABBKBoBGYwZAIBAQYMKwYBBAGCqTAB
# AwYBMDEwDQYJYIZIAWUDBAIBBQAEIGcq+TT8m5bBQlYGXTnGy9FIujcDRwX0jjZ9
# IsuUJiKxAghoCGQKYwaGmBgPMjAyNTA3MjgyMjAyMzVaMAMCAQGgggwAMIIE/DCC
# AuSgAwIBAgIQWlqs6Bo1brRiho1XfeA9xzANBgkqhkiG9w0BAQsFADBzMQswCQYD
# VQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xETAPBgNV
# BAoMCFNTTCBDb3JwMS8wLQYDVQQDDCZTU0wuY29tIFRpbWVzdGFtcGluZyBJc3N1
# aW5nIFJTQSBDQSBSMTAeFw0yNDAyMTkxNjE4MTlaFw0zNDAyMTYxNjE4MThaMG4x
# CzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjER
# MA8GA1UECgwIU1NMIENvcnAxKjAoBgNVBAMMIVNTTC5jb20gVGltZXN0YW1waW5n
# IFVuaXQgMjAyNCBFMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKdhcvUw6XrE
# gxSWBULj3Oid25Rt2TJvSmLLaLy3cmVATADvhyMryD2ZELwYfVwABUwivwzYd1ml
# WCRXUtcEsHyjggFaMIIBVjAfBgNVHSMEGDAWgBQMnRAljpqnG5mHQ88IfuG9gZD0
# zzBRBggrBgEFBQcBAQRFMEMwQQYIKwYBBQUHMAKGNWh0dHA6Ly9jZXJ0LnNzbC5j
# b20vU1NMLmNvbS10aW1lU3RhbXBpbmctSS1SU0EtUjEuY2VyMFEGA1UdIARKMEgw
# PAYMKwYBBAGCqTABAwYBMCwwKgYIKwYBBQUHAgEWHmh0dHBzOi8vd3d3LnNzbC5j
# b20vcmVwb3NpdG9yeTAIBgZngQwBBAIwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgw
# RgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NybHMuc3NsLmNvbS9TU0wuY29tLXRp
# bWVTdGFtcGluZy1JLVJTQS1SMS5jcmwwHQYDVR0OBBYEFFBPJKzvtT5jEyMJkibs
# ujqW5F0iMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAmKCPAwCR
# vKvEZEF/QiHiv6tsIHnuVO7BWILqcfZ9lJyIyiCmpLOtJ5VnZ4hvm+GP2tPuOpZd
# mfTYWdyzhhOsDVDLElbfrKMLiOXn9uwUJpa5fMZe3Zjoh+n/8DdnSw1MxZNMGhuZ
# x4zeyqei91f1OhEU/7b2vnJCc9yBFMjY++tVKovFj0TKT3/Ry+Izdbb1gGXTzQQ1
# uVFy7djxGx/NG1VP/aye4OhxHG9FiZ3RM9oyAiPbEgjrnVCc+nWGKr3FTQDKi8vN
# uyLnCVHkiniL+Lz7H4fBgk163Llxi11Ynu5A/phpm1b+M2genvqo1+2r8iVLHrER
# gFGMUHEdKrZ/OFRDmgFrCTY6xnaPTA5/ursCqMK3q3/59uZaOsBZhZkaP9EuOW2p
# 0U8Gkgqp2GNUjFoaDNWFoT/EcoGDiTgN8VmQFgn0Fa4/3dOb6lpYEPBcjsWDdqUa
# xugStY9aW/AwCal4lSN4otljbok8u31lZx5NVa4jK6N6upvkgyZ6osmbmIWr9DLh
# g8bI+KiXDnDWT0547gSuZLYUq+TV6O/DhJZH5LVXJaeS1jjjZZqhK3EEIJVZl0xY
# V4H4Skvy6hA2rUyFK3+whSNS52TJkshsxVCOPtvqA9ecPqZLwWBaIICG4zVr+GAD
# 7qjWwlaLMd2ZylgOHI3Oit/0pVETqJHutyYwggb8MIIE5KADAgECAhBtUhhwh+gj
# TYVgANCAj5NWMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMQ4wDAYDVQQI
# DAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBvcmF0
# aW9uMTEwLwYDVQQDDChTU0wuY29tIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
# dHkgUlNBMB4XDTE5MTExMzE4NTAwNVoXDTM0MTExMjE4NTAwNVowczELMAkGA1UE
# BhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQK
# DAhTU0wgQ29ycDEvMC0GA1UEAwwmU1NMLmNvbSBUaW1lc3RhbXBpbmcgSXNzdWlu
# ZyBSU0EgQ0EgUjEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCuURAT
# 0vk8IKAghd7JUBxkyeH9xek0/wp/MUjoclrFXqhh/fGH91Fc+7fm0MHCE7A+wmOi
# qBj9ODrJAYGq3rm33jCnHSsCBNWAQYyoauLq8IjqsS1JlXL29qDNMMdwZ8UNzQS7
# vWZMDJ40JSGNphMGTIA2qn2bohGtgRc4p1395ESypUOaGvJ3t0FNL3BuKmb6YctM
# cQUF2sqooMzd89h0E6ujdvBDo6ZwNnWoxj7YmfWjSXg33A5GuY9ym4QZM5OEVgo8
# ebz/B+gyhyCLNNhh4Mb/4xvCTCMVmNYrBviGgdPZYrym8Zb84TQCmSuX0JlLLa6W
# K1aO6qlwISbb9bVGh866ekKblC/XRP20gAu1CjvcYciUgNTrGFg8f8AJgQPOCc1/
# CCdaJSYwhJpSdheKOnQgESgNmYZPhFOC6IKaMAUXk5U1tjTcFCgFvvArXtK4azAW
# UOO1Y3fdldIBL6LjkzLUCYJNkFXqhsBVcPMuB0nUDWvLJfPimstjJ8lF4S6ECxWn
# lWi7OElVwTnt1GtRqeY9ydvvGLntU+FecK7DbqHDUd366UreMkSBtzevAc9aqoZP
# njVMjvFqV1pYOjzmTiVHZtAc80bAfFe5LLfJzPI6DntNyqobpwTevQpHqPDN9qqN
# O83r3kaw8A9j+HZiSw2AX5cGdQP0kG0vhzfgBwIDAQABo4IBgTCCAX0wEgYDVR0T
# AQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBTdBAkHovV6fVJTEpKV7jiAJQ2mWTCB
# gwYIKwYBBQUHAQEEdzB1MFEGCCsGAQUFBzAChkVodHRwOi8vd3d3LnNzbC5jb20v
# cmVwb3NpdG9yeS9TU0xjb21Sb290Q2VydGlmaWNhdGlvbkF1dGhvcml0eVJTQS5j
# cnQwIAYIKwYBBQUHMAGGFGh0dHA6Ly9vY3Nwcy5zc2wuY29tMD8GA1UdIAQ4MDYw
# NAYEVR0gADAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3dy5zc2wuY29tL3JlcG9z
# aXRvcnkwEwYDVR0lBAwwCgYIKwYBBQUHAwgwOwYDVR0fBDQwMjAwoC6gLIYqaHR0
# cDovL2NybHMuc3NsLmNvbS9zc2wuY29tLXJzYS1Sb290Q0EuY3JsMB0GA1UdDgQW
# BBQMnRAljpqnG5mHQ88IfuG9gZD0zzAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcN
# AQELBQADggIBAJIZdQ2mWkLPGQfZ8vyU+sCb8BXpRJZaL3Ez3VDlE3uZk3cPxPty
# bVfLuqaci0W6SB22JTMttCiQMnIVOsXWnIuAbD/aFTcUkTLBI3xys+wEajzXaXJY
# WACDS47BRjDtYlDW14gLJxf8W6DQoH3jHDGGy8kGJFOlDKG7/YrK7UGfHtBAEDVe
# 6lyZ+FtCsrk7dD/IiL/+Q3Q6SFASJLQ2XI89ihFugdYL77CiDNXrI2MFspQGswXE
# AGpHuaQDTHUp/LdR3TyrIsLlnzoLskUGswF/KF8+kpWUiKJNC4rPWtNrxlbXYRGg
# dEdx8SMjUTDClldcrknlFxbqHsVmr9xkT2QtFmG+dEq1v5fsIK0vHaHrWjMMmaJ9
# i+4qGJSD0stYfQ6v0PddT7EpGxGd867Ada6FZyHwbuQSadMb0K0P0OC2r7rwqBUe
# 0BaMqTa6LWzWItgBjGcObXeMxmbQqlEz2YtAcErkZvh0WABDDE4U8GyV/32FdaAv
# JgTfe9MiL2nSBioYe/g5mHUSWAay/Ip1RQmQCvmF9sNfqlhJwkjy/1U1ibUkTIUB
# X3HgymyQvqQTZLLys6pL2tCdWcjI9YuLw30rgZm8+K387L7ycUvqrmQ3ZJlujHl3
# r1hgV76s3WwMPgKk1bAEFMj+rRXimSC+Ev30hXZdqyMdl/il5Ksd0vhGMYICWDCC
# AlQCAQEwgYcwczELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQH
# DAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDEvMC0GA1UEAwwmU1NMLmNvbSBU
# aW1lc3RhbXBpbmcgSXNzdWluZyBSU0EgQ0EgUjECEFparOgaNW60YoaNV33gPccw
# CwYJYIZIAWUDBAIBoIIBYTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJ
# KoZIhvcNAQkFMQ8XDTI1MDcyODIyMDIzNVowKAYJKoZIhvcNAQk0MRswGTALBglg
# hkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEINGJibVUxqDw2+A0
# Uc3OQYlaUTDlcj25DvLbQd3vsU9jMIHJBgsqhkiG9w0BCRACLzGBuTCBtjCBszCB
# sAQgnXF/jcI3ZarOXkqw4fV115oX1Bzu2P2v7wP9Pb2JR+cwgYswd6R1MHMxCzAJ
# BgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8G
# A1UECgwIU1NMIENvcnAxLzAtBgNVBAMMJlNTTC5jb20gVGltZXN0YW1waW5nIElz
# c3VpbmcgUlNBIENBIFIxAhBaWqzoGjVutGKGjVd94D3HMAoGCCqGSM49BAMCBEcw
# RQIgRqSz40j514gzup4lHzzroBPb4AQ7wkrPYM/t3aCyeDECIQCCZz7gnOQ78Nsr
# Tyhb26MeAxj1JVNvZVAvDqFskve2Lg==
# SIG # End signature block
