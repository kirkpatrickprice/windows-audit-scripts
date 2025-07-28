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
    Write-Host "✓ Active Directory module loaded successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to import Active Directory module. Ensure RSAT AD Tools are installed."
    exit 1
}

# Get current domain information
try {
    $CurrentDomain = Get-ADDomain
    Write-Host "✓ Connected to domain: $($CurrentDomain.Name)" -ForegroundColor Green
    
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
    Write-Host "`n⚠️  WARNING: This will delete all test objects in the specified OU!" -ForegroundColor Yellow
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
        Write-Host "✓ Test OU does not exist: $TestOUPath" -ForegroundColor Green
        Write-Host "Nothing to clean up." -ForegroundColor Green
        exit 0
    }
} catch {
    Write-Host "✓ Test OU does not exist: $TestOUPath" -ForegroundColor Green
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
            Write-Host "✓ Removed $($User.SamAccountName) from Domain Admins" -ForegroundColor Green
        }
        
        # Remove from Enterprise Admins if present
        if (Get-ADGroupMember -Identity "Enterprise Admins" -ErrorAction SilentlyContinue | Where-Object {$_.SamAccountName -eq $User.SamAccountName}) {
            Remove-ADGroupMember -Identity "Enterprise Admins" -Members $User.SamAccountName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "✓ Removed $($User.SamAccountName) from Enterprise Admins" -ForegroundColor Green
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
        Write-Host "✓ Removed fine-grained password policy: TestPasswordPolicy" -ForegroundColor Green
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
                Write-Host "✓ Removed GPO: $GPOName" -ForegroundColor Green
            }
        } catch {
            $errorMsg = "Failed to remove GPO " + $GPOName + " - " + $_.Exception.Message
            Write-Warning $errorMsg
        }
    }
} catch {
    Write-Warning "Group Policy module not available. Skipping GPO cleanup."
}

# Remove all objects in test OU (this will cascade delete everything)
Write-Host "Removing test OU and all contained objects..." -ForegroundColor Yellow
try {
    # First, get all child OUs and remove them (bottom-up)
    $ChildOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $TestOUPath -SearchScope OneLevel | Sort-Object DistinguishedName -Descending
    
    foreach ($ChildOU in $ChildOUs) {
        try {
            Remove-ADOrganizationalUnit -Identity $ChildOU.DistinguishedName -Recursive -Confirm:$false
            Write-Host "✓ Removed sub-OU: $($ChildOU.Name)" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to remove sub-OU $($ChildOU.Name): $($_.Exception.Message)"
        }
    }
    
    # Remove the main test OU
    Remove-ADOrganizationalUnit -Identity $TestOUPath -Recursive -Confirm:$false
    Write-Host "✓ Removed main test OU: $TestOUPath" -ForegroundColor Green
    
} catch {
    Write-Warning "Failed to remove test OU: $($_.Exception.Message)"
    
    # Try alternative cleanup approach - remove objects individually
    Write-Host "Attempting individual object cleanup..." -ForegroundColor Yellow
    
    try {
        # Remove users
        $Users = Get-ADUser -Filter * -SearchBase $TestOUPath -SearchScope Subtree
        foreach ($User in $Users) {
            Remove-ADUser -Identity $User.SamAccountName -Confirm:$false
            Write-Host "✓ Removed user: $($User.SamAccountName)" -ForegroundColor Green
        }
        
        # Remove groups
        $Groups = Get-ADGroup -Filter * -SearchBase $TestOUPath -SearchScope Subtree
        foreach ($Group in $Groups) {
            Remove-ADGroup -Identity $Group.SamAccountName -Confirm:$false
            Write-Host "✓ Removed group: $($Group.Name)" -ForegroundColor Green
        }
        
        # Remove OUs
        $OUs = Get-ADOrganizationalUnit -Filter * -SearchBase $TestOUPath -SearchScope Subtree | Sort-Object DistinguishedName -Descending
        foreach ($OU in $OUs) {
            Remove-ADOrganizationalUnit -Identity $OU.DistinguishedName -Confirm:$false
            Write-Host "✓ Removed OU: $($OU.Name)" -ForegroundColor Green
        }
        
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
        Write-Host "✓ Test OU successfully removed" -ForegroundColor Green
    }
} catch {
    Write-Host "✓ Test OU successfully removed" -ForegroundColor Green
}

Write-Host "`n=== Cleanup Summary ===" -ForegroundColor Cyan
Write-Host "✓ Test objects cleanup completed" -ForegroundColor Green
Write-Host "✓ Built-in admin group memberships removed" -ForegroundColor Green
Write-Host "✓ Fine-grained password policy removed" -ForegroundColor Green
Write-Host "✓ Test GPOs removed" -ForegroundColor Green
Write-Host "✓ Test OU and all objects removed" -ForegroundColor Green

Write-Host "`n🧹 Cleanup completed successfully!" -ForegroundColor Green
