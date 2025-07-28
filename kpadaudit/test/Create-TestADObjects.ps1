<#
.SYNOPSIS
    Creates Active Directory test objects for validating the KPADAUDIT script
.DESCRIPTION
    This script creates a comprehensive set of test objects in Active Directory to validate
    all sections of the KPADAUDIT script. It creates users, groups, and applies various
    configurations to test different audit scenarios.
    
    WARNING: This script is designed for TEST DOMAINS ONLY. Do not run in production.
    
.PARAMETER TestOUPath
    The Distinguished Name of the OU where test objects will be created.
    Default: "OU=KPAuditTest,DC=test,DC=local"
    
.PARAMETER UserCount
    Number of test users to create (default: 50, max: 1500 to test performance)
    
.PARAMETER CreateLargeDataSet
    Switch to create a large dataset (1500+ users) to test performance optimizations
    
.EXAMPLE
    .\Create-TestADObjects.ps1
    
.EXAMPLE
    .\Create-TestADObjects.ps1 -TestOUPath "OU=Testing,DC=contoso,DC=com" -UserCount 100
    
.EXAMPLE
    .\Create-TestADObjects.ps1 -CreateLargeDataSet
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TestOUPath = "OU=KPAuditTest,DC=test,DC=local",
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(10, 2000)]
    [int]$UserCount = 50,
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateLargeDataSet
)

# Import required modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "✓ Active Directory module loaded successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to import Active Directory module. Ensure RSAT AD Tools are installed."
    exit 1
}

# If CreateLargeDataSet is specified, set UserCount to test performance
if ($CreateLargeDataSet) {
    $UserCount = 1500
    Write-Host "Large dataset mode enabled - creating $UserCount users" -ForegroundColor Yellow
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

Write-Host "`n=== KPADAUDIT Test Object Creation Script ===" -ForegroundColor Cyan
Write-Host "Domain: $($CurrentDomain.Name)" -ForegroundColor White
Write-Host "Test OU: $TestOUPath" -ForegroundColor White
Write-Host "User Count: $UserCount" -ForegroundColor White
Write-Host ""

# Create test OU structure
Write-Host "Creating test OU structure..." -ForegroundColor Yellow
try {
    # Create main test OU
    if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$TestOUPath'" -ErrorAction SilentlyContinue) {
        Write-Host "✓ Test OU already exists: $TestOUPath" -ForegroundColor Green
    } else {
        New-ADOrganizationalUnit -Name "KPAuditTest" -Path $CurrentDomain.DistinguishedName -Description "Test OU for KPADAUDIT script validation"
        Write-Host "✓ Created test OU: $TestOUPath" -ForegroundColor Green
    }
    
    # Create sub-OUs
    $SubOUs = @("TestUsers", "TestGroups", "DisabledUsers", "ServiceAccounts")
    foreach ($SubOU in $SubOUs) {
        $SubOUPath = "OU=$SubOU,$TestOUPath"
        if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$SubOUPath'" -ErrorAction SilentlyContinue) {
            Write-Host "✓ Sub-OU already exists: $SubOU" -ForegroundColor Green
        } else {
            New-ADOrganizationalUnit -Name $SubOU -Path $TestOUPath -Description "Test $SubOU for KPADAUDIT validation"
            Write-Host "✓ Created sub-OU: $SubOU" -ForegroundColor Green
        }
    }
} catch {
    Write-Error "Failed to create OU structure: $_"
    exit 1
}

# Create test groups with admin-like names
Write-Host "`nCreating test groups..." -ForegroundColor Yellow
$TestGroups = @(
    @{Name="TestAdmins"; Description="Test administrative group"; Members=@()},
    @{Name="DatabaseAdmins"; Description="Test database administrators"; Members=@()},
    @{Name="BackupAdmins"; Description="Test backup administrators"; Members=@()},
    @{Name="TestUsers"; Description="Standard test users group"; Members=@()},
    @{Name="DisabledTestGroup"; Description="Test group for disabled accounts"; Members=@()}
)

foreach ($Group in $TestGroups) {
    try {
        $GroupPath = "OU=TestGroups,$TestOUPath"
        if (Get-ADGroup -Filter "Name -eq '$($Group.Name)'" -ErrorAction SilentlyContinue) {
            Write-Host "✓ Group already exists: $($Group.Name)" -ForegroundColor Green
        } else {
            New-ADGroup -Name $Group.Name -GroupScope Global -GroupCategory Security -Path $GroupPath -Description $Group.Description
            Write-Host "✓ Created group: $($Group.Name)" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to create group $($Group.Name): $_"
    }
}

# Create test users with various configurations
Write-Host "`nCreating $UserCount test users..." -ForegroundColor Yellow
$TestUserPath = "OU=TestUsers,$TestOUPath"
$DisabledUserPath = "OU=DisabledUsers,$TestOUPath"
$ServiceAccountPath = "OU=ServiceAccounts,$TestOUPath"

# Generate test users with realistic patterns
$FirstNames = @("John", "Jane", "Michael", "Sarah", "David", "Lisa", "Robert", "Emily", "James", "Ashley", "Christopher", "Amanda", "Daniel", "Jessica", "Matthew", "Jennifer", "Anthony", "Michelle")
$LastNames = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore")

$CreatedUsers = @()
$UserCounter = 0

for ($i = 1; $i -le $UserCount; $i++) {
    $UserCounter++
    $FirstName = $FirstNames | Get-Random
    $LastName = $LastNames | Get-Random
    $Username = "$FirstName$LastName$i"
    $DisplayName = "$FirstName $LastName"
    $Email = "$Username@test.local"
    
    # Determine user type and path
    $IsDisabled = ($i % 10 -eq 0)  # Every 10th user is disabled
    $IsServiceAccount = ($i % 15 -eq 0)  # Every 15th user is a service account
    $IsOldAccount = ($i % 7 -eq 0)  # Every 7th user hasn't logged in for 120+ days
    
    if ($IsServiceAccount) {
        $UserPath = $ServiceAccountPath
        $Username = "svc$Username"
        $DisplayName = "Service Account - $DisplayName"
    } elseif ($IsDisabled) {
        $UserPath = $DisabledUserPath
    } else {
        $UserPath = $TestUserPath
    }
    
    try {
        if (Get-ADUser -Filter "SamAccountName -eq '$Username'" -ErrorAction SilentlyContinue) {
            Write-Host "✓ User already exists: $Username" -ForegroundColor Green
            continue
        }
        
        # Create user with comprehensive properties
        $UserParams = @{
            SamAccountName = $Username
            UserPrincipalName = $Email
            Name = $DisplayName
            GivenName = $FirstName
            Surname = $LastName
            DisplayName = $DisplayName
            EmailAddress = $Email
            Path = $UserPath
            Enabled = -not $IsDisabled
            PasswordNeverExpires = ($i % 20 -eq 0)  # 5% have non-expiring passwords
            PasswordNotRequired = ($i % 50 -eq 0)   # 2% don't require passwords
            AllowReversiblePasswordEncryption = ($i % 100 -eq 0)  # 1% have reversible encryption
            UseDESKeyOnly = ($i % 200 -eq 0)        # 0.5% use DES only
            AccountPassword = (ConvertTo-SecureString "TestPassword123!" -AsPlainText -Force)
            ChangePasswordAtLogon = $false
        }
        
        New-ADUser @UserParams
        
        # Set last logon date for testing stale accounts
        if ($IsOldAccount) {
            $OldDate = (Get-Date).AddDays(-($i % 200 + 90))  # 90-290 days ago
            Set-ADUser -Identity $Username -Replace @{lastLogon = $OldDate.ToFileTime()}
        } else {
            # Recent logon (within last 30 days)
            $RecentDate = (Get-Date).AddDays(-($i % 30))
            Set-ADUser -Identity $Username -Replace @{lastLogon = $RecentDate.ToFileTime()}
        }
        
        # Set password last set date
        $PasswordDate = (Get-Date).AddDays(-($i % 90))  # 0-90 days ago
        Set-ADUser -Identity $Username -Replace @{pwdLastSet = $PasswordDate.ToFileTime()}
        
        $CreatedUsers += $Username
        
        if ($UserCounter % 50 -eq 0) {
            Write-Host "Created $UserCounter users..." -ForegroundColor Cyan
        }
        
    } catch {
        Write-Warning "Failed to create user $Username`: $($_.Exception.Message)"
    }
}

Write-Host "✓ Created $($CreatedUsers.Count) test users" -ForegroundColor Green

# Add users to groups for testing group membership
Write-Host "`nAssigning group memberships..." -ForegroundColor Yellow
$AdminUsers = $CreatedUsers | Select-Object -First 5
$DatabaseUsers = $CreatedUsers | Select-Object -First 10 | Select-Object -Skip 5
$BackupUsers = $CreatedUsers | Select-Object -First 15 | Select-Object -Skip 10
# Note: StandardUsers variable removed as it was unused

# Add to test admin groups
foreach ($User in $AdminUsers) {
    try {
        Add-ADGroupMember -Identity "TestAdmins" -Members $User -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Failed to add $User to TestAdmins: $_"
    }
}

foreach ($User in $DatabaseUsers) {
    try {
        Add-ADGroupMember -Identity "DatabaseAdmins" -Members $User -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Failed to add $User to DatabaseAdmins: $_"
    }
}

foreach ($User in $BackupUsers) {
    try {
        Add-ADGroupMember -Identity "BackupAdmins" -Members $User -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Failed to add $User to BackupAdmins: $_"
    }
}

# Add a few users to built-in admin groups for testing (if they exist)
if (Get-ADGroup -Filter "Name -eq 'Domain Admins'" -ErrorAction SilentlyContinue) {
    $TestDomainAdmin = $AdminUsers | Select-Object -First 1
    try {
        Add-ADGroupMember -Identity "Domain Admins" -Members $TestDomainAdmin -ErrorAction SilentlyContinue
        Write-Host "✓ Added $TestDomainAdmin to Domain Admins group" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to add user to Domain Admins: $_"
    }
}

Write-Host "✓ Group memberships assigned" -ForegroundColor Green

# Create test GPOs (if Group Policy module is available)
Write-Host "`nCreating test GPOs..." -ForegroundColor Yellow
try {
    Import-Module GroupPolicy -ErrorAction Stop
    
    $TestGPOs = @(
        "Test Security Policy",
        "Test Password Policy", 
        "Test Audit Policy",
        "Test User Rights Policy"
    )
    
    foreach ($GPOName in $TestGPOs) {
        try {
            if (Get-GPO -Name $GPOName -ErrorAction SilentlyContinue) {
                Write-Host "✓ GPO already exists: $GPOName" -ForegroundColor Green
            } else {
                New-GPO -Name $GPOName -Comment "Test GPO for KPADAUDIT validation"
                Write-Host "✓ Created GPO: $GPOName" -ForegroundColor Green
            }
        } catch {
            Write-Warning "Failed to create GPO $GPOName`: $($_.Exception.Message)"
        }
    }
} catch {
    Write-Warning "Group Policy module not available. Skipping GPO creation."
}

# Create test fine-grained password policy (if supported)
Write-Host "`nCreating test fine-grained password policy..." -ForegroundColor Yellow
try {
    $PSO = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'TestPasswordPolicy'" -ErrorAction SilentlyContinue
    if ($PSO) {
        Write-Host "✓ Fine-grained password policy already exists: TestPasswordPolicy" -ForegroundColor Green
    } else {
        $PSOParams = @{
            Name = "TestPasswordPolicy"
            Precedence = 100
            ComplexityEnabled = $true
            Description = "Test fine-grained password policy for KPADAUDIT validation"
            DisplayName = "Test Password Policy"
            LockoutDuration = "00:30:00"
            LockoutObservationWindow = "00:30:00"
            LockoutThreshold = 5
            MaxPasswordAge = "90.00:00:00"
            MinPasswordAge = "1.00:00:00"
            MinPasswordLength = 12
            PasswordHistoryCount = 12
            ReversibleEncryptionEnabled = $false
        }
        
        New-ADFineGrainedPasswordPolicy @PSOParams
        
        # Apply to TestAdmins group
        Add-ADFineGrainedPasswordPolicySubject -Identity "TestPasswordPolicy" -Subjects "TestAdmins"
        Write-Host "✓ Created fine-grained password policy: TestPasswordPolicy" -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to create fine-grained password policy (may not be supported in this domain functional level): $_"
}

# Summary report
Write-Host "`n=== Test Object Creation Summary ===" -ForegroundColor Cyan
Write-Host "✓ Test OU Structure: Created" -ForegroundColor Green
Write-Host "✓ Test Groups: $($TestGroups.Count) created" -ForegroundColor Green
Write-Host "✓ Test Users: $($CreatedUsers.Count) created" -ForegroundColor Green
Write-Host "✓ Group Memberships: Assigned" -ForegroundColor Green
Write-Host "✓ Test GPOs: Attempted creation" -ForegroundColor Green
Write-Host "✓ Fine-grained Password Policy: Attempted creation" -ForegroundColor Green

Write-Host "`n=== Next Steps ===" -ForegroundColor Yellow
Write-Host "1. Run the KPADAUDIT script: .\kpadaudit.ps1" -ForegroundColor White
Write-Host "2. Run the validation script: .\Validate-KPAuditOutput.ps1 -FilePath <domain_file.txt>" -ForegroundColor White
Write-Host "3. Clean up test objects when done: .\Cleanup-TestADObjects.ps1" -ForegroundColor White

Write-Host "`n✓ Test environment ready for KPADAUDIT validation!" -ForegroundColor Green
