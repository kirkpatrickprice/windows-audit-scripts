<#
.SYNOPSIS
    Creates Active Directory test objects for validating the KPADAUDIT script
.DESCRIPTION
    This script creates a comprehensive set of test objects in Active Directory to validate
    all sections of the KPADAUDIT script. It creates users, groups, and applies various
    configurations to test different audit scenarios.
    
    WARNING: This script is designed for TEST DOMAINS ONLY. Do not run in production.
    
    NOTE: The lastLogon attribute cannot be set directly as it's managed by SAM. 
    To test stale account detection, you would need to wait for accounts to age naturally
    or manually test with existing accounts that haven't logged in recently.
    
.PARAMETER TestOUPath
    The Distinguished Name of the OU where test objects will be created.
    Default: "OU=KPAuditTest,DC=test,DC=local"
    
.PARAMETER UserCount
    Number of test users to create (default: 50, max: 1500 to test performance)
    
.PARAMETER CreateLargeDataSet
    Switch to create a large dataset (1500+ users) to test performance optimizations
    
.PARAMETER Force
    Bypasses the normal safety confirmation prompt. When used, defaults to "yes" 
    after 15 second timeout instead of "no". Still requires confirmation for safety.
    
.EXAMPLE
    .\Create-TestADObjects.ps1
    
.EXAMPLE
    .\Create-TestADObjects.ps1 -TestOUPath "OU=Testing,DC=contoso,DC=com" -UserCount 100
    
.EXAMPLE
    .\Create-TestADObjects.ps1 -CreateLargeDataSet
    
.EXAMPLE
    .\Create-TestADObjects.ps1 -Force -UserCount 200
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TestOUPath = "OU=KPAuditTest,DC=test,DC=local",
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(10, 2000)]
    [int]$UserCount = 50,
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateLargeDataSet,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Function to prompt user with timeout
function Confirm-ActionWithTimeout {
    param(
        [string]$Message,
        [int]$TimeoutSeconds = 15,
        [bool]$DefaultYes = $false
    )
    
    $DefaultAction = if ($DefaultYes) { "YES" } else { "NO" }
    $Options = if ($DefaultYes) { "Y/n" } else { "y/N" }
    
    Write-Host $Message -ForegroundColor Yellow
    Write-Host "Options: ($Options) - Default: $DefaultAction - Timeout: $TimeoutSeconds seconds" -ForegroundColor Cyan
    Write-Host "Press CTRL+C to cancel at any time" -ForegroundColor Gray
    
    $startTime = Get-Date
    $response = $null
    
    try {
        do {
            # Check for CTRL+C interrupt
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq 'Enter') {
                    $response = if ($DefaultYes) { 'y' } else { 'n' }
                    break
                } elseif ($key.KeyChar -match '[yYnN]') {
                    $response = $key.KeyChar.ToString().ToLower()
                    Write-Host $response
                    break
                } elseif ($key.Key -eq 'C' -and $key.Modifiers -eq 'Control') {
                    # Handle CTRL+C explicitly
                    Write-Host "`nOperation cancelled by user (CTRL+C)." -ForegroundColor Yellow
                    exit 0
                }
            }
            
            $elapsed = (Get-Date) - $startTime
            if ($elapsed.TotalSeconds -ge $TimeoutSeconds) {
                $response = if ($DefaultYes) { 'y' } else { 'n' }
                Write-Host "`nTimeout reached. Using default: $DefaultAction" -ForegroundColor Yellow
                break
            }
            
            Start-Sleep -Milliseconds 100
        } while ($true)
    }
    catch [System.Management.Automation.PipelineStoppedException] {
        # Handle CTRL+C pipeline stop
        Write-Host "`nOperation cancelled by user (CTRL+C)." -ForegroundColor Yellow
        exit 0
    }
    catch {
        # Handle any other interruption
        Write-Host "`nOperation interrupted: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    
    return ($response -eq 'y')
}

# Import required modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "Active Directory module loaded successfully" -ForegroundColor Green
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
    Write-Host "Connected to domain: $($CurrentDomain.Name)" -ForegroundColor Green
    
    # Check current user permissions
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Host "Running as: $($CurrentUser.Name)" -ForegroundColor Cyan
    
    # Check if user is in Domain Admins group
    $IsDomainAdmin = Get-ADGroupMember -Identity "Domain Admins" | Where-Object { $_.SamAccountName -eq $CurrentUser.Name.Split('\')[1] }
    
    if ($IsDomainAdmin) {
        Write-Host "Current user is a Domain Administrator" -ForegroundColor Green
    } else {
        Write-Warning "Current user is NOT a Domain Administrator. This script requires Domain Admin privileges."
        Write-Host "Please run this script as a Domain Administrator account." -ForegroundColor Yellow
        Write-Host "Required permissions: Create/modify users, groups, and OUs in Active Directory" -ForegroundColor Yellow
        $Continue = Read-Host "Continue anyway? (y/N)"
        if ($Continue -ne 'y' -and $Continue -ne 'Y') {
            exit 1
        }
    }
    
    # Auto-detect TestOUPath if using default
    if ($TestOUPath -eq "OU=KPAuditTest,DC=test,DC=local") {
        $TestOUPath = "OU=KPAuditTest,$($CurrentDomain.DistinguishedName)"
        Write-Host "Auto-detected TestOUPath: $TestOUPath" -ForegroundColor Cyan
    }
} catch {
    Write-Error "Failed to connect to Active Directory domain: $_"
    exit 1
}

Write-Host "`n=== KPADAUDIT Test Object Creation Script ===" -ForegroundColor Cyan
Write-Host "Domain: $($CurrentDomain.Name)" -ForegroundColor White
Write-Host "Test OU: $TestOUPath" -ForegroundColor White
Write-Host "User Count: $UserCount" -ForegroundColor White
Write-Host ""

# User confirmation prompt with safety timeout
Write-Host "=== CONFIRMATION REQUIRED ===" -ForegroundColor Red
Write-Host "This script will create the following test objects in Active Directory:" -ForegroundColor White
Write-Host "  - Organizational Units under: $TestOUPath" -ForegroundColor White
Write-Host "  - $UserCount test user accounts" -ForegroundColor White
Write-Host "  - 5 test security groups" -ForegroundColor White
Write-Host "  - Test Group Policy Objects (if supported)" -ForegroundColor White
Write-Host "  - Test Fine-Grained Password Policy (if supported)" -ForegroundColor White
Write-Host ""
Write-Host "Connected to domain: $($CurrentDomain.DNSRoot)" -ForegroundColor Cyan
Write-Host "Domain Controller: $($CurrentDomain.PDCEmulator)" -ForegroundColor Cyan
Write-Host ""
Write-Host "WARNING: This script should ONLY be run in test/development environments!" -ForegroundColor Red
Write-Host "         DO NOT run this script in production domains!" -ForegroundColor Red
Write-Host ""

if ($Force) {
    $confirmed = Confirm-ActionWithTimeout -Message "Force mode enabled. Do you want to proceed with creating test objects?" -TimeoutSeconds 30 -DefaultYes $true
} else {
    $confirmed = Confirm-ActionWithTimeout -Message "Do you want to proceed with creating these test objects?" -TimeoutSeconds 30 -DefaultYes $false
}

if (-not $confirmed) {
    Write-Host "Operation cancelled by user." -ForegroundColor Yellow
    exit 0
}

Write-Host "Proceeding with test object creation..." -ForegroundColor Green

# Create test OU structure
Write-Host "Creating test OU structure..." -ForegroundColor Yellow
try {
    # Test write permissions by attempting to read domain info with elevated query
    try {
        $null = Get-ADDomain -Server $CurrentDomain.PDCEmulator
        Write-Host "Successfully connected to domain controller" -ForegroundColor Green
    } catch {
        Write-Warning "Unable to connect to domain controller. Check network connectivity and permissions."
    }
    
    # Create main test OU
    if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$TestOUPath'" -ErrorAction SilentlyContinue) {
        Write-Host "Test OU already exists: $TestOUPath" -ForegroundColor Green
    } else {
        try {
            New-ADOrganizationalUnit -Name "KPAuditTest" -Path $CurrentDomain.DistinguishedName -Description "Test OU for KPADAUDIT script validation"
            Write-Host "Created test OU: $TestOUPath" -ForegroundColor Green
        } catch {
            Write-Error "Failed to create main test OU. This indicates insufficient permissions."
            Write-Host "Required permissions:" -ForegroundColor Yellow
            Write-Host "- Domain Administrator membership" -ForegroundColor Yellow
            Write-Host "- Create Organizational Unit objects permission" -ForegroundColor Yellow
            Write-Host "- Create User objects permission" -ForegroundColor Yellow
            Write-Host "- Create Group objects permission" -ForegroundColor Yellow
            throw $_
        }
    }
    
    # Create sub-OUs
    $SubOUs = @("TestUsers", "TestGroups", "DisabledUsers", "ServiceAccounts")
    foreach ($SubOU in $SubOUs) {
        $SubOUPath = "OU=$SubOU,$TestOUPath"
        if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$SubOUPath'" -ErrorAction SilentlyContinue) {
            Write-Host "Sub-OU already exists: $SubOU" -ForegroundColor Green
        } else {
            New-ADOrganizationalUnit -Name $SubOU -Path $TestOUPath -Description "Test $SubOU for KPADAUDIT validation"
            Write-Host "Created sub-OU: $SubOU" -ForegroundColor Green
        }
    }
} catch {
    Write-Error "Failed to create OU structure: $_"
    Write-Host "`nTroubleshooting steps:" -ForegroundColor Yellow
    Write-Host "1. Ensure you are running as a Domain Administrator" -ForegroundColor White
    Write-Host "2. Check that the Active Directory domain is reachable" -ForegroundColor White
    Write-Host "3. Verify RSAT AD Tools are properly installed" -ForegroundColor White
    Write-Host "4. Try running PowerShell as Administrator" -ForegroundColor White
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
            Write-Host "Group already exists: $($Group.Name)" -ForegroundColor Green
        } else {
            New-ADGroup -Name $Group.Name -GroupScope Global -GroupCategory Security -Path $GroupPath -Description $Group.Description
            Write-Host "Created group: $($Group.Name)" -ForegroundColor Green
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
$FirstNames = @("Aaron", "Adam", "Adrian", "Albert", "Alex", "Alexander", "Andrew", "Anthony", "Antonio", "Arthur", "Benjamin", "Bernard", "Bobby", "Bradley", "Brandon", "Brian", "Bruce", "Carl", "Charles", "Christopher", "Clarence", "Craig", "Daniel", "David", "Dennis", "Donald", "Douglas", "Edward", "Eric", "Eugene", "Frank", "Gary", "George", "Gerald", "Gregory", "Harold", "Harry", "Henry", "Howard", "Jack", "James", "Jason", "Jeffrey", "Jeremy", "Jerry", "Jesse", "John", "Johnny", "Jonathan", "Jordan", "Jose", "Joseph", "Joshua", "Justin", "Keith", "Kenneth", "Kevin", "Larry", "Lawrence", "Louis", "Mark", "Martin", "Matthew", "Michael", "Nicholas", "Patrick", "Paul", "Peter", "Philip", "Ralph", "Raymond", "Richard", "Robert", "Roger", "Ronald", "Roy", "Russell", "Ryan", "Samuel", "Scott", "Sean", "Stephen", "Steven", "Terry", "Thomas", "Timothy", "Todd", "Victor", "Walter", "Wayne", "William")

$LastNames = @("Adams", "Alexander", "Allen", "Anderson", "Baker", "Barnes", "Bell", "Bennett", "Brooks", "Brown", "Butler", "Campbell", "Carter", "Clark", "Collins", "Cook", "Cooper", "Cox", "Davis", "Edwards", "Evans", "Fisher", "Flores", "Foster", "Garcia", "Gonzalez", "Gray", "Green", "Hall", "Harris", "Henderson", "Hernandez", "Hill", "Jackson", "Johnson", "Jones", "Kelly", "King", "Lee", "Lewis", "Lopez", "Martin", "Martinez", "Miller", "Mitchell", "Moore", "Morgan", "Murphy", "Nelson", "Parker", "Perez", "Peterson", "Phillips", "Powell", "Reed", "Richardson", "Rivera", "Roberts", "Robinson", "Rodriguez", "Rogers", "Ross", "Russell", "Sanchez", "Scott", "Smith", "Stewart", "Taylor", "Thomas", "Thompson", "Torres", "Turner", "Walker", "Ward", "Washington", "Watson", "White", "Williams", "Wilson", "Wood", "Wright", "Young")

# Female names for additional variety
$FemaleFirstNames = @("Amanda", "Amy", "Andrea", "Angela", "Anna", "Ashley", "Barbara", "Betty", "Brenda", "Carol", "Carolyn", "Catherine", "Christine", "Cynthia", "Deborah", "Debra", "Diane", "Donna", "Dorothy", "Elizabeth", "Emily", "Emma", "Frances", "Helen", "Janet", "Jennifer", "Jessica", "Joan", "Joyce", "Julie", "Karen", "Kathleen", "Kimberly", "Laura", "Linda", "Lisa", "Margaret", "Maria", "Marie", "Martha", "Mary", "Michelle", "Nancy", "Nicole", "Olivia", "Pamela", "Patricia", "Rachel", "Rebecca", "Ruth", "Sandra", "Sarah", "Sharon", "Stephanie", "Susan", "Teresa", "Virginia")

# Combine all first names for maximum variety
$AllFirstNames = $FirstNames + $FemaleFirstNames

$CreatedUsers = @()
$UserCounter = 0
$UsedUsernames = @{}  # Track used usernames to avoid duplicates

for ($i = 1; $i -le $UserCount; $i++) {
    $UserCounter++
    
    # Generate unique username with better randomization
    $AttemptCount = 0
    do {
        $AttemptCount++
        $FirstName = $AllFirstNames | Get-Random
        $LastName = $LastNames | Get-Random
        
        # Create username with multiple strategies to ensure uniqueness
        if ($AttemptCount -eq 1) {
            # First attempt: FirstnameLastname + counter
            $BaseUsername = "$FirstName$LastName$i"
        } elseif ($AttemptCount -eq 2) {
            # Second attempt: First initial + Lastname + counter
            $BaseUsername = "$($FirstName.Substring(0,1))$LastName$i"
        } elseif ($AttemptCount -eq 3) {
            # Third attempt: Firstname + Last initial + counter + random number
            $RandomSuffix = Get-Random -Minimum 10 -Maximum 99
            $BaseUsername = "$FirstName$($LastName.Substring(0,1))$i$RandomSuffix"
        } else {
            # Fallback: Simple incremental naming
            $BaseUsername = "TestUser$i$AttemptCount"
        }
        
        # Ensure username is not too long and contains only valid characters
        if ($BaseUsername.Length -gt 15) {
            if ($AttemptCount -le 2) {
                $BaseUsername = $FirstName.Substring(0, [Math]::Min(4, $FirstName.Length)) + $LastName.Substring(0, [Math]::Min(4, $LastName.Length)) + $i
            } else {
                $BaseUsername = "User$i$AttemptCount"
            }
        }
        
        # Remove any potentially problematic characters
        $BaseUsername = $BaseUsername -replace '[^a-zA-Z0-9]', ''
        
        # Ensure it doesn't exceed SAM account name limit
        if ($BaseUsername.Length -gt 20) {
            $BaseUsername = $BaseUsername.Substring(0, 20)
        }
        
        $Username = $BaseUsername
        
    } while ($UsedUsernames.ContainsKey($Username.ToLower()) -and $AttemptCount -lt 5)
    
    # If we still have a duplicate after 5 attempts, force uniqueness
    if ($UsedUsernames.ContainsKey($Username.ToLower())) {
        $Username = "User$i$(Get-Random -Minimum 1000 -Maximum 9999)"
        if ($Username.Length -gt 20) {
            $Username = $Username.Substring(0, 20)
        }
    }
    
    # Mark username as used
    $UsedUsernames[$Username.ToLower()] = $true
    
    $DisplayName = "$FirstName $LastName"
    
    # Determine user type and path
    $IsDisabled = ($i % 10 -eq 0)  # Every 10th user is disabled
    $IsServiceAccount = ($i % 15 -eq 0)  # Every 15th user is a service account
    $IsOldAccount = ($i % 7 -eq 0)  # Every 7th user for stale account simulation
    
    if ($IsServiceAccount) {
        $UserPath = $ServiceAccountPath
        $Username = "svc$i"  # Simple service account naming
        $DisplayName = "Service Account $i - $DisplayName"
    } elseif ($IsDisabled) {
        $UserPath = $DisabledUserPath
    } else {
        $UserPath = $TestUserPath
    }
    
    try {
        # Check if user already exists
        if (Get-ADUser -Filter "SamAccountName -eq '$Username'" -ErrorAction SilentlyContinue) {
            Write-Host "User already exists: $Username" -ForegroundColor Green
            $CreatedUsers += $Username
            continue
        }
        
        # Validate that the target OU exists
        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$UserPath'" -ErrorAction SilentlyContinue)) {
            Write-Warning "Target OU does not exist: $UserPath. Skipping user $Username"
            continue
        }
        
        # Debug output for first few users
        if ($UserCounter -le 10) {
            Write-Host "DEBUG - Creating user $UserCounter : $Username (Length: $($Username.Length))" -ForegroundColor Cyan
            Write-Host "  Path: $UserPath" -ForegroundColor Gray
            Write-Host "  DisplayName: '$DisplayName'" -ForegroundColor Gray
        }
        
        # Use the most basic user creation possible to avoid parameter issues
        $SecurePassword = ConvertTo-SecureString "TestPassword123!" -AsPlainText -Force
        
        # Create user with minimal required parameters only
        New-ADUser -SamAccountName $Username -Name $DisplayName -Path $UserPath -AccountPassword $SecurePassword -Enabled (-not $IsDisabled)
        
        # Set additional attributes one by one with error handling
        try {
            Set-ADUser -Identity $Username -GivenName $FirstName -Surname $LastName -DisplayName $DisplayName
        } catch {
            Write-Warning "Failed to set name attributes for $Username : $($_.Exception.Message)"
        }
        
        try {
            Set-ADUser -Identity $Username -UserPrincipalName "$Username@$($CurrentDomain.DNSRoot)"
        } catch {
            Write-Warning "Failed to set UPN for $Username : $($_.Exception.Message)"
        }
        
        try {
            Set-ADUser -Identity $Username -EmailAddress "$Username@$($CurrentDomain.DNSRoot)"
        } catch {
            Write-Warning "Failed to set email for $Username : $($_.Exception.Message)"
        }
        
        # Set optional security attributes with individual error handling
        if ($i % 20 -eq 0) {
            try {
                Set-ADUser -Identity $Username -PasswordNeverExpires $true
            } catch {
                Write-Warning "Failed to set PasswordNeverExpires for $Username"
            }
        }
        
        if ($i % 50 -eq 0) {
            try {
                Set-ADUser -Identity $Username -PasswordNotRequired $true
            } catch {
                Write-Warning "Failed to set PasswordNotRequired for $Username"
            }
        }
        
        # Set description for testing purposes
        try {
            if ($IsOldAccount) {
                $AgeDays = $i % 200 + 90  # 90-290 days ago
                Set-ADUser -Identity $Username -Description "Test account - Stale account simulation - Age: $AgeDays days"
            } else {
                Set-ADUser -Identity $Username -Description "Test account - Active account simulation"
            }
        } catch {
            Write-Warning "Failed to set description for $Username"
        }
        
        $CreatedUsers += $Username
        
        if ($UserCounter % 50 -eq 0) {
            Write-Host "Created $UserCounter users..." -ForegroundColor Cyan
        }
        
    } catch {
        Write-Warning "Failed to create user $Username : $($_.Exception.Message)"
        Write-Host "  Username: '$Username' (Length: $($Username.Length))" -ForegroundColor Red
        Write-Host "  DisplayName: '$DisplayName'" -ForegroundColor Red
        Write-Host "  Path: '$UserPath'" -ForegroundColor Red
    }
}

Write-Host "Created $($CreatedUsers.Count) test users" -ForegroundColor Green

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
        Write-Host "Added $TestDomainAdmin to Domain Admins group" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to add user to Domain Admins: $_"
    }
}

Write-Host "Group memberships assigned" -ForegroundColor Green

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
                Write-Host "GPO already exists: $GPOName" -ForegroundColor Green
            } else {
                New-GPO -Name $GPOName -Comment "Test GPO for KPADAUDIT validation"
                Write-Host "Created GPO: $GPOName" -ForegroundColor Green
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
        Write-Host "Fine-grained password policy already exists: TestPasswordPolicy" -ForegroundColor Green
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
        Write-Host "Created fine-grained password policy: TestPasswordPolicy" -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to create fine-grained password policy (may not be supported in this domain functional level): $_"
}

# Summary report
Write-Host "`n=== Test Object Creation Summary ===" -ForegroundColor Cyan
Write-Host "Test OU Structure: Created" -ForegroundColor Green
Write-Host "Test Groups: $($TestGroups.Count) created" -ForegroundColor Green
Write-Host "Test Users: $($CreatedUsers.Count) created" -ForegroundColor Green
Write-Host "Group Memberships: Assigned" -ForegroundColor Green
Write-Host "Test GPOs: Attempted creation" -ForegroundColor Green
Write-Host "Fine-grained Password Policy: Attempted creation" -ForegroundColor Green

Write-Host "`n=== Next Steps ===" -ForegroundColor Yellow
Write-Host "1. Run the KPADAUDIT script: .\kpadaudit.ps1" -ForegroundColor White
Write-Host "2. Run the validation script: .\Validate-KPAuditOutput.ps1 -FilePath <domain_file.txt>" -ForegroundColor White
Write-Host "3. Clean up test objects when done: .\Cleanup-TestADObjects.ps1" -ForegroundColor White

Write-Host "`nTest environment ready for KPADAUDIT validation!" -ForegroundColor Green

# SIG # Begin signature block
# MIIfYgYJKoZIhvcNAQcCoIIfUzCCH08CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA4/E/vF54789wf
# 2y1ek1wKxCENdORhwqU0KR/QJUfuk6CCDOgwggZuMIIEVqADAgECAhAtYLGndXgb
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCKRpGcSFd9
# tp1k24iYLCrigETXrpmihJEMgG0tI4KjqTANBgkqhkiG9w0BAQEFAASCAYBrYQCO
# FbZPzO0Yd7klmRocHu2XSJV3TLMeUmvuEkTtqgGqHjtVPd3Th2AupcqzCj4eLiJp
# b0g90sSPfn3hLxIQ4jfRUsUL8M192D0nZbTGhpktX7ejQH7uwUtIjH2F+vZDTcpQ
# SMon2v9zXi+7Q8QFVIJo7KX7xP3ALsY0xWZmhHML+p+evrWOm81PvAX8nhzmzx4c
# lJVjVSDYA+YVijO6MPujAolHdhbs6HTDzAiQThuZXP5k6HEp7gT1C7Ka4tsyU/3a
# nTEN0U0lLtaci4sO11IUbYUu3X1MUqK9f34fRYc5vXbxEdUwL3PBsQZW786OYqTK
# mJrgIfQgjXc8B40BV7bqL8pcmzFMO8m7nmOLeGDmwaagx7gwKjF7ITy+8Tu5nOCt
# HHS4fg6IfshIvAKOL5ezrojI7sAw7iySR9Lr7tWc6oS37MSdQesulft7SEtR5uwj
# Q8LPcjCKc6dJFSFxJ6573s0gxs8m51IitmCalu2m724isdnPasOTN/4SQEShgg8W
# MIIPEgYKKwYBBAGCNwMDATGCDwIwgg7+BgkqhkiG9w0BBwKggg7vMIIO6wIBAzEN
# MAsGCWCGSAFlAwQCATB3BgsqhkiG9w0BCRABBKBoBGYwZAIBAQYMKwYBBAGCqTAB
# AwYBMDEwDQYJYIZIAWUDBAIBBQAEIEqr9N6/xPukmci/M/6Wbr/Is7czYZ1pTynf
# 2+VTpp0PAghEyoze5KuKMBgPMjAyNTA3MjgyMTU5NDdaMAMCAQGgggwAMIIE/DCC
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
# KoZIhvcNAQkFMQ8XDTI1MDcyODIxNTk0N1owKAYJKoZIhvcNAQk0MRswGTALBglg
# hkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIGK3jSXkyLiA7SkE
# z3lO2fr+LbVVtlfG2JxeKIltG4D8MIHJBgsqhkiG9w0BCRACLzGBuTCBtjCBszCB
# sAQgnXF/jcI3ZarOXkqw4fV115oX1Bzu2P2v7wP9Pb2JR+cwgYswd6R1MHMxCzAJ
# BgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8G
# A1UECgwIU1NMIENvcnAxLzAtBgNVBAMMJlNTTC5jb20gVGltZXN0YW1waW5nIElz
# c3VpbmcgUlNBIENBIFIxAhBaWqzoGjVutGKGjVd94D3HMAoGCCqGSM49BAMCBEcw
# RQIhANlTsCWjAQMDeMhYJ2Za95xZtXamIwEz+H2AbkLPpwLBAiBNFq4z+TYpUJXX
# 4s6mkTSGRrcvnIO9xDZZ4SmhmXAw2w==
# SIG # End signature block
