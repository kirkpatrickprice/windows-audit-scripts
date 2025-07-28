# KPADAUDIT Test Scripts

This directory contains test scripts to validate the KPADAUDIT Active Directory auditing script in a controlled test environment.

## 🚀 Quick Start

### Prerequisites
- Windows Server with Active Directory Domain Services
- PowerShell 5.1 or later (PowerShell 4.0 minimum for validation script)
- RSAT Active Directory PowerShell module
- Domain Administrator privileges (for test object creation)

### Step 1: Create Test Objects
```powershell
# Run on a Domain Controller or system with RSAT AD tools
.\Create-TestADObjects.ps1

# For large dataset testing (1500+ users)
.\Create-TestADObjects.ps1 -CreateLargeDataSet

# Custom configuration
.\Create-TestADObjects.ps1 -TestOUPath "OU=Testing,DC=contoso,DC=com" -UserCount 100
```

### Step 2: Run KPADAUDIT Script
```powershell
# Navigate to the kpadaudit directory
cd ..\kpadaudit

# Run the audit script
.\kpadaudit.ps1

# Or specify custom output location
.\kpadaudit.ps1 -OutPath C:\Temp
```

### Step 3: Validate Output
```powershell
# Run the PowerShell validation script
.\Validate-KPAuditOutput.ps1 -FilePath "TESTDOMAIN.txt"

# Verbose output
.\Validate-KPAuditOutput.ps1 -FilePath "TESTDOMAIN.txt" -Verbose

# Export results to JSON
.\Validate-KPAuditOutput.ps1 -FilePath "TESTDOMAIN.txt" -ExportResults
```

### Step 4: Clean Up (Optional)
```powershell
# Remove all test objects when done
.\Cleanup-TestADObjects.ps1

# Force cleanup without prompts
.\Cleanup-TestADObjects.ps1 -Force
```

## 📋 Test Scripts Overview

### Create-TestADObjects.ps1
Creates a comprehensive test environment for KPADAUDIT validation:

**Test Objects Created:**
- **OU Structure**: KPAuditTest OU with sub-OUs (TestUsers, TestGroups, DisabledUsers, ServiceAccounts)
- **Users**: Configurable number (default 50, up to 2000 for performance testing)
  - Various account states (enabled/disabled, password policies, logon dates)
  - Service accounts with `svc` prefix
  - Users with different password security settings
- **Groups**: Test admin groups (TestAdmins, DatabaseAdmins, BackupAdmins)
- **Group Memberships**: Users assigned to various groups including built-in admin groups
- **GPOs**: Test Group Policy Objects for policy validation
- **Fine-Grained Password Policy**: Test PSO applied to admin groups

**Parameters:**
- `-TestOUPath`: Custom OU path for test objects
- `-UserCount`: Number of users to create (10-2000)
- `-CreateLargeDataSet`: Creates 1500 users for performance testing

### Validate-KPAuditOutput.ps1
PowerShell script that validates KPADAUDIT output for completeness and correctness:

**Validation Checks:**
- ✅ All expected sections present
- ✅ Required field headers in User_List section
- ✅ Record count limits enforced (≤1000 users)
- ✅ Performance optimizations (ResultSetSize usage)
- ✅ Test objects appear in appropriate sections
- ✅ No obvious error messages
- ⚠️ Warnings for missing or unexpected data
- ❌ Errors for critical issues

**Features:**
- **Self-contained**: Pure PowerShell, no external dependencies
- **Verbose mode**: Detailed section-by-section validation
- **JSON export**: Results can be exported for further analysis
- **Exit codes**: Returns 0 for success, 1 for failures

**Usage:**
```powershell
.\Validate-KPAuditOutput.ps1 -FilePath "TESTDOMAIN.txt"
.\Validate-KPAuditOutput.ps1 -FilePath "TESTDOMAIN.txt" -Verbose
.\Validate-KPAuditOutput.ps1 -FilePath "TESTDOMAIN.txt" -ExportResults
```

### Cleanup-TestADObjects.ps1
Safely removes all test objects created by the test script:

**Cleanup Actions:**
- Removes users from built-in admin groups
- Deletes fine-grained password policies
- Removes test GPOs
- Recursively deletes test OU and all contents
- Provides confirmation prompts (unless `-Force` is used)

## 🧪 Test Scenarios

### Basic Functionality Test
```powershell
# Create minimal test environment
.\Create-TestADObjects.ps1 -UserCount 25

# Run audit
..\kpadaudit\kpadaudit.ps1

# Validate
.\Validate-KPAuditOutput.ps1 -FilePath "TESTDOMAIN.txt"
```

### Performance Test (Large Dataset)
```powershell
# Create large dataset
.\Create-TestADObjects.ps1 -CreateLargeDataSet

# Run audit (should complete without enumeration errors)
..\kpadaudit\kpadaudit.ps1

# Validate performance optimizations
.\Validate-KPAuditOutput.ps1 -FilePath "TESTDOMAIN.txt" -Verbose
```

### Custom Domain Test
```powershell
# Test with custom domain configuration
.\Create-TestADObjects.ps1 -TestOUPath "OU=AuditTest,DC=corp,DC=example,DC=com" -UserCount 75

# Run audit
..\kpadaudit\kpadaudit.ps1

# Validate with JSON export
.\Validate-KPAuditOutput.ps1 -FilePath "CORP.txt" -ExportResults
```

## 📊 Expected Validation Results

A successful test run should show:

```
=== Validation Results ===

✅ PASSED CHECKS:
   ✓ All expected sections present
   ✓ Script_Init: Contains timestamp
   ✓ Script_Init: Contains system type detection
   ✓ AD_DomainList: Found 1 domain(s)
   ✓ User_List: All required fields present
   ✓ User_List: Found 50 user records
   ✓ User_List: Record limit properly enforced
   ✓ Group_Admins: Found built-in groups: Domain Admins, Administrators
   ✓ Group_Admins: Found test groups: TestAdmins, DatabaseAdmins, BackupAdmins
   ✓ User_LastLogon90: Found 7 stale user records
   ✓ Domain_DefaultPasswordPolicy: Found 4 policy fields
   ✓ Domain_FineGrainedPasswordPolicies: Test policy found
   ✓ GPOs_List: Found 4 GPO fields
   ✓ GPOs_List: Found test GPOs: Test Security Policy, Test Password Policy
   ✓ Performance: ResultSetSize found in User_List, Group_List
   ✓ Performance: User_List record count within limits
   ✓ No obvious error messages found

=== Summary ===
✅ Passed: 16
⚠️  Warnings: 0
❌ Errors: 0

🎉 VALIDATION SUCCESSFUL!
The KPADAUDIT script appears to be working correctly.
```

## 🔧 Troubleshooting

### Common Issues

**"Access Denied" Errors**
- Ensure you're running as Domain Administrator
- Check that RSAT AD PowerShell module is installed

**"OU Already Exists" Warnings**
- Run cleanup script first: `.\Cleanup-TestADObjects.ps1`
- Or use different TestOUPath parameter

**Python Script Not Found**
- ~~Python is no longer required~~ - The validation script is now pure PowerShell
- Ensure PowerShell 4.0+ is available
- Check execution policy: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

**Large Dataset Performance Issues**
- Monitor Domain Controller resources during large tests
- Consider running tests during off-peak hours
- Use `-CreateLargeDataSet` switch for controlled performance testing

### Validation Failures

**Missing Sections**
- Check KPADAUDIT script for syntax errors
- Verify all required PowerShell modules are available
- Check Domain Controller connectivity

**Performance Issues**
- Verify ResultSetSize optimizations are working
- Check that user counts don't exceed 1000 records
- Monitor for "enumeration context" errors

## 📝 Test Environment Notes

- **Test Domain Only**: These scripts are designed for test environments only
- **Resource Usage**: Large datasets may consume significant DC resources
- **Cleanup Important**: Always run cleanup script when testing is complete
- **Version Compatibility**: Tested with PowerShell 4.0+ (classes require PowerShell 5.0+)
- **Self-Contained**: All scripts are pure PowerShell with no external dependencies

## 🔍 Files Created During Testing

```
Test OU Structure:
OU=KPAuditTest,DC=domain,DC=com
├── OU=TestUsers (regular test users)
├── OU=TestGroups (security groups)
├── OU=DisabledUsers (disabled accounts)
└── OU=ServiceAccounts (service accounts)

Groups Created:
- TestAdmins (added to Domain Admins)
- DatabaseAdmins
- BackupAdmins
- TestUsers
- DisabledTestGroup

GPOs Created:
- Test Security Policy
- Test Password Policy
- Test Audit Policy
- Test User Rights Policy

Fine-Grained Password Policy:
- TestPasswordPolicy (applied to TestAdmins)
```

## 🚨 Security Considerations

- **Test Environment Only**: Never run these scripts in production
- **Privilege Escalation**: Test users are added to admin groups temporarily
- **Cleanup Required**: Always clean up test objects after testing
- **Audit Logs**: Test activities will generate audit events

---

*These test scripts ensure the KPADAUDIT script functions correctly across various Active Directory configurations and scales properly for enterprise environments.*
