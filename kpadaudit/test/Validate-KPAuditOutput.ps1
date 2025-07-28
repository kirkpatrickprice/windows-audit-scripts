<#
.SYNOPSIS
    Validates KPADAUDIT PowerShell script output for completeness and correctness
.DESCRIPTION
    This script validates the output from the KPADAUDIT PowerShell script to ensure
    all expected sections are present and contain the required data elements.
    
    This is a self-contained PowerShell validation script that eliminates the need
    for Python dependencies while providing comprehensive validation of audit results.
    
.PARAMETER FilePath
    Path to the KPADAUDIT output file to validate
    
.PARAMETER Verbose
    Enable verbose output showing additional validation details
    
.PARAMETER ExportResults
    Export validation results to a JSON file for further analysis
    
.EXAMPLE
    .\Validate-KPAuditOutput.ps1 -FilePath "TESTDOMAIN.txt"
    
.EXAMPLE
    .\Validate-KPAuditOutput.ps1 -FilePath "C:\Audit\CONTOSO.txt" -Verbose
    
.EXAMPLE
    .\Validate-KPAuditOutput.ps1 -FilePath "TESTDOMAIN.txt" -ExportResults
    
.NOTES
    Author: Generated for KPADAUDIT testing
    Requires: PowerShell 4.0 or later
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$FilePath,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportResults
)

# Validation results class
class ValidationResult {
    [string]$Type        # "Success", "Warning", "Error"
    [string]$Section
    [string]$Message
    [string]$Details
    
    ValidationResult([string]$Type, [string]$Section, [string]$Message, [string]$Details = "") {
        $this.Type = $Type
        $this.Section = $Section
        $this.Message = $Message
        $this.Details = $Details
    }
}

# Main validator class
class KPAuditValidator {
    [string]$FilePath
    [string]$Content
    [hashtable]$Sections
    [System.Collections.Generic.List[ValidationResult]]$Results
    [int]$PassCount
    [int]$WarnCount
    [int]$ErrorCount
    
    # Expected sections in the audit output
    [string[]]$ExpectedSections = @(
        "Script_Init",
        "AD_DomainList", 
        "AD_Domain",
        "Domain_DomainControllers",
        "Domain_DefaultPasswordPolicy",
        "Domain_FineGrainedPasswordPolicies",
        "Group_List",
        "Group_Admins",
        "User_List",
        "User_AdminPasswordPolicy",
        "User_LastLogon90",
        "GPOs_List"
    )
    
    # Required fields for User_List section
    [string[]]$UserListFields = @(
        "DistinguishedName",
        "Name", 
        "GivenName",
        "UserPrincipalName",
        "Enabled",
        "SID",
        "LastLogonDate",
        "PasswordLastSet",
        "PasswordNeverExpires",
        "PasswordExpired",
        "PasswordNotRequired",
        "AllowReversibleEncryption",
        "UseDESKeyOnly"
    )
    
    KPAuditValidator([string]$FilePath) {
        $this.FilePath = $FilePath
        $this.Content = ""
        $this.Sections = @{}
        $this.Results = [System.Collections.Generic.List[ValidationResult]]::new()
        $this.PassCount = 0
        $this.WarnCount = 0
        $this.ErrorCount = 0
    }
    
    [bool] LoadFile() {
        try {
            $this.Content = Get-Content -Path $this.FilePath -Raw -Encoding UTF8
            $fileSize = (Get-Item $this.FilePath).Length
            Write-Host "✓ Loaded file: $($this.FilePath) ($($fileSize.ToString('N0')) bytes)" -ForegroundColor Green
            return $true
        }
        catch {
            $this.AddResult("Error", "FileLoad", "Failed to load file: $($_.Exception.Message)")
            return $false
        }
    }
    
    [void] ParseSections() {
        # Parse sections using regex pattern for ###[BEGIN] and ###[END] markers
        $pattern = '(\w+):: ###\[BEGIN\](.*?)(\w+):: ###\[END\]'
        $regexMatches = [regex]::Matches($this.Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
        
        foreach ($match in $regexMatches) {
            $startSection = $match.Groups[1].Value
            $sectionContent = $match.Groups[2].Value.Trim()
            $endSection = $match.Groups[3].Value
            
            if ($startSection -eq $endSection) {
                $this.Sections[$startSection] = $sectionContent
            }
            else {
                $this.AddResult("Warning", "SectionParsing", "Section mismatch: $startSection -> $endSection")
            }
        }
        
        Write-Host "✓ Parsed $($this.Sections.Count) sections" -ForegroundColor Green
    }
    
    [void] AddResult([string]$Type, [string]$Section, [string]$Message, [string]$Details = "") {
        $result = [ValidationResult]::new($Type, $Section, $Message, $Details)
        $this.Results.Add($result)
        
        switch ($Type) {
            "Success" { $this.PassCount++ }
            "Warning" { $this.WarnCount++ }
            "Error" { $this.ErrorCount++ }
        }
    }
    
    [void] ValidateSectionPresence() {
        $missingSections = @()
        foreach ($section in $this.ExpectedSections) {
            if (-not $this.Sections.ContainsKey($section)) {
                $missingSections += $section
            }
        }
        
        if ($missingSections.Count -gt 0) {
            $this.AddResult("Error", "SectionPresence", "Missing sections: $($missingSections -join ', ')")
        }
        else {
            $this.AddResult("Success", "SectionPresence", "All expected sections present")
        }
    }
    
    [void] ValidateScriptInit() {
        if (-not $this.Sections.ContainsKey("Script_Init")) {
            return
        }
        
        $sectionContent = $this.Sections["Script_Init"]
        
        # Check for timestamp
        if ($sectionContent -match "Processing Command: Get-Date") {
            $this.AddResult("Success", "Script_Init", "Contains timestamp")
        }
        else {
            $this.AddResult("Warning", "Script_Init", "No timestamp found")
        }
        
        # Check for system type detection
        if ($sectionContent -match "System type is detected as") {
            $this.AddResult("Success", "Script_Init", "Contains system type detection")
        }
        else {
            $this.AddResult("Warning", "Script_Init", "No system type detection found")
        }
        
        # Check for version information
        if ($sectionContent -match "Version: \d+\.\d+\.\d+") {
            $this.AddResult("Success", "Script_Init", "Contains version information")
        }
    }
    
    [void] ValidateADDomainList() {
        if (-not $this.Sections.ContainsKey("AD_DomainList")) {
            return
        }
        
        $sectionContent = $this.Sections["AD_DomainList"]
        
        # Look for domain patterns (FQDN format)
        $domainPattern = '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        $domains = [regex]::Matches($sectionContent, $domainPattern)
        
        if ($domains.Count -gt 0) {
            $this.AddResult("Success", "AD_DomainList", "Found $($domains.Count) domain(s)")
        }
        else {
            $this.AddResult("Warning", "AD_DomainList", "No domains found")
        }
    }
    
    [void] ValidateUserList() {
        if (-not $this.Sections.ContainsKey("User_List")) {
            return
        }
        
        $sectionContent = $this.Sections["User_List"]
        
        # Check for required field headers
        $missingFields = @()
        foreach ($field in $this.UserListFields) {
            if ($sectionContent -notmatch [regex]::Escape($field)) {
                $missingFields += $field
            }
        }
        
        if ($missingFields.Count -gt 0) {
            $this.AddResult("Warning", "User_List", "Missing field headers: $($missingFields -join ', ')")
        }
        else {
            $this.AddResult("Success", "User_List", "All required fields present")
        }
        
        # Count user records (lines with CN= but not header lines)
        $userLines = ($sectionContent -split "`n" | Where-Object { $_ -match 'CN=' -and $_ -notmatch 'DistinguishedName' })
        $userCount = $userLines.Count
        
        if ($userCount -gt 0) {
            $this.AddResult("Success", "User_List", "Found $userCount user records")
            
            # Check if limit is being enforced (should be <= 1000)
            if ($userCount -le 1000) {
                $this.AddResult("Success", "User_List", "Record limit properly enforced")
            }
            else {
                $this.AddResult("Warning", "User_List", "Record count ($userCount) exceeds expected limit of 1000")
            }
        }
        else {
            $this.AddResult("Warning", "User_List", "No user records found")
        }
    }
    
    [void] ValidateGroupAdmins() {
        if (-not $this.Sections.ContainsKey("Group_Admins")) {
            return
        }
        
        $sectionContent = $this.Sections["Group_Admins"]
        
        # Check for built-in admin groups
        $builtinGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
        $foundGroups = @()
        
        foreach ($group in $builtinGroups) {
            $groupNoSpaces = $group -replace ' ', ''
            if ($sectionContent -match [regex]::Escape($groupNoSpaces)) {
                $foundGroups += $group
            }
        }
        
        if ($foundGroups.Count -gt 0) {
            $this.AddResult("Success", "Group_Admins", "Found built-in groups: $($foundGroups -join ', ')")
        }
        else {
            $this.AddResult("Warning", "Group_Admins", "No built-in admin groups found")
        }
        
        # Check for test admin groups
        $testGroups = @("TestAdmins", "DatabaseAdmins", "BackupAdmins")
        $foundTestGroups = @()
        
        foreach ($group in $testGroups) {
            if ($sectionContent -match [regex]::Escape($group)) {
                $foundTestGroups += $group
            }
        }
        
        if ($foundTestGroups.Count -gt 0) {
            $this.AddResult("Success", "Group_Admins", "Found test groups: $($foundTestGroups -join ', ')")
        }
    }
    
    [void] ValidateUserLastLogon90() {
        if (-not $this.Sections.ContainsKey("User_LastLogon90")) {
            return
        }
        
        $sectionContent = $this.Sections["User_LastLogon90"]
        
        # Check for proper date filtering indication
        if ($sectionContent -match "90 days") {
            $this.AddResult("Success", "User_LastLogon90", "Contains 90-day filter reference")
        }
        
        # Count stale user records
        $userLines = ($sectionContent -split "`n" | Where-Object { $_ -match 'CN=' -and $_ -notmatch 'DistinguishedName' })
        $staleCount = $userLines.Count
        
        $this.AddResult("Success", "User_LastLogon90", "Found $staleCount stale user records")
    }
    
    [void] ValidatePasswordPolicies() {
        # Default password policy
        if ($this.Sections.ContainsKey("Domain_DefaultPasswordPolicy")) {
            $sectionContent = $this.Sections["Domain_DefaultPasswordPolicy"]
            $policyFields = @("ComplexityEnabled", "MinPasswordLength", "MaxPasswordAge", "MinPasswordAge")
            
            $foundFields = @()
            foreach ($field in $policyFields) {
                if ($sectionContent -match [regex]::Escape($field)) {
                    $foundFields += $field
                }
            }
            
            if ($foundFields.Count -gt 0) {
                $this.AddResult("Success", "Domain_DefaultPasswordPolicy", "Found $($foundFields.Count) policy fields")
            }
        }
        
        # Fine-grained password policies
        if ($this.Sections.ContainsKey("Domain_FineGrainedPasswordPolicies")) {
            $sectionContent = $this.Sections["Domain_FineGrainedPasswordPolicies"]
            if ($sectionContent -match "TestPasswordPolicy") {
                $this.AddResult("Success", "Domain_FineGrainedPasswordPolicies", "Test policy found")
            }
        }
    }
    
    [void] ValidateGPOs() {
        if (-not $this.Sections.ContainsKey("GPOs_List")) {
            return
        }
        
        $sectionContent = $this.Sections["GPOs_List"]
        
        # Check for GPO fields
        $gpoFields = @("DisplayName", "DomainName", "Owner", "GpoStatus")
        $foundFields = @()
        
        foreach ($field in $gpoFields) {
            if ($sectionContent -match [regex]::Escape($field)) {
                $foundFields += $field
            }
        }
        
        if ($foundFields.Count -gt 0) {
            $this.AddResult("Success", "GPOs_List", "Found $($foundFields.Count) GPO fields")
        }
        
        # Check for test GPOs
        $testGPOs = @("Test Security Policy", "Test Password Policy", "Test Audit Policy")
        $foundTestGPOs = @()
        
        foreach ($gpo in $testGPOs) {
            if ($sectionContent -match [regex]::Escape($gpo)) {
                $foundTestGPOs += $gpo
            }
        }
        
        if ($foundTestGPOs.Count -gt 0) {
            $this.AddResult("Success", "GPOs_List", "Found test GPOs: $($foundTestGPOs -join ', ')")
        }
    }
    
    [void] ValidatePerformanceOptimizations() {
        # Check for ResultSetSize usage in commands
        $commandsWithResultSetSize = @()
        
        foreach ($sectionName in $this.Sections.Keys) {
            $sectionContent = $this.Sections[$sectionName]
            if ($sectionContent -match "ResultSetSize") {
                $commandsWithResultSetSize += $sectionName
            }
        }
        
        if ($commandsWithResultSetSize.Count -gt 0) {
            $this.AddResult("Success", "Performance", "ResultSetSize found in: $($commandsWithResultSetSize -join ', ')")
        }
        
        # Check that User_List doesn't exceed reasonable limits
        if ($this.Sections.ContainsKey("User_List")) {
            $sectionContent = $this.Sections["User_List"]
            $userLines = ($sectionContent -split "`n" | Where-Object { $_ -match 'CN=' -and $_ -notmatch 'DistinguishedName' })
            
            if ($userLines.Count -le 1000) {
                $this.AddResult("Success", "Performance", "User_List record count within limits")
            }
            else {
                $this.AddResult("Warning", "Performance", "User_List has $($userLines.Count) records (exceeds 1000)")
            }
        }
    }
    
    [void] CheckForErrors() {
        # Check for error messages in the output
        $errorPatterns = @(
            "Error processing command",
            "invalid enumeration context",
            "Exception",
            "Failed"
        )
        
        $foundErrors = @()
        foreach ($pattern in $errorPatterns) {
            $regexMatches = [regex]::Matches($this.Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($regexMatches.Count -gt 0) {
                $foundErrors += "$($regexMatches.Count) instances of '$pattern'"
            }
        }
        
        if ($foundErrors.Count -gt 0) {
            $this.AddResult("Warning", "ErrorCheck", "Potential errors found: $($foundErrors -join ', ')")
        }
        else {
            $this.AddResult("Success", "ErrorCheck", "No obvious error messages found")
        }
    }
    
    [void] ValidateAll() {
        Write-Host "`n=== KPADAUDIT Output Validation ===" -ForegroundColor Cyan
        Write-Host "File: $($this.FilePath)" -ForegroundColor White
        $fileSize = (Get-Item $this.FilePath).Length
        Write-Host "Size: $($fileSize.ToString('N0')) bytes" -ForegroundColor White
        Write-Host ""
        
        # Parse content
        $this.ParseSections()
        
        # Run all validations
        $this.ValidateSectionPresence()
        $this.ValidateScriptInit()
        $this.ValidateADDomainList()
        $this.ValidateUserList()
        $this.ValidateGroupAdmins()
        $this.ValidateUserLastLogon90()
        $this.ValidatePasswordPolicies()
        $this.ValidateGPOs()
        $this.ValidatePerformanceOptimizations()
        $this.CheckForErrors()
    }
    
    [void] PrintResults([bool]$VerboseOutput = $false) {
        Write-Host "`n=== Validation Results ===" -ForegroundColor Cyan
        
        # Group results by type
        $successResults = $this.Results | Where-Object { $_.Type -eq "Success" }
        $warningResults = $this.Results | Where-Object { $_.Type -eq "Warning" }
        $errorResults = $this.Results | Where-Object { $_.Type -eq "Error" }
        
        # Print successes
        if ($successResults.Count -gt 0) {
            Write-Host "`n✅ PASSED CHECKS:" -ForegroundColor Green
            foreach ($result in $successResults) {
                $message = if ($VerboseOutput -and $result.Section) { "$($result.Section): $($result.Message)" } else { $result.Message }
                Write-Host "   ✓ $message" -ForegroundColor Green
            }
        }
        
        # Print warnings
        if ($warningResults.Count -gt 0) {
            Write-Host "`n⚠️  WARNINGS:" -ForegroundColor Yellow
            foreach ($result in $warningResults) {
                $message = if ($VerboseOutput -and $result.Section) { "$($result.Section): $($result.Message)" } else { $result.Message }
                Write-Host "   ⚠️  $message" -ForegroundColor Yellow
            }
        }
        
        # Print errors
        if ($errorResults.Count -gt 0) {
            Write-Host "`n❌ ERRORS:" -ForegroundColor Red
            foreach ($result in $errorResults) {
                $message = if ($VerboseOutput -and $result.Section) { "$($result.Section): $($result.Message)" } else { $result.Message }
                Write-Host "   ❌ $message" -ForegroundColor Red
            }
        }
        
        # Summary
        Write-Host "`n=== Summary ===" -ForegroundColor Cyan
        Write-Host "✅ Passed: $($this.PassCount)" -ForegroundColor Green
        Write-Host "⚠️  Warnings: $($this.WarnCount)" -ForegroundColor Yellow
        Write-Host "❌ Errors: $($this.ErrorCount)" -ForegroundColor Red
        
        # Final status
        if ($this.ErrorCount -eq 0 -and $this.PassCount -gt 0) {
            Write-Host "`n🎉 VALIDATION SUCCESSFUL!" -ForegroundColor Green
            Write-Host "The KPADAUDIT script appears to be working correctly." -ForegroundColor Green
        }
        elseif ($this.ErrorCount -gt 0) {
            Write-Host "`n💥 VALIDATION FAILED!" -ForegroundColor Red
            Write-Host "Critical issues found that need to be addressed." -ForegroundColor Red
        }
        else {
            Write-Host "`n⚠️  VALIDATION INCOMPLETE!" -ForegroundColor Yellow
            Write-Host "Some issues found but no critical errors." -ForegroundColor Yellow
        }
    }
    
    [hashtable] ExportResults() {
        $export = @{
            FilePath = $this.FilePath
            ValidationDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Summary = @{
                Passed = $this.PassCount
                Warnings = $this.WarnCount
                Errors = $this.ErrorCount
                TotalSections = $this.Sections.Count
            }
            Results = @()
        }
        
        foreach ($result in $this.Results) {
            $export.Results += @{
                Type = $result.Type
                Section = $result.Section
                Message = $result.Message
                Details = $result.Details
            }
        }
        
        return $export
    }
}

# Main execution
try {
    # Validate file exists
    if (-not (Test-Path $FilePath -PathType Leaf)) {
        Write-Host "❌ Error: File not found: $FilePath" -ForegroundColor Red
        exit 1
    }
    
    # Create validator and run validation
    $validator = [KPAuditValidator]::new($FilePath)
    
    if (-not $validator.LoadFile()) {
        Write-Host "❌ Failed to load file" -ForegroundColor Red
        exit 1
    }
    
    $validator.ValidateAll()
    $validator.PrintResults($Verbose)
    
    # Export results if requested
    if ($ExportResults) {
        $exportPath = [System.IO.Path]::ChangeExtension($FilePath, "validation.json")
        $exportData = $validator.ExportResults()
        $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $exportPath -Encoding UTF8
        Write-Host "`n📄 Validation results exported to: $exportPath" -ForegroundColor Cyan
    }
    
    # Return appropriate exit code
    if ($validator.ErrorCount -gt 0) {
        exit 1
    }
    else {
        exit 0
    }
}
catch {
    Write-Host "❌ Unexpected error during validation: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
}
