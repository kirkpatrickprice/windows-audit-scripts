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
    
.PARAMETER VerboseOutput
    Enable verbose output showing additional validation details
    
.PARAMETER ExportResults
    Export validation results to a JSON file for further analysis
    
.EXAMPLE
    .\Validate-KPAuditOutput.ps1 -FilePath "TESTDOMAIN.txt"
    
.EXAMPLE
    .\Validate-KPAuditOutput.ps1 -FilePath "C:\Audit\CONTOSO.txt" -VerboseOutput
    
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
    [switch]$VerboseOutput,
    
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
        "AllowReversiblePasswordEncryption",
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
            $fileSizeFormatted = $fileSize.ToString('N0')
            Write-Host "Loaded file: $($this.FilePath) ($fileSizeFormatted bytes)" -ForegroundColor Green
            return $true
        }
        catch {
            $this.AddResult("Error", "FileLoad", "Failed to load file: $($_.Exception.Message)")
            return $false
        }
    }
    
    [void] ParseSections() {
        # Parse sections with proper header/footer validation and content line counting
        
        # First, find all expected sections and validate header/footer presence
        foreach ($expectedSection in $this.ExpectedSections) {
            $hasHeader = $this.Content -match "$expectedSection:: ###\[BEGIN\]"
            $hasFooter = $this.Content -match "$expectedSection:: ###\[END\]"
            
            if (-not $hasHeader -and -not $hasFooter) {
                # Section completely missing
                $this.AddResult("Error", "SectionStructure", "Section '$expectedSection' is completely missing (no header or footer found)")
                continue
            }
            
            if (-not $hasHeader) {
                $this.AddResult("Error", "SectionStructure", "Section '$expectedSection' missing header marker (###[BEGIN])")
            }
            
            if (-not $hasFooter) {
                $this.AddResult("Error", "SectionStructure", "Section '$expectedSection' missing footer marker (###[END])")
            }
            
            # If both header and footer exist, extract and analyze content
            if ($hasHeader -and $hasFooter) {
                $pattern = "$expectedSection:: ###\[BEGIN\](.*?)$expectedSection:: ###\[END\]"
                $match = [regex]::Match($this.Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
                
                if ($match.Success) {
                    $fullSectionContent = $match.Groups[1].Value.Trim()
                    $this.Sections[$expectedSection] = $fullSectionContent
                    
                    # Count actual content lines (exclude comments and empty lines)
                    $contentLines = $fullSectionContent -split "`n" | Where-Object { 
                        $line = $_.Trim()
                        # Skip empty lines and comment lines (those starting with ###)
                        $line -ne "" -and -not ($line -match "^$expectedSection:: ###")
                    }
                    
                    $contentLineCount = $contentLines.Count
                    
                    if ($contentLineCount -eq 0) {
                        $this.AddResult("Warning", "SectionContent", "Section '$expectedSection' has no content lines (only comments/headers)")
                    }
                    else {
                        $this.AddResult("Success", "SectionContent", "Section '$expectedSection' has $contentLineCount content line(s)")
                    }
                }
            }
            elseif ($hasHeader -or $hasFooter) {
                # One marker exists but not the other - try to extract what we can
                if ($hasHeader) {
                    # Extract from header to next section or end of file
                    $pattern = "$expectedSection:: ###\[BEGIN\](.*?)(?=\w+:: ###\[BEGIN\]|\z)"
                    $match = [regex]::Match($this.Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
                    if ($match.Success) {
                        $this.Sections[$expectedSection] = $match.Groups[1].Value.Trim()
                    }
                }
            }
        }
        
        Write-Host "Parsed $($this.Sections.Count) sections" -ForegroundColor Green
    }
    
    [void] AddResult([string]$Type, [string]$Section, [string]$Message) {
        $this.AddResult($Type, $Section, $Message, "")
    }
    
    [void] AddResult([string]$Type, [string]$Section, [string]$Message, [string]$Details) {
        $result = [ValidationResult]::new($Type, $Section, $Message, $Details)
        $this.Results.Add($result)
        
        switch ($Type) {
            "Success" { $this.PassCount++ }
            "Warning" { $this.WarnCount++ }
            "Error" { $this.ErrorCount++ }
        }
    }
    
    [void] ValidateSectionPresence() {
        # Section presence is now validated during parsing
        # This method now just provides a summary
        $presentSections = @()
        $missingSections = @()
        
        foreach ($section in $this.ExpectedSections) {
            if ($this.Sections.ContainsKey($section)) {
                $presentSections += $section
            }
            else {
                $missingSections += $section
            }
        }
        
        if ($presentSections.Count -gt 0) {
            $this.AddResult("Success", "SectionPresence", "Found $($presentSections.Count) of $($this.ExpectedSections.Count) expected sections")
        }
        
        if ($missingSections.Count -gt 0) {
            $this.AddResult("Error", "SectionPresence", "Missing sections: $($missingSections -join ', ')")
        }
    }
    
    [void] ValidateScriptInit() {
        if (-not $this.Sections.ContainsKey("Script_Init")) {
            return
        }
        
        $sectionContent = $this.Sections["Script_Init"]
        
        # Check for timestamp command and actual timestamp
        if ($sectionContent -match "###Processing Command:\s+Get-Date") {
            $this.AddResult("Success", "Script_Init", "Contains timestamp command")
            
            # Also check for actual timestamp output (date/time format)
            if ($sectionContent -match "\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}\s+(AM|PM)") {
                $this.AddResult("Success", "Script_Init", "Contains timestamp output")
            }
            else {
                $this.AddResult("Warning", "Script_Init", "Timestamp command found but no timestamp output detected")
            }
        }
        else {
            $this.AddResult("Warning", "Script_Init", "No timestamp command found")
        }
        
        # Check for system type detection
        if ($sectionContent -match "###System type is detected as") {
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
    
    [void] ValidateBuiltinAdministratorAccounts() {
        if (-not $this.Sections.ContainsKey("Group_Admins")) {
            return
        }
        
        $sectionContent = $this.Sections["Group_Admins"]
        
        # Check for built-in admin groups and their administrator account patterns
        $builtinGroups = @("Domain_Admins", "Enterprise_Admins", "Schema_Admins", "Administrators")
        $foundAdacPatterns = @()
        $foundRecursePatterns = @()
        $missingAdacPatterns = @()
        $missingRecursePatterns = @()
        
        foreach ($group in $builtinGroups) {
            # Check for ADAC pattern
            $adacPattern = "Group_Admins-$group-ADAC::distinguishedName"
            if ($sectionContent -match [regex]::Escape($adacPattern)) {
                $foundAdacPatterns += $group
            }
            else {
                $missingAdacPatterns += $group
            }
            
            # Check for Recurse pattern
            $recursePattern = "Group_Admins-$group-Recurse::distinguishedName"
            if ($sectionContent -match [regex]::Escape($recursePattern)) {
                $foundRecursePatterns += $group
            }
            else {
                $missingRecursePatterns += $group
            }
        }
        
        # Report ADAC validation results
        if ($foundAdacPatterns.Count -eq $builtinGroups.Count) {
            $this.AddResult("Success", "Group_Admins", "Found ADAC patterns for all built-in admin groups: $($foundAdacPatterns -join ', ')")
        }
        else {
            if ($foundAdacPatterns.Count -gt 0) {
                $this.AddResult("Warning", "Group_Admins", "Found ADAC patterns for: $($foundAdacPatterns -join ', '), but missing: $($missingAdacPatterns -join ', ')")
            }
            $this.AddResult("Error", "Group_Admins", "Missing ADAC distinguishedName patterns for built-in admin groups: $($missingAdacPatterns -join ', ')")
        }
        
        # Report Recurse validation results
        if ($foundRecursePatterns.Count -eq $builtinGroups.Count) {
            $this.AddResult("Success", "Group_Admins", "Found Recurse patterns for all built-in admin groups: $($foundRecursePatterns -join ', ')")
        }
        else {
            if ($foundRecursePatterns.Count -gt 0) {
                $this.AddResult("Warning", "Group_Admins", "Found Recurse patterns for: $($foundRecursePatterns -join ', '), but missing: $($missingRecursePatterns -join ', ')")
            }
            $this.AddResult("Error", "Group_Admins", "Missing Recurse patterns for built-in admin groups: $($missingRecursePatterns -join ', ')")
        }
        
        # Check for the presence of distinguishedName content indicating successful data collection
        $distinguishedNameCount = ($sectionContent | Select-String "Group_Admins.*distinguishedName" -AllMatches).Matches.Count
        if ($distinguishedNameCount -gt 0) {
            $this.AddResult("Success", "Group_Admins", "Found $distinguishedNameCount distinguishedName entries indicating successful data collection")
        }
        else {
            $this.AddResult("Error", "Group_Admins", "No distinguishedName entries found - collection script may have failed")
        }
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
        $fileSizeFormatted = $fileSize.ToString('N0')
        Write-Host "Size: $fileSizeFormatted bytes" -ForegroundColor White
        Write-Host ""
        
        # Parse content
        $this.ParseSections()
        
        # Run all validations
        $this.ValidateSectionPresence()
        $this.ValidateScriptInit()
        $this.ValidateADDomainList()
        $this.ValidateUserList()
        $this.ValidateGroupAdmins()
        $this.ValidateBuiltinAdministratorAccounts()
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
            Write-Host "`nPASSED CHECKS:" -ForegroundColor Green
            foreach ($result in $successResults) {
                $message = if ($VerboseOutput -and $result.Section) { "$($result.Section): $($result.Message)" } else { $result.Message }
                Write-Host "   $message" -ForegroundColor Green
            }
        }
        
        # Print warnings
        if ($warningResults.Count -gt 0) {
            Write-Host "`nWARNINGS:" -ForegroundColor Yellow
            foreach ($result in $warningResults) {
                $message = if ($VerboseOutput -and $result.Section) { "$($result.Section): $($result.Message)" } else { $result.Message }
                Write-Host "   $message" -ForegroundColor Yellow
            }
        }
        
        # Print errors
        if ($errorResults.Count -gt 0) {
            Write-Host "`nERRORS:" -ForegroundColor Red
            foreach ($result in $errorResults) {
                $message = if ($VerboseOutput -and $result.Section) { "$($result.Section): $($result.Message)" } else { $result.Message }
                Write-Host "   $message" -ForegroundColor Red
            }
        }
        
        # Summary
        Write-Host "`n=== Summary ===" -ForegroundColor Cyan
        Write-Host "Passed: $($this.PassCount)" -ForegroundColor Green
        Write-Host "Warnings: $($this.WarnCount)" -ForegroundColor Yellow
        Write-Host "Errors: $($this.ErrorCount)" -ForegroundColor Red
        
        # Final status
        if ($this.ErrorCount -eq 0 -and $this.PassCount -gt 0) {
            Write-Host "`nVALIDATION SUCCESSFUL!" -ForegroundColor Green
            Write-Host "The KPADAUDIT script appears to be working correctly." -ForegroundColor Green
        }
        elseif ($this.ErrorCount -gt 0) {
            Write-Host "`nVALIDATION FAILED!" -ForegroundColor Red
            Write-Host "Critical issues found that need to be addressed." -ForegroundColor Red
        }
        else {
            Write-Host "`nVALIDATION INCOMPLETE!" -ForegroundColor Yellow
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
        Write-Host "Error: File not found: $FilePath" -ForegroundColor Red
        exit 1
    }
    
    # Create validator and run validation
    $validator = [KPAuditValidator]::new($FilePath)
    
    if (-not $validator.LoadFile()) {
        Write-Host "Failed to load file" -ForegroundColor Red
        exit 1
    }
    
    $validator.ValidateAll()
    $validator.PrintResults($VerboseOutput)
    
    # Export results if requested
    if ($ExportResults) {
        $exportPath = [System.IO.Path]::ChangeExtension($FilePath, "validation.json")
        $exportData = $validator.ExportResults()
        $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $exportPath -Encoding UTF8
        Write-Host "`nValidation results exported to: $exportPath" -ForegroundColor Cyan
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
    Write-Host "Unexpected error during validation: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
}

# SIG # Begin signature block
# MIIfYwYJKoZIhvcNAQcCoIIfVDCCH1ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBUXIiXiOmWBBhZ
# aVneltyAFoOghmRuqETKLw+4HNa816CCDOgwggZuMIIEVqADAgECAhAtYLGndXgb
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
# spWrmo2dzJTw7XhQf+xkR6OdMYIR0TCCEc0CAQEwgYwweDELMAkGA1UEBhMCVVMx
# DjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wg
# Q29ycDE0MDIGA1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25pbmcgSW50ZXJtZWRpYXRl
# IENBIFJTQSBSMQIQLWCxp3V4G8xb8zBHQUvkijANBglghkgBZQMEAgEFAKB8MBAG
# CisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC/T8fH6IwM
# tCLmaDxu3hgrKgf/hSBe4MBNPO8yv8ftuzANBgkqhkiG9w0BAQEFAASCAYAfaxSZ
# TF1alJt1CzzlxN0fwbm2+CzX67xkaLjK9Vwsll+07Emjhp5o2EsuWtYcl0nTWXsJ
# QwqERwypD2bU2iUpWlBa6sQ3z1YqxtULehyuZgm63l4hR3lN8xKVQpCc6BLl1pXt
# 3+rei4owc8RRwzqhHJYecUALvmooKeUJEYbW1p6VSpLd3K9DWVKmzSfmNSlW51F5
# egQz558ljCCKJS9m3DGqH0E1hFb0zm7OYDMdFwbQuQboFcN53rR24z5GFzb9xJfm
# 5TD3y1VX1iQiqY6CXTAlo4aPoX4EieDn5KuihOiEIF95e0mK4RaXVf9QcsAJIg/O
# 6LvAnhM9fZV3Ud7ntLg7jHFrAfdhaqJXZ6bPs0ia36NezMsQQpjPZHki4zbdEB95
# +G7s5grVngpcTtWqi+Gk1UinyAZ81oXexJsUNcxATVysh+/QvyP4law5BiLuA5Qc
# nIqAaVyVw/BNrrAYwEmhpGF02TNj/MArwCb35ILwQVy+DnPggBj5dyeaTdOhgg8X
# MIIPEwYKKwYBBAGCNwMDATGCDwMwgg7/BgkqhkiG9w0BBwKggg7wMIIO7AIBAzEN
# MAsGCWCGSAFlAwQCATB3BgsqhkiG9w0BCRABBKBoBGYwZAIBAQYMKwYBBAGCqTAB
# AwYBMDEwDQYJYIZIAWUDBAIBBQAEIH4A6AlZAYac6oxHmLVF6ICft5FIE5n9r+Zg
# GtuclaaQAggq9R9W2M1hYxgPMjAyNTA3MjkwMTA0MzhaMAMCAQGgggwAMIIE/DCC
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
# r1hgV76s3WwMPgKk1bAEFMj+rRXimSC+Ev30hXZdqyMdl/il5Ksd0vhGMYICWTCC
# AlUCAQEwgYcwczELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQH
# DAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDEvMC0GA1UEAwwmU1NMLmNvbSBU
# aW1lc3RhbXBpbmcgSXNzdWluZyBSU0EgQ0EgUjECEFparOgaNW60YoaNV33gPccw
# CwYJYIZIAWUDBAIBoIIBYTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJ
# KoZIhvcNAQkFMQ8XDTI1MDcyOTAxMDQzOFowKAYJKoZIhvcNAQk0MRswGTALBglg
# hkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIEkocaBmA+w8e7B/
# Cf1AdFXnfE6Ag7mrLcNt2H8m5DhiMIHJBgsqhkiG9w0BCRACLzGBuTCBtjCBszCB
# sAQgnXF/jcI3ZarOXkqw4fV115oX1Bzu2P2v7wP9Pb2JR+cwgYswd6R1MHMxCzAJ
# BgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8G
# A1UECgwIU1NMIENvcnAxLzAtBgNVBAMMJlNTTC5jb20gVGltZXN0YW1waW5nIElz
# c3VpbmcgUlNBIENBIFIxAhBaWqzoGjVutGKGjVd94D3HMAoGCCqGSM49BAMCBEgw
# RgIhAKo8goFzQhD6qCQHKNI9CUvpb/EQYJu+hf2krIWtb/o7AiEAv2SDMoehhy+q
# 9hBwHbmnuV/EKLWnNVzoy3NtUHMPBxo=
# SIG # End signature block
