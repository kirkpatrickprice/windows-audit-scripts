<#
KP Active Directory Auditor
Author: Randy Bartels
0.1.0   Initial release
0.1.1   Fixed issue where spaces in user names threw an error in the Get-AdResultantPasswordPolicy PowerShell command (User_AdminPasswordPolicy) (Issue #8)
0.1.2   Change output file encoding to ASCII
0.1.3   Fix ASCII Art formatting: replaced ` with ' to resolve rendering issues and added space above the first K to align tops of letters
0.1.4   (Feb 8, 2024) Add AllowReversibleEncryption and UseDESKeyOnly to Get-ADUser check (PCI DSS v4 8.3.2)
#>

<#
.SYNOPSIS
    A Windows PowerShell script that collects information from Active Directory for offline auditing
.DESCRIPTION
    This script is used by KirkpatrickPrice auditors to collect information from Active Directory. Unlike many other tools out there, the approach used in this script is "keep it lite":

    - Use only commands that are already built into the operating system -- no installer, no custom libraries
    - Built on PowerShell modules provided directly from Microsoft and that should be present on any Domain Controller
    - Minimal real-time analysis -- we collect data for off-line analysis and don't report findings during data collection. This keeps the dependencies to a minimum and the logic simple, especially important for running the script on production machines.

    Dependencies:
    - Windows PowerShell 5.1 for Windows 10 or Windows Server 2016
    - Windows PowerShell 4.0 for Windows Server 2012
    - Remote Server Administration Tools (RSAT) Active Directory Powershell module (RSAT-AD-Powershell on servers or Rsat.ActiveDirectory.DS-LDS.Tools on Windows 10)

    NOTE: This script is signed by KirkpatrickPrice using an Authenticode signature.  Use "Get-AuthenticodeSignature .\kpadaudit.ps1" to confirm the validity of the signature.
.PARAMETER OutPath
    The path to use for the output file.  
    
    If not specified, the default is to place it on the user's Desktop, but this might not work well on OneDrive-synced folders.  You can override the default by specifying a path here.

    NOTE: A check is made to validate that the path exists and the script will terminate if it does not.  Use tab-completion to reduce path-not-found errors.

.EXAMPLE
    Default run without any parameters.  Output file goes to the users' desktop.  User will be prompted to enable Windows Time Service.
    
    ./kpwinaudit.ps1

.EXAMPLE
    Overriding the destination folder with -OutPath

    ./kpwinaudit.ps1 -OutPath .\

    This will put the output file in the current working folder.

.LINK
    https://github.com/kirkpatrickprice/windows-audit-scripts

.NOTES
    Author: Randy Bartels
    Official location:  https://github.com/kirkpatrickprice/windows-audit-scripts
    Bug reports:        https://github.com/kirkpatrickprice/windows-audit-scripts/issues 
#>

[CmdletBinding()]

param(
    [Parameter(
            ParameterSetName='ParameterSet1',
            Mandatory=$False,
            Position=0,
            ValueFromPipeline=$true,
            HelpMessage="The path to use for the output file.  Default is to place it on the user's Desktop, but this might not work on OneDrive-synced folders"
            )
    ]
    [string]$OutPath
)

Clear-Host

$KPADAVERSION="0.1.3"
$OutWidth=512                   #Width to use for the outfile / setting high to avoid line truncation "..."
$MaxItemCount=1000              #Maximum number of items to return for Get-ADUser and Get-ADGroup
$BugReportsURL="https://github.com/kirkpatrickprice/windows-audit-scripts/issues"

function header {
  param (
    [string]$text
  )

  Process {
    write-host "Processing: $text"
    "$text:: ###[BEGIN]" | Out-File -encoding ascii -FilePath $Outfile -Append -width $OutWidth

  }
}

function footer {
  param (
    [string]$text
  )
  Process {
    "$text:: ###[END]" | Out-File -encoding ascii -FilePath $Outfile -Append -width $OutWidth
  }
}

function comment {
  param (
    [string]$text,
    [string]$section
  )

  Process {
    "$section:: ###$text" | Out-File -encoding ascii -FilePath $Outfile -Append -width $OutWidth
  }
}

function Invoke-MyCommand {
    param (
        [string]$section,
        [scriptblock]$command
    )

    Process {
        $errorCount = $error.count
    #    write-host "$section:: Processing Command: $command" -ForegroundColor Red
        "$section:: ###Processing Command: $command" | Out-File -encoding ascii -FilePath $Outfile -Append -width $OutWidth
        Invoke-Command -ScriptBlock $command -ErrorAction SilentlyContinue | Out-String -stream -Width $Outwidth | ForEach-Object {
            #Only print lines that have alpha/numeric/punction
            if ($_.Length -match "[A-Za-z0-9,.]") {
                "$section::$_" | Out-File -encoding ascii -FilePath $Outfile -Append -width $OutWidth
            }
            if ($error.count -gt $errorCount ) {
                "$section:: Error processing command" | Out-File -encoding ascii -FilePath $Outfile -Append -width $OutWidth
                write-debug "$error"
            }
        }
    }
}

Write-Host "
 _   ___      _                _        _      _   ______     _          
| | / (_)    | |              | |      (_)    | |  | ___ \   (_)         
| |/ / _ _ __| | ___ __   __ _| |_ _ __ _  ___| | _| |_/ / __ _  ___ ___ 
|    \| | '__| |/ / '_ \ / _' | __| '__| |/ __| |/ /  __/ '__| |/ __/ _ \
| |\  \ | |  |   <| |_) | (_| | |_| |  | | (__|   <| |  | |  | | (_|  __/
\_|_\_/_|_| _|_|\_\ .__/ \__,_|\__|_|  |_|\___|_|\_\_|  |_|  |_|\___\___|
 / _ \     | | (_)| |        |  _  (_)             | |                   
/ /_\ \ ___| |_ __|_| _____  | | | |_ _ __ ___  ___| |_ ___  _ __ _   _  
|  _  |/ __| __| \ \ / / _ \ | | | | | '__/ _ \/ __| __/ _ \| '__| | | | 
| | | | (__| |_| |\ V /  __/ | |/ /| | | |  __/ (__| || (_) | |  | |_| | 
\_|_|_/\___|\__|_| \_/ \___| |___/ |_|_|  \___|\___|\__\___/|_|   \__, | 
 / _ \          | (_) |                                            __/ | 
/ /_\ \_   _  __| |_| |_ ___  _ __                                |___/  
|  _  | | | |/ _' | | __/ _ \| '__|                                      
| | | | |_| | (_| | | || (_) | |                                         
\_| |_/\__,_|\__,_|_|\__\___/|_|                                         
                                                                         

  Version: $KPADAVERSION
                                       "


$section="Script_Init"
    $osname = Get-CimInstance Win32_OperatingSystem -ErrorAction silentlycontinue | Select-Object Caption
    switch -Regex ($osname)
    { 
        "Server 2022"   {$systemtype="Server2022"}
        "Server 2019"   {$systemtype="Server2019"}
        "Server 2016"   {$systemtype="Server2016"}
        "Server 2012"   {$systemtype="Server2012"}
        "Windows 10"    {$systemtype="Windows10"}
        "Windows 11"    {$systemtype="Windows11"}
        default         {
                            $systemtype="Unsupported"
                            Write-Host "Operating system type is not supported by the script.  Supported systems include Windows 10, Server 2012, Server 2016, Server 2019 and Server 2022."
                            Write-Host "We will continue with the tests in case we can collect some useful information.  Please report the following to your KP auditor:"
                            Write-Host
                            write-host "OSName: $($osname.caption)"
                            $PSVersionTable
                            $PSScriptRoot
                            Read-host -Prompt "Press any key to continue..."
                        }
    }

    write-host -ForegroundColor Green "Performing some pre-flight checks..."
    #CHeck if the current user is an Enterprise Admin
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)

    if ($WindowsPrincipal.IsInRole("Enterprise Admins")) {
        write-host "$($CurrentUser.Name) is an Enterprise Admin."
    } else {
        Write-Host -BackgroundColor Black -ForegroundColor Red "Could not confirm that the current user ($($CurrentUser.Name)) is an Enterprise Admin.`nIf this is incorrect, please let us know.`nBug tracking URL: https://github.com/kirkpatrickprice/windows-audit-scripts/issues"
        exit
    }

    #Test for availability of required commands
    $RequiredCommands=@(
        "Get-Date",
        "Get-ADForest",
        "Get-ADDomain",
        "Get-ADDomainController",
        "Get-ADDefaultDomainPasswordPolicy",
        "Get-ADFineGrainedPasswordPolicy",
        "Get-ADUser",
        "Get-ADDomain",
        "Get-ADGroup",
        "Get-ADGroupMember",
        "Get-ADUserResultantPasswordPolicy",
        "Get-GPO"
    )

    $AllCommandsFound=$true

    Write-Host "Checking for required commands..."
    ForEach ($command in $RequiredCommands) {
        #Have to put $_ in a temp variable as $_ gets clobbered if the command isn't found.
        try {
            if (get-command $Command -ErrorAction Stop) {
                Write-Host "[FOUND]     $Command"
            }
        } catch {
            Write-Host -BackgroundColor Black -ForegroundColor Red "[NOTFOUND]  $Command"
            $AllCommandsFound=$False
        }
    }

    if ($AllCommandsFound -eq $False) {
        Write-Host
        write-host -BackgroundColor Black -ForegroundColor Red "Not all required commands were found.  Please verify your RSAT AD Tools installation.`nIf this is incorrect, please let us know.`nBug tracking URL: https://github.com/kirkpatrickprice/windows-audit-scripts/issues"
        exit
    }

    try {
        $CurrentDomain=Get-ADDomain
        Write-Host "Domain identified as: $($CurrentDomain.Name)"
        $FileName=$CurrentDomain.Name+".txt"
    } catch {
        Write-Host "Could not determine the domain name using ""Get-ADDomain""."
        $FileName=Read-Host -Prompt "Please provide the filename to use (e.g. MyDomain.txt): "
    } 

    #Set up the output path.  If we specify the OutPath variable on the command line, use that.  Otherwise, use the desktop
    #In both cases, check that the provided path is usable and throw an error if it's not.
    if ( $OutPath.length -gt 0 ) {
        if ( Test-Path $OutPath ) {                                     #Check if the OutPath path exists
            if ( $OutPath.Substring($OutPath.Length-1) -eq "\") {       # Remove the last character if it's a back-slash "\"
                $OutPath=$OutPath.Remove($OutPath.Length -1)
            }
            $Outfile="$OutPath\$FileName"                               #Build the $Outfile path
        } else {
            Write-Host -BackgroundColor Black -ForegroundColor Red "$Outpath does not exist.  Please verify your path."
            exit
        }
    } else {
        if ( Test-Path "$home\Desktop" ) {
            $Outfile="$home\Desktop\$FileName"
        } else {
            Write-Host -BackgroundColor Black -ForegroundColor Red "Could not determine the users home directory.  Use kpadaudit.ps1 -Outpath <path> to provide a path."
            exit
        }
    }
    write-host "Sending output to $Outfile"
    #Remove the old file if it exists
    if (Test-Path $Outfile) {
        Remove-Item -Path $Outfile  
    }

    $command={ Get-Date -Format g }
    Invoke-MyCommand -section $section -command $command

    comment -section $section -text "System type is detected as $systemtype."

    write-host -ForegroundColor Green "Pre-flight checks complete.  Proceeding..."

footer -text $section

$section="AD_ForestSummary"
    header -text $section
    comment -section $section -text "This section provides some details on the AD Forest itself.  Compare these details against interviews and documentation:"
    comment -section $section -text "   ForestMode      Forest Functional Level at which AD is operating.  NOTE: different FLs support different AD capabilities, including security features."
    comment -section $section -text "                   See https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754918(v=ws.10)"
    comment -section $section -text "                   NOTE: Keep scrolling the page until you get to ""Forest Functional Levels (about two-third the way down)"
    $command={ Get-ADForest -ErrorAction SilentlyContinue | Select-Object * | format-list }
    Invoke-MyCommand -section $section -command $command
footer -text $section

$section="AD_Domain"
    header -text $section
    comment -section $section -text "This section provides some details on the current user's AD Domain.  Compare these details against interviews and documentation:"
    comment -section $section -text "   DomainMode      Domain Functional Level at which AD is operating.  NOTE: different FLs support different AD capabilities, including security features."
    comment -section $section -text "                   See https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754918(v=ws.10)"

    $command={ Get-ADDomain -ErrorAction SilentlyContinue | Select-Object * | format-list }
    Invoke-MyCommand -section $section -command $command     

$section="Domain_DomainControllers"
    header -text $section
    comment -section $section -text "This section provides a list of domain controllers for the current domain"
    $command={ Get-ADDomainController -Filter * -ErrorAction SilentlyContinue | Select-Object * | format-list }
    Invoke-MyCommand -section $section -command $command     
footer -text $section

$section="Domain_DefaultPasswordPolicy"
    header -text $section
    comment -section $section -text "This section provides the default password policy for the current domain."
    comment -section $section -text "NOTE: It's possible that there are other password policies, applied specific users or groups.  We'll get those next."
    $command={ Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue | format-list }
    Invoke-MyCommand -section $section -command $command     
footer -text $section

$section="Domain_FineGrainedPasswordPolicies"
    header -text $section
    comment -section $section -text "This section provides any fine-grained password policies that might be defined."
    comment -section $section -text "AppliesTo      This may include groups, users or other items"
    comment -section $section -text "Precedence     When conflicting settings apply, the policy with the lowest precedence wins (""We're Number One"")"
    $command={ Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue | Select-Object * | format-list }
    Invoke-MyCommand -section $section -command $command     
footer -text $section

$section="Group_List"
    header -text $section
    comment -section $section -text "This section provides list of all groups defined in the domain (max 1000 records)."
    $command={ Get-ADGroup -Filter * -ErrorAction SilentlyContinue | Select-Object -First $MaxItemCount | Format-Table -AutoSize }
    Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Group_Admins"
    header -text $section
    comment -section $section -text "This section provides information on any groups with ""Admin"" in the name."
    comment -section $section -text "First, this displays the Group Membership exactly as it appears in ADAC."
    comment -section $section -text "Then, it recurses each member group to get to the individual users with admin persmissions"
    Get-ADGroup -filter 'Name -like "*Admin*"' | ForEach-Object {
        $GroupDN=$_.DistinguishedName
        $GroupName=$_.Name.Replace(" ", "")
        $section="Group_Admins-$GroupName-ADAC"        
        $command={ Get-ADGroupMember -Identity "$GroupDN" -ErrorAction SilentlyContinue | Format-list }
        Invoke-MyCommand -section $section -command $command
        $section="Group_Admins-$GroupName-Recurse"
        $command={ Get-ADGroupMember -Identity "$GroupDN" -Recursive -ErrorAction SilentlyContinue | Format-Table -AutoSize }
        Invoke-MyCommand -section $section -command $command
    }
    $section="Group_Admins"
footer -text $section

$section="User_List"
    header -text $section
    comment -section $section -text "This section provides list of all users defined in the domain (max 1000 records)."
    $command={  Get-ADUser -Filter * -Properties * -ErrorAction SilentlyContinue | Format-Table DistinguishedName,Name,GivenName,UserPrincipalName,Enabled,SID,LastLogonDate,PasswordLastSet,PasswordNeverExpires,PasswordExpired,PasswordNotRequired,AllowReversibleEncryption,UseDESKeyOnly -AutoSize }
    Invoke-MyCommand -section $section -command $command     
footer -text $section

$section="User_AdminPasswordPolicy"
    header -text $section
    comment -section $section -text "This provides the effective password policy for users in the Domain and Enterprise Admins groups."

    #Build a list of Admin Users that we can iterate over
    $InterestingGroups=@(
        "Enterprise Admins",
        "Domain Admins"
    )   
    $AdminUsers=@()                                 #Define an array to hold the AdminUsers
    ForEach ($Group in $InterestingGroups) {
        (Get-AdGroupMember -Recursive -Identity "$Group").SamAccountName | ForEach-Object {
            $AdminUsers += "$_"
        }
    }

    #Iterate through the AdminUsers to get their effective password policy
    $AdminUsers | Select-Object -Unique | ForEach-Object {
        $User=$_
        $section="User_AdminPasswordPolicy-$User"        
        $command={ Get-ADUserResultantPasswordPolicy -Identity "$User" -ErrorAction SilentlyContinue | Format-list }
        Invoke-MyCommand -section $section -command $command
    }
    $section="User_AdminPasswordPolicy"
footer -text $section


$section="User_LastLogon90"
    header -text $section
    comment -section $section -text "This section provides list of all users who have not logged in for more than 90 days (max 1000 records)."
    $command={  Get-ADUser -Filter * -Properties LastLogonDate -ErrorAction SilentlyContinue | where-object { $_.LastLogonDate -lt (Get-Date).AddDays(-90) } | Select-Object DistinguishedName,Name,GivenName,UserPrincipalName,Enabled,LastLogonDate,PasswordLastSet,PasswordExpired -First $MaxItemCount | Sort-Object -Property LastLogonDate | Format-Table -AutoSize }
    Invoke-MyCommand -section $section -command $command     
footer -text $section

$section="GPOs_List"
    header -text $section
    comment -section $section -text "This section provides the names of all of the GPOs.  You'll need to request a GPO report for each interesting one (ideally in HTML format)"
    $command={ Get-GPO -All -ErrorAction SilentlyContinue | Select-Object DisplayName,DomainName,Owner,GpoStatus,CreationTime,ModificationTime | Format-Table -AutoSize }
    Invoke-MyCommand -section $section -command $command     
footer -text $section

# SIG # Begin signature block
# MIIfXgYJKoZIhvcNAQcCoIIfTzCCH0sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA2imfvgi2KTs5G
# XBrg4vXKrD+jhm7WUGhZzqKp/jUP3qCCDOgwggZuMIIEVqADAgECAhAtYLGndXgb
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
# spWrmo2dzJTw7XhQf+xkR6OdMYIRzDCCEcgCAQEwgYwweDELMAkGA1UEBhMCVVMx
# DjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wg
# Q29ycDE0MDIGA1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25pbmcgSW50ZXJtZWRpYXRl
# IENBIFJTQSBSMQIQLWCxp3V4G8xb8zBHQUvkijANBglghkgBZQMEAgEFAKB8MBAG
# CisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBrSyomKi7m
# TD5ZxovsjmiEbcPuT/jsOCdlWdjok8OkuDANBgkqhkiG9w0BAQEFAASCAYAJ2Aey
# HcIXEX5bkWJGniqQpUtRVg8PROVuysiVEJx84i0ei6Rz0lFuQ15UrERf+lnmT9WO
# A4dxd5pwhHlZmamxIUnf1HqYzRRfWgziiaOCzX/UruXvUG/CNCqiX/GQAP6q4Qny
# z/Vwp/G46QDLcQqUmB/MXiQuTKcINztTvjggDzlh2xjVWRj/qEB3ntgD6/x2asdE
# CmUOri0V/18nAYXAYxLE0/awnt4ev/B5FzPCnH0YmJ91eybsEpUIc3dJh57Rke19
# 9TR9rgNXxr+vfNfLdZ6OKtowMey3NfoLYC3NSqLg94/bDh46aaiqO61JgJ6A+vI9
# L5uzQVssV+MPWJcUxJjAMZS+JWF+KHzvMn4e+OFr4BDYbYeivmcekwMjAgBazGZo
# OaijnMLVnkWX+taLJBu4KRcuu9viwiKYwAn0pFtKyDzFwoa1fbBvkb4kZoGSNUBn
# TT2s9Vy1iRxPdGqvmU4TUXc4nU1PiZX2g7raPLAlw+0A/3OYsXAXNYGhrqqhgg8S
# MIIPDgYKKwYBBAGCNwMDATGCDv4wgg76BgkqhkiG9w0BBwKggg7rMIIO5wIBAzEN
# MAsGCWCGSAFlAwQCATB3BgsqhkiG9w0BCRABBKBoBGYwZAIBAQYMKwYBBAGCqTAB
# AwYBMDEwDQYJYIZIAWUDBAIBBQAEIGSZXHPYKK3GWW9oKBRgCh9//IYojWRh6Da0
# ELQRyUWzAgh9mH4OqeJGsBgPMjAyNDAyMDgyMjEzMTJaMAMCAQGgggv9MIIE+TCC
# AuGgAwIBAgIQGtYIp9Y0tc3el8ujzPDQSzANBgkqhkiG9w0BAQsFADBzMQswCQYD
# VQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xETAPBgNV
# BAoMCFNTTCBDb3JwMS8wLQYDVQQDDCZTU0wuY29tIFRpbWVzdGFtcGluZyBJc3N1
# aW5nIFJTQSBDQSBSMTAeFw0yMjEyMDkxODMwNTFaFw0zMjEyMDYxODMwNTBaMGsx
# CzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjER
# MA8GA1UECgwIU1NMIENvcnAxJzAlBgNVBAMMHlNTTC5jb20gVGltZXN0YW1waW5n
# IFVuaXQgMjAyMjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABN58+pIllLLZNNnI
# XgaHKkSv1gJjjgpCv7j9Hb7hA4fIDEIvJgwiiVUtDNqo7JJ4jqcjiP/4vVoHcm/0
# d4E9O7ijggFaMIIBVjAfBgNVHSMEGDAWgBQMnRAljpqnG5mHQ88IfuG9gZD0zzBR
# BggrBgEFBQcBAQRFMEMwQQYIKwYBBQUHMAKGNWh0dHA6Ly9jZXJ0LnNzbC5jb20v
# U1NMLmNvbS10aW1lU3RhbXBpbmctSS1SU0EtUjEuY2VyMFEGA1UdIARKMEgwPAYM
# KwYBBAGCqTABAwYBMCwwKgYIKwYBBQUHAgEWHmh0dHBzOi8vd3d3LnNzbC5jb20v
# cmVwb3NpdG9yeTAIBgZngQwBBAIwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwRgYD
# VR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NybHMuc3NsLmNvbS9TU0wuY29tLXRpbWVT
# dGFtcGluZy1JLVJTQS1SMS5jcmwwHQYDVR0OBBYEFAW6k9Hf4hSsICqGWTF/KHIO
# raxfMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAWqi0lhBjDURo
# zMeTk2UktonPEN/eeN5k1LeIys69k8AycnHM94hYaqd4jqvEZ07B7CpLeBhwI9ko
# RqDZZVOOuEGkW03mgJ1udoJC5Zwke9/cfXTg0GFiyqQKszBaijcTZR1rDj08F5mh
# kUzKQ+tpMb8jdbvoWg/UG7Mj3GFIbnoPNGfeUjAiDzQmCKaxEBIkTBzDgrZSTRrV
# o7eEnz9EeFnsRnZtIRB/LKbrqRRu4aySzHNuC0JJmmTvpct9P6tI4gvlJj5YIiJV
# 34WtQ98uEUxLPGPBtW5EDkUt1wvv6n2S5KCClQj6bZ/PCuil1foYemnkR9h2lYZk
# N0H1H59sqIsLniBvN3a5sCsSfVAc7B7krWpeqNit6Vq0hs2UDk1RLsEmaZyOUu2I
# Yx+rD9+ZJ8Y6+jWV7UcWdEWPVAlhf2tiS7aJO2MZLqOJQCY/pDbKK6efyc1W2BRg
# KisPk2yBuZUSrNxwgiQoiZb0jFYc5IUa7jVmzClIYoMAFx2r41xRVPCODpCW8aLe
# tC0BVkppdbNttlKJHuEzQIO1w/Bc8p2Fu10aQma8K8F9ffnurv52aQHdcdgu16jE
# R8KXMxEwn0AoXSpKHqF/g9OD1ZsvAU0IKVZB4z0Je2mLkRYPfC7kOV8gOkic3BRk
# M86tU7QMa736ax3vadow9dlOX5y+u/0wggb8MIIE5KADAgECAhBtUhhwh+gjTYVg
# ANCAj5NWMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVU
# ZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9u
# MTEwLwYDVQQDDChTU0wuY29tIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkg
# UlNBMB4XDTE5MTExMzE4NTAwNVoXDTM0MTExMjE4NTAwNVowczELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhT
# U0wgQ29ycDEvMC0GA1UEAwwmU1NMLmNvbSBUaW1lc3RhbXBpbmcgSXNzdWluZyBS
# U0EgQ0EgUjEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCuURAT0vk8
# IKAghd7JUBxkyeH9xek0/wp/MUjoclrFXqhh/fGH91Fc+7fm0MHCE7A+wmOiqBj9
# ODrJAYGq3rm33jCnHSsCBNWAQYyoauLq8IjqsS1JlXL29qDNMMdwZ8UNzQS7vWZM
# DJ40JSGNphMGTIA2qn2bohGtgRc4p1395ESypUOaGvJ3t0FNL3BuKmb6YctMcQUF
# 2sqooMzd89h0E6ujdvBDo6ZwNnWoxj7YmfWjSXg33A5GuY9ym4QZM5OEVgo8ebz/
# B+gyhyCLNNhh4Mb/4xvCTCMVmNYrBviGgdPZYrym8Zb84TQCmSuX0JlLLa6WK1aO
# 6qlwISbb9bVGh866ekKblC/XRP20gAu1CjvcYciUgNTrGFg8f8AJgQPOCc1/CCda
# JSYwhJpSdheKOnQgESgNmYZPhFOC6IKaMAUXk5U1tjTcFCgFvvArXtK4azAWUOO1
# Y3fdldIBL6LjkzLUCYJNkFXqhsBVcPMuB0nUDWvLJfPimstjJ8lF4S6ECxWnlWi7
# OElVwTnt1GtRqeY9ydvvGLntU+FecK7DbqHDUd366UreMkSBtzevAc9aqoZPnjVM
# jvFqV1pYOjzmTiVHZtAc80bAfFe5LLfJzPI6DntNyqobpwTevQpHqPDN9qqNO83r
# 3kaw8A9j+HZiSw2AX5cGdQP0kG0vhzfgBwIDAQABo4IBgTCCAX0wEgYDVR0TAQH/
# BAgwBgEB/wIBADAfBgNVHSMEGDAWgBTdBAkHovV6fVJTEpKV7jiAJQ2mWTCBgwYI
# KwYBBQUHAQEEdzB1MFEGCCsGAQUFBzAChkVodHRwOi8vd3d3LnNzbC5jb20vcmVw
# b3NpdG9yeS9TU0xjb21Sb290Q2VydGlmaWNhdGlvbkF1dGhvcml0eVJTQS5jcnQw
# IAYIKwYBBQUHMAGGFGh0dHA6Ly9vY3Nwcy5zc2wuY29tMD8GA1UdIAQ4MDYwNAYE
# VR0gADAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3dy5zc2wuY29tL3JlcG9zaXRv
# cnkwEwYDVR0lBAwwCgYIKwYBBQUHAwgwOwYDVR0fBDQwMjAwoC6gLIYqaHR0cDov
# L2NybHMuc3NsLmNvbS9zc2wuY29tLXJzYS1Sb290Q0EuY3JsMB0GA1UdDgQWBBQM
# nRAljpqnG5mHQ88IfuG9gZD0zzAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQEL
# BQADggIBAJIZdQ2mWkLPGQfZ8vyU+sCb8BXpRJZaL3Ez3VDlE3uZk3cPxPtybVfL
# uqaci0W6SB22JTMttCiQMnIVOsXWnIuAbD/aFTcUkTLBI3xys+wEajzXaXJYWACD
# S47BRjDtYlDW14gLJxf8W6DQoH3jHDGGy8kGJFOlDKG7/YrK7UGfHtBAEDVe6lyZ
# +FtCsrk7dD/IiL/+Q3Q6SFASJLQ2XI89ihFugdYL77CiDNXrI2MFspQGswXEAGpH
# uaQDTHUp/LdR3TyrIsLlnzoLskUGswF/KF8+kpWUiKJNC4rPWtNrxlbXYRGgdEdx
# 8SMjUTDClldcrknlFxbqHsVmr9xkT2QtFmG+dEq1v5fsIK0vHaHrWjMMmaJ9i+4q
# GJSD0stYfQ6v0PddT7EpGxGd867Ada6FZyHwbuQSadMb0K0P0OC2r7rwqBUe0BaM
# qTa6LWzWItgBjGcObXeMxmbQqlEz2YtAcErkZvh0WABDDE4U8GyV/32FdaAvJgTf
# e9MiL2nSBioYe/g5mHUSWAay/Ip1RQmQCvmF9sNfqlhJwkjy/1U1ibUkTIUBX3Hg
# ymyQvqQTZLLys6pL2tCdWcjI9YuLw30rgZm8+K387L7ycUvqrmQ3ZJlujHl3r1hg
# V76s3WwMPgKk1bAEFMj+rRXimSC+Ev30hXZdqyMdl/il5Ksd0vhGMYICVzCCAlMC
# AQEwgYcwczELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdI
# b3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDEvMC0GA1UEAwwmU1NMLmNvbSBUaW1l
# c3RhbXBpbmcgSXNzdWluZyBSU0EgQ0EgUjECEBrWCKfWNLXN3pfLo8zw0EswCwYJ
# YIZIAWUDBAIBoIIBYTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZI
# hvcNAQkFMQ8XDTI0MDIwODIyMTMxMlowKAYJKoZIhvcNAQk0MRswGTALBglghkgB
# ZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIAxPKsUbLqkh2npWkfHi
# vdgHnpbAgmf0PJ7iwHRK+1K5MIHJBgsqhkiG9w0BCRACLzGBuTCBtjCBszCBsAQg
# jcXEJULSTxXP9cgZbtRag2jUyta9y+Qhqd4jUJ2L0yIwgYswd6R1MHMxCzAJBgNV
# BAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UE
# CgwIU1NMIENvcnAxLzAtBgNVBAMMJlNTTC5jb20gVGltZXN0YW1waW5nIElzc3Vp
# bmcgUlNBIENBIFIxAhAa1gin1jS1zd6Xy6PM8NBLMAoGCCqGSM49BAMCBEYwRAIg
# CmHkce1gJ53exTPRkfgISw+dgOpo0MDohbcXB8G39IACIGY/bIJx47R92PQaDE1S
# zuHSayJMKZdwTtmMS0FGEEng
# SIG # End signature block
