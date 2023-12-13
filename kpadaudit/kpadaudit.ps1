<#
KP Active Directory Auditor
Author: Randy Bartels
0.1.0   Initial release
0.1.1   Fixed issue where spaces in user names threw an error in the Get-AdResultantPasswordPolicy PowerShell command (User_AdminPasswordPolicy) (Issue #8)
0.1.2   Change output file encoding to ASCII
0.1.3   Fix ASCII Art formatting: replaced ` with ' to resolve rendering issues and added space above the first K to align tops of letters
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
    $command={  Get-ADUser -Filter * -Properties * -ErrorAction SilentlyContinue | Select-Object DistinguishedName,Name,GivenName,UserPrincipalName,Enabled,SID,LastLogonDate,PasswordLastSet,PasswordNeverExpires,PasswordExpired,PasswordNotRequired -First $MaxItemCount | Format-Table -AutoSize }
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
# MIIOZQYJKoZIhvcNAQcCoIIOVjCCDlICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUpfO9R1mVysFARjvMzMT87pr5
# Pjigggw/MIIDeTCCAv6gAwIBAgIQHM+dZ83iGf8S2Zr/NoLlpzAKBggqhkjOPQQD
# AzB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0
# b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8GA1UEAwwoU1NMLmNvbSBS
# b290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IEVDQzAeFw0xOTAzMDcxOTM1NDda
# Fw0zNDAzMDMxOTM1NDdaMHgxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQ
# MA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENvcnAxNDAyBgNVBAMMK1NT
# TC5jb20gQ29kZSBTaWduaW5nIEludGVybWVkaWF0ZSBDQSBFQ0MgUjIwdjAQBgcq
# hkjOPQIBBgUrgQQAIgNiAATqbe4MiW33ZdU8l6ycuiWRrnicKt/Xds/xTiU25zUb
# mK5UvNtzFiry6fs4ij0QrppV1mIgkuV9MWcVr9hSMbA/U3+7QpvCXKkrGulvLkco
# 10/shAYJVUXDiRmYiI3hcSSjggFHMIIBQzASBgNVHRMBAf8ECDAGAQH/AgEAMB8G
# A1UdIwQYMBaAFILRhXMw5zUE044CkvvlpNHEIejNMHgGCCsGAQUFBwEBBGwwajBG
# BggrBgEFBQcwAoY6aHR0cDovL3d3dy5zc2wuY29tL3JlcG9zaXRvcnkvU1NMY29t
# LVJvb3RDQS1FQ0MtMzg0LVIxLmNydDAgBggrBgEFBQcwAYYUaHR0cDovL29jc3Bz
# LnNzbC5jb20wEQYDVR0gBAowCDAGBgRVHSAAMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MDsGA1UdHwQ0MDIwMKAuoCyGKmh0dHA6Ly9jcmxzLnNzbC5jb20vc3NsLmNvbS1l
# Y2MtUm9vdENBLmNybDAdBgNVHQ4EFgQUMnixDpDbRs8az7ZjEW3+MOdnVDAwDgYD
# VR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCGcDWlFB9jotTnyvTxEtCe
# AMtxCJtZgDo6cRByLS96UplfubSf4kEKitg8IHr5MRUCMQCBy7n+glqPFr8Z9l2U
# f/t3aNEP146kEm34SZasEVFT5cVM+Witb6ScLy0R2j84c10wggOxMIIDN6ADAgEC
# AhBifJPq6WiWiiHSYYjwKX0PMAoGCCqGSM49BAMDMHgxCzAJBgNVBAYTAlVTMQ4w
# DAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENv
# cnAxNDAyBgNVBAMMK1NTTC5jb20gQ29kZSBTaWduaW5nIEludGVybWVkaWF0ZSBD
# QSBFQ0MgUjIwHhcNMjIwMTA3MTUzNzA5WhcNMjQwMTA3MTUzNzA5WjB3MQswCQYD
# VQQGEwJVUzESMBAGA1UECAwJVGVubmVzc2VlMRIwEAYDVQQHDAlOYXNodmlsbGUx
# HzAdBgNVBAoMFktpcmtwYXRyaWNrIFByaWNlIEluYy4xHzAdBgNVBAMMFktpcmtw
# YXRyaWNrIFByaWNlIEluYy4wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAShUzTZ8o6x
# Pks/PAdkxdR3P/hEDsde1MSpFi9frF20I04Hw6LmmWilPD3bg3A+WUqaV9wz2czc
# 07WIh0zD0oU6R6dxrr88kNMsuPsdO1Abn0jHJpP+EG3sBwISlUqcLZKjggGFMIIB
# gTAfBgNVHSMEGDAWgBQyeLEOkNtGzxrPtmMRbf4w52dUMDB5BggrBgEFBQcBAQRt
# MGswRwYIKwYBBQUHMAKGO2h0dHA6Ly9jZXJ0LnNzbC5jb20vU1NMY29tLVN1YkNB
# LWNvZGVTaWduaW5nLUVDQy0zODQtUjIuY2VyMCAGCCsGAQUFBzABhhRodHRwOi8v
# b2NzcHMuc3NsLmNvbTBRBgNVHSAESjBIMAgGBmeBDAEEATA8BgwrBgEEAYKpMAED
# AwEwLDAqBggrBgEFBQcCARYeaHR0cHM6Ly93d3cuc3NsLmNvbS9yZXBvc2l0b3J5
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMEwGA1UdHwRFMEMwQaA/oD2GO2h0dHA6Ly9j
# cmxzLnNzbC5jb20vU1NMY29tLVN1YkNBLWNvZGVTaWduaW5nLUVDQy0zODQtUjIu
# Y3JsMB0GA1UdDgQWBBRh8xDkEwFMtKqqWFgx4BXeisO2BDAOBgNVHQ8BAf8EBAMC
# B4AwCgYIKoZIzj0EAwMDaAAwZQIwK0EweI0P6gCqPWbL9bYwfm+EM3sJVw+LmqeR
# 5F2ZIiKltTZwEXVOhruYSkfeB2khAjEAzg7wyFP6/0hgOgveWYuXX8AHLJqcjJrB
# sLTCBe0qG2F2BnZYjFhNyfPTX6X5SxxuMIIFCTCCAvGgAwIBAgIIPyxgjFz5YyEw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAw
# DgYDVQQHDAdIb3VzdG9uMRgwFgYDVQQKDA9TU0wgQ29ycG9yYXRpb24xMTAvBgNV
# BAMMKFNTTC5jb20gUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBSU0EwHhcN
# MTkwMjE0MTgwNzA4WhcNMjcwMjEyMTgwNzA4WjB8MQswCQYDVQQGEwJVUzEOMAwG
# A1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jw
# b3JhdGlvbjExMC8GA1UEAwwoU1NMLmNvbSBSb290IENlcnRpZmljYXRpb24gQXV0
# aG9yaXR5IEVDQzB2MBAGByqGSM49AgEGBSuBBAAiA2IABEVuqVDEpiM2nl8ojRfL
# liJkP9x6jh3MCLOicSS6jkm5BBtHllirLZXI7Z4INcgn64mMU1jrYor+8FsPazFS
# Y0E7ic3s7LaNGdM0B9y7xgZ/wkWV7Mt/qCPgCemB+vNH06OCATswggE3MA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU3QQJB6L1en1SUxKSle44gCUNplkwgYMG
# CCsGAQUFBwEBBHcwdTBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5zc2wuY29tL3Jl
# cG9zaXRvcnkvU1NMY29tUm9vdENlcnRpZmljYXRpb25BdXRob3JpdHlSU0EuY3J0
# MCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcHMuc3NsLmNvbTARBgNVHSAECjAIMAYG
# BFUdIAAwOwYDVR0fBDQwMjAwoC6gLIYqaHR0cDovL2NybHMuc3NsLmNvbS9zc2wu
# Y29tLXJzYS1Sb290Q0EuY3JsMB0GA1UdDgQWBBSC0YVzMOc1BNOOApL75aTRxCHo
# zTAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggIBAPC4p7e2/AfR2M/1
# S1dX6tXCKBNJmezj60laF+VZgx6mWPUEIfVy5TPHGIjEQHucWLUrgvKpWhIqRqxA
# XAIYfLetsWMNHpZcbgvyMSc5ZnZgGJFpEMuaCGPpmTYNvg0KE+Sp3mExmC4jqeeb
# N2kFQnaF99rGxCKGwXy7s9wvpVM0jHqUYU75uN2Wlr0SF/cdPk/RnQDSQf97KXlI
# qXVCUnwu9oobgOl8ULITcDLYqtvbXrQb1lFrkjYQ6jIU7wNi2URiMPuwJ9MhKWS6
# Bt2CMUisnIVp2PZ5LkX1lBQdmNWmBg6wbgg3Ya2g8hPIwwyq850O7u9qrhAsjYkF
# JJVxlb0Mzvz675nLzzGzdklLY0GADaDLK5yuVoMcuijaUnKNQHnwTXrDiMZOgtTa
# 7+UNmBjA5VAwwN24wl5UgYw8plgnCIQyV4ltHNI0EyKX5NyOHtfT2MLelI4rqBsl
# eMIF065b1A7IQb/sgrSpq0dlCRMa8YGGmafxhWKTFABz0ES2MrXm3falKY/fp48T
# KNTnYU6QIMO6evNNXbxtM2gGVN+a9zIhGhfxg5Adv4gju/886VksL+4YrGZvTHB+
# EtHCD/jvKOslGAitujP0yQ3bCSgZbkyQS2eC1h8SyRIbOcb+8WsL0vXJkpz0eK3F
# VsEGdd3ECjAFazn5T00wP02aJxfaMYIBkDCCAYwCAQEwgYwweDELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhT
# U0wgQ29ycDE0MDIGA1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25pbmcgSW50ZXJtZWRp
# YXRlIENBIEVDQyBSMgIQYnyT6ulolooh0mGI8Cl9DzAJBgUrDgMCGgUAoHgwGAYK
# KwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIB
# BDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU
# pGLKrBsrFwNRfGrXyPz6h4i4mQwwCwYHKoZIzj0CAQUABGYwZAIwSqAG+Q5lul5V
# 1Jw8yHQQPdBn1dKYKs8ncOUNh0sqvR4CBkQTP7s9RYVlIj7azb4tAjADg27qXlOY
# 3tpcZmElFwII/L07kMUln4zldHuahvS1l2QiIvLDoduZ72WRMuCOHIw=
# SIG # End signature block
