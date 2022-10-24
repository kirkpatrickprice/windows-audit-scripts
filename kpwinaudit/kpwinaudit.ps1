<#
kpwinaudit.ps1
Developed and tested against Windows 10 and Windows 2012 and 2016 Server operating systems.
Change History
Version 0.3
 - Ground-up rewrite to introduce header, footer, invoke-mycommand, comment and other functions to increase consistency and readability of output
 - Favor built-in PowerShell functions and WMI data sources over console-based text commands (e.g. Get-BitLocker vs. manage-bde)
 - Emphasis on searching and processing output with per-line contextual information
Version 0.3.1
 - Fixed an issue with accurately reporting Windows Version information in System_OSInfo.  Thank you Gene Fry for pointing it out and providing the fix.
Version 0.3.2
 - Added "w32tm /query /configuration" as a second method to acquire time service settings
Version 0.3.3
  - Added better reporting for network listeners to include Windows process name
  - Replaced "start-transcript" method of capturing results to use "out-file" instead.  Allows for sending short
    status updates to console while sending full command results to the output file.
  - Renamed and moved "Software_InstalledSoftware" to "System_InstalledSoftware"
Version 0.3.4
  - Fixed typo in w32tm section
  - Added "KPWINVersion" to report file
Version 0.3.5
  - Removed "get-wmiobject" method from Users_LocalGroups and Users_LocalUserInfo sections to avoid a performance problem on member servers querying the domain controller for data
Version 0.4.0
  - Added Authenticode signature to PowerShell Script
Version 0.4.2
  - Added Outfile parameter to control where the output file is written to if the default doesn't work (e.g. if it's saved to a OneDrive folder)
  - Added help content compatible with Get-Help built-in Powershell command
  - Branching based on OS type to try to reduce some of the duplicate information
    - System_InstalledFeatures will only run on Server operating systems
  - Rewrote System_RDPEncryption to provide info on configured Security Layer (SSL vs RDP) in addition to the RDP Security setting
  - Set a default out-path width of 200 characters to control format-table truncation
  - Changed some command output to "Format-List" (over "Format-Table") for better display/readability
  - Added collection of logging samples in Logging_EventLogSamples
  - Users_LocalGroups and Users_LocalUsers will both prefer "Get-LocalUser/Group" cmdlets and fall back to Get-WmiObject if not available
  - Rewrote Logging_AuditEventsConfig to use AuditPol.exe instead of SecEdit.exe.  AuditPol is the source of truth compared to GPResult, SecEdit and other tools
        https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/auditpol-local-security-policy-results-differ
        https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/getting-the-effective-audit-policy-in-windows-7-and-2008-r2/ba-p/399010
  - Provided in-line comments to assist auditors and other reviewing the results
  - Renamed Time_NTPRegistry to Time_W32TimeRegistry to more accurately reflect Microsoft documentation.
  - Added option to start the W32Time service (or to prompt the user if they didn't specify if on the command line).  This greatly increases the quality of the 
    Time Service checks using the w32tm command.  The scripted prompt will assume "YES" in 30 seconds.
Version 0.4.3
  - System_BitLockerStatus: Added test to see if Get-BitLockerVolume command is present (e.g., not installed on some server versions)
  - Users_LocalAdministrator: Added test to see if Get-LocalUser command is presnet.  Fallback to Get-WmiObject if not.  
  - System_InstalledCapabilities: Added ttest to see if Get-WindowsCapability is present (e.g. not installed on some server versions)
  - Time_W32TimeLogs: Added alternate command for Windows 2012 servers
  - System_WindowsUpdateConfig: Improved collection of WU-related registry keys, including when using Configuration Service Providers such as Intune
Version 0.4.4
  - Add System_WindowsUpdateHistory to attempt to overcome limitations on Get-Hotfix PowerShell command.  https://docs.microsoft.com/en-us/answers/questions/191945/get-hotfix-not-returning-all-installed-kbs.html
  - Force all "out-file" commands to write ASCII text (not UTF-8, UTF-16, etc).  Will help with Analysis Toolkit processing and /hopefully/ avoid the need to convert
    files with the Linux "dos2unix" command prior to processing with Grep, Python, etc.
  - Collect IPSec Configurations in Networking_IPSecConfig
  - Collect File System Auditing settings (and other details) for critical OS folders and files (Logging_FSAuditing)
Version 0.4.5
  - Clarifications to support adv-searchfor.py
#>

<#
.SYNOPSIS
    A Windows PowerShell script that collects system configuraiton information for offline auditing
.DESCRIPTION
    This script is used by KirkpatrickPrice auditors to collect information from Windows hosts. Unlike many other tools out there, the approach used in this script is "keep it lite":

    - Use only commands that are already built into the operating system -- no installer, no custom libraries
    - Built on PowerShell versions that come standard with recent Windows operating systems
    - Minimal real-time analysis -- we collect data for off-line analysis and don't report findings during data collection. This keeps the dependencies to a minimum and the logic simple, especially important for running the script on production machines.

    Dependencies:
    - Windows PowerShell 5.1 for Windows 10 or Windows Server 2016
    - Windows PowerShell 4.0 for Windows Server 2012

    NOTE: This script is signed by KirkpatrickPrice using an Authenticode signature.  Use "Get-AuthenticodeSignature .\kpwinaudit.ps1" to confirm the validity of the signature.
.PARAMETER OutPath
    The path to use for the output file.  
    
    If not specified, the default is to place it on the user's Desktop, but this might not work well on OneDrive-synced folders.  You can override the default by specifying a path here.

    NOTE: A check is made to validate that the path exists and the script will terminate if it does not.  Use tab-completion to reduce path-not-found errors.

.PARAMETER StartW32Time
    Start the W32Time Service if it is disabled.
    
    On some system types, such as workstations, the W32Time service starts and stops as needed.  When the service is not running, important Time Synchronization settings will be missed.
    
    This setting allows the script to start the service if it's not running.  If not specified, the script will prompt the user to enable it where the default is "Yes" after 30 seconds.

    Starting the Time Service should have no effect on a running system, but the script will also stop the service again if it started it.

.EXAMPLE
    Default run without any parameters.  Output file goes to the users' desktop.  User will be prompted to enable Windows Time Service.
    
    ./kpwinaudit.ps1

.EXAMPLE
    Overriding the destination folder with -OutPath

    ./kpwinaudit.ps1 -OutPath .\

    This will put the output file in the current working folder.

.EXAMPLE
    Allow the script to start the W32Time Service.

    ./kpwinaudit.ps1 -StartTimeService

.LINK
    https://github.com/kirkpatrickprice/windows-audit-scripts

.NOTES
    Author: Randy Bartels
    Official location: https://github.com/kirkpatrickprice/windows-audit-scripts

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
    [string]$OutPath,
    [switch]$StartTimeService
)

Clear-Host

#Requires -RunAsAdministrator

$KPWINVERSION="0.4.4"
$hn = hostname.exe
#Width to use for the outfile / setting high to avoid line truncation "..."
$OutWidth=512

#Set up the output path.  If we specify the OutPath variable on the command line, use that.  Otherwise, use the desktop
#In both cases, check that the provided path is usable and throw an error if it's not.
if ( $OutPath.length -gt 0 ) {
    if ( Test-Path $OutPath ) {                                     #Check if the OutPath path exists
        if ( $OutPath.Substring($OutPath.Length-1) -eq "\") {       # Remove the last character if it's a back-slash "\"
            $OutPath=$OutPath.Remove($OutPath.Length -1)
        }
        $Outfile="$OutPath\$hn.txt"                                 #Build the $Outfile path
    } else {
        Write-Host "$Outpath does not exist.  Please verify your path."
        exit
    }
} else {
    if ( Test-Path "$home\Desktop" ) {
        $Outfile="$home\Desktop\$hn.txt"
    } else {
        Write-Host "Could not determine the users home directory.  Use kpwinaudit.ps1 -Outpath <path> to provide a path."
        exit
    }
}
write-host "Sending output to $Outfile"
#Remove the old file if it exists
if (Test-Path $Outfile) {
    Remove-Item -Path $Outfile  
}


function header {
  param (
    [string]$text
  )

  Process {
    write-host "Processing: $text" -ForegroundColor red
    "$text:: ###[BEGIN]" | Out-File -encoding ascii -FilePath $Outfile -Append -width $OutWidth

  }
}

function footer {
  param (
    [string]$text
  )
  Process {
    "$text:: ###[END]" | out-file -encoding ascii -FilePath $Outfile -Append -width $OutWidth
  }
}

function comment {
  param (
    [string]$text,
    [string]$section
  )

  Process {
    "$section:: ###$text" | out-file -encoding ascii -FilePath $Outfile -Append -width $OutWidth
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
        "$section:: ###Processing Command: $command" | out-file -encoding ascii -FilePath $Outfile -Append -width $OutWidth
        Invoke-Command -ScriptBlock $command -ErrorAction SilentlyContinue | Out-String -stream -Width $Outwidth | ForEach-Object {
            #Only print lines that have alpha/numeric/punction
            if ($_.Length -match "[A-Za-z0-9,.]") {
                "$section::$_" | out-file -encoding ascii -FilePath $Outfile -Append -width $OutWidth
            }
#            if ($error.count -gt $errorCount ) {
#                "$section:: Error processing command" | out-file -encoding ascii -FilePath $Outfile -Append -width $OutWidth
#                write-debug "$error"
#            }
        }
    }
}

function Get-WifiNetworks {
  #Code taken from https://www.fortypoundhead.com/showcontent.asp?artid=24189
  end {
   netsh wlan sh net mode=bssid | ForEach-Object -process {
     if ($_ -match '^SSID (\d+) : (.*)$') {
         $current = @{}
         $networks += $current
         $current.Index = $matches[1].trim()
         $current.SSID = $matches[2].trim()
     } else {
         if ($_ -match '^\s+(.*)\s+:\s+(.*)\s*$') {
             $current[$matches[1].trim()] = $matches[2].trim()
         }
     }
   } -begin { $networks = @() } -end { $networks| ForEach-Object { new-object psobject -property $_ } }
  }
 }

function Get-AuditLogConfigs {
  Process {
    $output = New-Object -TypeName "System.Collections.ArrayList"
    "Application", "Security", "System" | ForEach-Object {
      $output += Get-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$_"
    }
    $results = $output | Select-Object PrimaryModule, MaxSize, Retention, AutoBackupLogFiles, RestrictLogFiles, RestrictGuestAccess | format-table
  return $results
  }
}

function Get-NetworkListeners {
  # Function to pull netstat information along with PID and ProcessName in single-line format for easier analysis
  # Code taken from: https://lazywinadmin.com/2011/02/how-to-find-running-processes-and-their.html
  
  $properties = 'Protocol','LocalAddress','LocalPort'
  $properties += 'RemoteAddress','RemotePort','State','ProcessName','PID'

  netstat -ano |Select-String -Pattern '\s+(TCP|UDP)' | ForEach-Object {

    $item = $_.line.split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)

    if($item[1] -notmatch '^\[::') {
      if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') {
        $localAddress = $la.IPAddressToString
        $localPort = $item[1].split('\]:')[-1]
      } else {
        $localAddress = $item[1].split(':')[0]
        $localPort = $item[1].split(':')[-1]
      }

      if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') {
        $remoteAddress = $ra.IPAddressToString
        $remotePort = $item[2].split('\]:')[-1]
      } else {
        $remoteAddress = $item[2].split(':')[0]
        $remotePort = $item[2].split(':')[-1]
      }
    }

  New-Object PSObject -Property @{
    PID = $item[-1]
    ProcessName = (Get-Process -Id $item[-1] -ErrorAction SilentlyContinue).Name
    Protocol = $item[0]
    LocalAddress = $localAddress
    LocalPort = $localPort
    RemoteAddress =$remoteAddress
    RemotePort = $remotePort
    State = if($item[0] -eq 'tcp') {$item[3]} else {$null}
  } |Select-Object -Property $properties
  }
}

Function YesNoPrompt($prompt,$secondsToWait){ 
    # Function to provide the user with a time limit within which to provide a "No" response (just the N or n key will do).
    # Assumaes True unless the user provides an N within SecondsToWait seconds
    $ReturnVal=$True
    $count=0
    $sleepTimer=500                                     #in milliseconds / time to wait between cycles to check for a key press
    $WaitCycles=$secondsToWait*(1000/$sleeptimer)
    $NoKeyCaps="78"                                     #Cap N key
    $NoKeySmall="110"                                   #Small n key
    $YesKeyCaps="89"                                    #Cap Y key
    $YesKeySmall="121"                                  #Small y key
    $ResponseRecd=$false                                #Used for Loop control    
    while (($count -le $WaitCycles) -and ($ResponseRecd -ne $True)) {
        #write-host "$count (($count -le $WaitCycles) -or ($ResponseRecd -ne $True))"
        Write-Host -NoNewline "`r$($prompt) (Default Yes in $secondstowait seconds)  "
        Start-Sleep -m $sleepTimer
        if($host.UI.RawUI.KeyAvailable) {
            $key = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyUp")
            #Check if either of our keys were pressed
            switch ($key.VirtualKeyCode) {
                $NoKeyCaps {                    
                    $ReturnVal=$False
                    $ResponseRecd=$True
                    break
                }
                $YesKeyCaps {
                    $ReturnVal=$True
                    $ResponseRecd=$true
                    break
                }
                $NoKeySmall {                    
                    $ReturnVal=$False
                    $ResponseRecd=$True
                    break
                }
                $YesKeySmall {
                    $ReturnVal=$True
                    $ResponseRecd=$true
                    break
                }
                Default {
                    #if none of  our desired keys were preseed, clear the keyboard buffer
                    while ($host.ui.RawUI.KeyAvailable) {
                        $host.UI.RawUI.ReadKey() | Out-Null
                    }    
                }       #End Default
            }           #End switch
        }               #End if
        #Increase the counter
        $count++
        if ($count % (1000/$sleeptimer) -eq 0) {
            #If we've counted enough sleep cycles that we're on an even second
            $secondsToWait=$secondsToWait-1
        }               #End if
    }                   #End while
    return $ReturnVal
}                       #End function

$section="Script_Init"
    #Get the system type so we can run the correct versions of different commands
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

    comment -section $section -text "System type is detected as $systemtype."

    $WaitFor=30
    write-host

    if ($StartTimeService -eq $false) {
        $StartTimeService=YesNoPrompt -prompt "If not running, we will start the Windows Time Service (W32Time).  Press ""N/n"" to override." -secondstowait $WaitFor
    }

    if ($StartTimeService -eq $true) {
        comment -section "Script_Init" -text "If needed, KPWinAudit will start the W32Time Service"
    } else {
        comment -section "Script_Init" -text "KPWinAudit will NOT start the W32Time Service"
    }
footer -text $section



#Start-Transcript -path $home\Desktop\$hn.txt
Write-Host "
_  ___      _                _        _      _    ____       _                  
| |/ (_)_ __| | ___ __   __ _| |_ _ __(_) ___| | _|  _ \ _ __(_) ___ ___         
| ' /| | '__| |/ / '_ \ / _` | __| '__| |/ __| |/ / |_) | '__| |/ __/ _ \        
| . \| | |  |   <| |_) | (_| | |_| |  | | (__|   <|  __/| |  | | (_|  __/        
|_|\_\_|_|__|_|\_\ .__/ \__,_|\__|_|  |_|\___|_|\_\_|   |_|  |_|\___\___|        
\ \      / (_)_ _|_| __| | _____      _____     / \  _   _  __| (_) |_ ___  _ __ 
 \ \ /\ / /| | '_ \ / _` |/ _ \ \ /\ / / __|   / _ \| | | |/ _` | | __/ _ \| '__|
  \ V  V / | | | | | (_| | (_) \ V  V /\__ \  / ___ \ |_| | (_| | | || (_) | |   
   \_/\_/  |_|_| |_|\__,_|\___/ \_/\_/ |___/ /_/   \_\__,_|\__,_|_|\__\___/|_|   


  Version: $KPWINVERSION                                 
                                       ";

;

$section="DateTime"
    header -text $section
    $command={ Get-Date -Format g }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_PSDetails"
    header -text $section
    comment -section $section -text "Provide details on the PowerShell environment.  Mostly used for troubleshooting if something doesn't work."
    $command={ "KPWINVERSION: $KPWINVERSION" }
        Invoke-MyCommand -section $section -command $command
    $command={ $PSVersionTable }
        Invoke-MyCommand -section $section -command $command
    $command={ $home }
        Invoke-MyCommand -section $section -command $command
    $command={ $PSScriptRoot }
        Invoke-MyCommand -section $section -command $command

$section="System_Hostname"
    header -text $section
    comment -section $section -text "Capture the system's hostname.  This is also used to name the output file, but you have it here for backup if needed."
    $command={ $hn }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_OSInfo"
    header -text $section
    comment -section $section -text "Note: Use this information as the most accurate report of Windows version.  See Confluence for list of resources to map"
    comment -section $section -text "this info to which Updates have been installed and if the OS version is still supported."
    comment -section $section -text "Note: The first result provide an easy-to-search Windows version string (e.g. Windows 10 Pro 1909 18363.1082)."
    comment -section $section -text "Note: The second result provides the entire ""Current Version"" object from the registry."
    $command={ Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction silentlycontinue | Select-Object ProductName, ReleaseID, CurrentBuild, UBR | Format-List }
        Invoke-MyCommand -section $section -command $command
    $command={ Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction silentlycontinue | Select-Object * }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_BitLockerStatus"
    header -text $section
    comment -section $section -text "Capture the BitLocker status of each disk drive attached to the system.  This can be used to confirm statements such as 'All drives are encrypted with BitLocker.'"
    comment -section $section -text "Compare the results against the next section ('System_Disks') to see if any of the disks are Thumb Drives, FAT32, etc."
    #Test if the Get-BitLockerCommand is present.  If it is, run the test.  Otherwise, make a comment that we couldn't do it.
    try {
        if(Get-Command Get-BitLockerVolume -ErrorAction Stop) { 
            $command={ Get-BitLockerVolume | Select-Object MountPoint, EncryptionMethod, AutoUnlock*, KeyProtector, *Status, EncryptionPercentage | format-table -Autosize }
            Invoke-MyCommand -section $section -command $command
        }
    } catch {
        comment -section $section -text "Get-BitLockerVolume command not found.  Skipping test."
    }
footer -text $section

$section="System_Disks"
    header -text $section
    comment -section $section -text "Contextual information on all attached disk drives.  Useful to compare against System_BitLockerStatus results."
    $command={ get-disk -ErrorAction SilentlyContinue | format-table -AutoSize }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_GroupPolicyResults"
    header -text $section
    comment -section $section -text "This section includes a report for how Group Policy Objects have been applied.  It includes both USER and SYSTEM scopes and provides details on the specific policy items that have been applied."
    $command={ gpresult /z }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_InstalledCapabilities"
    header -text $section
    comment -section $section -text "Between System_InstalledCapabilities, System_InstalledFeatured, and System_InstalledSoftware, we collect a complete list of installed software -- from Microsoft and others."
    comment -section $section -text "Windows Capabilities include such things as an OpenSSH client, Notepad and Internet Explorer."
    try {
        if(Get-Command Get-WindowsCapability -ErrorAction Stop) { 
            $command={ Get-WindowsCapability -online | Where-Object {$_.State -ne 'NotPresent'} | format-table -autosize }
            Invoke-MyCommand -section $section -command $command
        }
    } catch {
        comment -section $section -text "Get-WindowsCapability command not found.  Skipping test."
    }
footer -text $section

$section="System_InstalledFeatures"
    header -text $section
    comment -section $section -text "Between System_InstalledCapabilities, System_InstalledFeatured, and System_InstalledSoftware, we collect a complete list of installed software -- from Microsoft and others."
    comment -section $section -text "Get-WindowsFeature is part of the Server Manager module for PowerShell and is therefore only relevant on Server operating systems."
    if ($systemtype.Contains("Server")) {
        $command={ Get-WindowsFeature -ErrorAction silentlycontinue | Where-Object {$_.InstallState -eq 'Installed'} | format-table -AutoSize }
    } else {
        $command={ "System is not a Server ($systemtype).  Get-WindowsFeatures was not run." }
    }
    Invoke-MyCommand -section $section -command $command

    comment -section $section -text "Between System_InstalledCapabilities, System_InstalledFeatured, and System_InstalledSoftware, we collect a complete list of installed software -- from Microsoft and others."
    comment -section $section -text "Get-WindowsOptionalFeature provides the list of Optional Features (see Apps & Features --> Optional Features)."
    $command={ Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq 'Enabled'} | format-table -Autosize }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_InstalledHotfixes"
    comment -section $section -text "This section provides a list of all hotfixes that have been installed.  Reviewing these results is a critical part of analyzing patch management practices."
    comment -section $section -text "Look at 'System_PendingWindowsUpdates' for a list of things that still need to be installed."
    comment -section $section -text "IMPORTANT NOTE: Get-HotFix is not 100% reliable.  Whether it reports on the HF action depends on the manner used to install the HF.  Notably, it does not capture"
    comment -section $section -text "all HFs installed by WindowsUpdate.  We will use two methods to gather HF info, hoping to improve the qualify of collected data."
    comment -section $section -text "The first method uses the PowerShell ""Get-Hotfix"" command.  The second queries the Windows Update Service directly."
    header -text $section
    $command={ Get-HotFix -ErrorAction silentlycontinue | Select-Object -Property Description, HotFixID, InstalledOn | Sort-Object -Descending -Property InstalledOn | Format-Table -AutoSize }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_WindowsUpdateHistory"
    header -text $section
    comment -section $section -text "This section collects all available Windows Update Service history.  This /should/ help with filling in the gaps where ""Get-Hotfix"" doesn't"
    comment -section $section -text "accurately report hotfix installation history (see note on System_InstalledHotfixes section)."
    comment -section $section -text "NOTE: This will grab /all/ Windows Update History, including for instance daily Defender updates.  That might be helpful as evidence that"
    comment -section $section -text "anti-virus tools are being updated daily.  Basically, if it was action taken by WUS, then it /should/ be in this log."
    
    #Setup a new Windows Update Session object
    $Session = New-Object -ComObject "Microsoft.Update.Session"
    $Searcher = $Session.CreateUpdateSearcher()
    $historyCount = $Searcher.GetTotalHistoryCount()
    #Search the WUS history and print the results
    $command={ $Searcher.QueryHistory(0, $historyCount) | Select-Object @{name="Operation"; expression={switch($_.operation){ 1 {"Installation"}; 2 {"Uninstallation"}; 3 {"Other"}}}}, Date, Title }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_InstalledSoftware"
    header -text $section
    comment -section $section -text "Between System_InstalledCapabilities, System_InstalledFeatured, and System_InstalledSoftware, we collect a complete list of installed software -- from Microsoft and others."
    comment -section $section -text "System_InstalledSoftware provides a list of all software installed including from 3rd party sources."
    comment -section $section -text "For 3rd party software, check each product to make sure that versions are reasonably maintained."

    $command={ Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction silentlycontinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | format-table -Autosize }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_PendingWindowsUpdates"
    header -text $section
    comment -section $section -text "System_PendingWindowsUpdates captures the results of an attempt to run Windows Update.  It will work identically to running the WU Control Panel, including using WSUS servers if configured."
    comment -section $section -text "This should be your go-to section for evaluating what MS-provided updates are waiting to be installed and has the same level of accuracy as running Windows Update."
    comment -section $section -text "If Internet connectivity is impaired and there is no WSUS server, this will fail."
    comment -section $section -text "Explanation of the fields is provided from https://docs.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdate"
    comment -section $section -text "     DeploymentChangeTime    Date when this item was made available as an update."
    comment -section $section -text "     AutoSelectOnWebSites    1 if this item is autoselected by WU to be installed."
    comment -section $section -text "     IsHidden                1 if this update has been hidden by the user."
    comment -section $section -text "     IsMandatory             1 if this update provides enhancements to the Windows Update Agent infrastructure."
    comment -section $section -text "This provides all available updates, even the ones that are optional or marked as driver updates that would only be installed if experiencing a problem."
    comment -section $section -text "It's probably best to focus on the AutoSelectOnWebsites field."

    # Create a Microsoft.Update.Session COM object" 
    $session1 = New-Object -ComObject Microsoft.Update.Session -ErrorAction silentlycontinue
    #Create an MS Update searcher
    $searcher = $session1.CreateUpdateSearcher()
    #Run the searcher for "Installed=0" and store the results in $result
    $result = $searcher.Search("IsInstalled=0")
    #Store the missing updates in $updates
    $updates = $result.Updates;
    $command={ "Found $($updates.Count) updates!" }
        Invoke-MyCommand -section $section -command $command
    #Print the results and interesting fields in a table
    $command={ $updates | Format-Table Title, LastDeploymentChangeTime, AutoSelectOnWebSites, IsHidden, IsMandatory -Autosize }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_RunningProcesses"
    header -text $section
    comment -section $section -text "A list of all of running processes on the system.  This is useful when looking for anti-virus, user programs and really anything else that's currently listed in the Task Manager."
    comment -section $section -text "NOTE: This is displayed in LIST format because PowerShell does some funny things when formatting this information as a table."
    $command={ Get-Process * | Select-Object ProcessName, Path, Company, Product, ID | Sort-Object Company, Product | Format-List }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_RDPEncryption"
    header -text $section
    comment -section $section -text "This section pulls together a couple of settings for how Windows handles TDP encryption."
    comment -section $section -text "First, we collect the GPO setting from the registry for the source of RDP's encryption.  Reference the ""Ensure 'Require use of specific security layer for RDP connections'"" CIS benchmark items."
    comment -section $section -text "     SecurityLayer = 0       Use RDP Security Layer (this is sub-par)"
    comment -section $section -text "     SecurityLayer = 1       Negotiate the security layer (not ideal)"     
    comment -section $section -text "     SecurityLayer = 2       Use SSL/TLS Security Layer (best)"
    comment -section $section -text "If the immediately following results are blank, then this GPO is not set, which results in ""Negotiate"" behavior."

    $command={ Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object SecurityLayer | Format-List }
        Invoke-MyCommand -section $section -command $command

    comment -section $section -text "When GPO is configured to ""RDP"" or when negotiated parameters result in using ""RDP Security Layer"", the next result provides the RDP Encryption setting."
    comment -section $section -text "  1 = Low"
    comment -section $section -text "  2 = Negotiated"
    comment -section $section -text "  3 = High"
    comment -section $section -text "RDP should not be used as the security layer (see above), but if it must be used, then only ""High Security"" should be used."

    $command={ Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction silentlycontinue | Select-Object MinEncryptionLevel | Format-List }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_RemoteAssistanceConfig"
    header -text $section 
    comment -section $section -text "Remote Assistance comes in two varieties -- Unsolicited (as in Help Desk-directred) and User-requested.  Both forms are disabled by default on both servers and workstations."
    comment -section $section -text "NOTE: **REMOTE ASSISTANCE SHOULD BE DISABLED** RESULTS SHOULD BE 0 or NON-EXISTANT"
    comment -section $section -text "Reference CIS Windows Server or Windows 10 Benchmarks section 18.8.36 for more information."
    comment -section $section -text "First, the policy configuration:"
    $section="System_RemoteAssistanceConfigPolicy"
    $command={ Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction silentlycontinue | Select-Object fAllowUnsolicited, fAllowToGetHelp | Format-List }
        Invoke-MyCommand -section $section -command $command
    $section="System_RemoteAssistanceConfigRunning"
    comment -section $section -text "The running configuration:"
    $command={ Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance\" -ErrorAction silentlycontinue | Select-Object fAllowUnsolicited, fAllowToGetHelp | Format-List }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_ScreensaverConfig"
    header -text $section
    comment -section $section -text "Using the screensaver is the most common way of locking the computer after inactivity.  Many audit standards (e.g. PCI) look for no more than 15 minutes (900 seconds), which seems reasonable."
    comment -section $section -text "There might be other methods of achieving this (such as through Power Settings), but these registry keys related to using GPO and to user-directed configurations respectively."
    comment -section $section -text "If these settings aren't conclusive or contradict what the customer says, you might need to dig in further."

    $section="System_ScreenSaverConfigGPO"
    comment -section $section -text "If this registry query comes back blank, GPO is not used to enforce screensaver settings"
    comment -section $section -text "     ScreenSaveActive        Is the screensaver enabled"
    comment -section $section -text "     ScreenSaverIsSecure     Requires a password to unlock the screensaver"
    comment -section $section -text "     ScreenSaverTimeOut      Inactivity period in seconds before the screensaver kicks in (900 seconds = 15 minutes)"
    $command={ Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ErrorAction silentlycontinue | Select-Object ScreenSaveActive, ScreenSaverIsSecure, ScreenSaveTimeOut | Format-List }
        Invoke-MyCommand -section $section -command $command

    $section="System_ScreenSaverConfigRunning"
    $command={ Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -ErrorAction silentlycontinue | Select-Object ScreenSaveActive, ScreenSaverIsSecure, ScreenSaveTimeOut | Format-List }
        Invoke-MyCommand -section $section -command $command
    comment -section $section -text "In addition to the settings described above in System_ScreenSaverConfigGPO:"
    comment -section $section -text "     ScreenSaverGracePeriod  The period of time after the screensaver activates where the user can cause movement to cancel the screen saver."
    comment -section $section -text "                             If the following results are blank, the default is 5 seconds"
    $command={ Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction silentlycontinue | Select-Object ScreenSaverGracePeriod | Format-List }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_ScheduledTaskInfo"
    header -text $section
    $command={ Get-ScheduledTask -ErrorAction silentlycontinue | where-object state -eq "ready" | Get-ScheduledTaskInfo | Select-Object Taskname, LastRunTime, LastTaskResult, NumberOfMissedRuns, NextRunTime | sort-object -property LastRunTime -desc | format-table -AutoSize }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_Services"
    header -text $section
    $command={ Get-Service | Select-Object DisplayName, Status, StartType | Sort-Object Status -desc |format-table -Autosize }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_SNMPConfig"
    header -text $section
    $command={ Get-Service snmp -ErrorAction silentlycontinue }
        Invoke-MyCommand -section $section -command $command
    comment -section $section -text "A blank PermittedManagers means that SNMP packets will be accepted from any source."
    $command={ Get-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" -ErrorAction silentlycontinue | Format-List }
        Invoke-MyCommand -section $section -command $command
    $command={ Get-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\RFC1156Agent" -ErrorAction silentlycontinue | Select-Object sysContact, SysLocation | Format-List }
        Invoke-MyCommand -section $section -command $command
    comment -section $section -text "Values for each listed community string are as follows:"
    comment -section $section -text "  16 - Read-Create"
    comment -section $section -text "  8 - Read-Write"
    comment -section $section -text "  4 - Read-Only"
    comment -section $section -text "  2 - Notify"
    comment -section $section -text "  1 - None"
    $command={ Get-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -ErrorAction silentlycontinue }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_WindowsUpdateConfig"
    header -text $section
    comment -section $section -text "Interpreting Windows Update settings from: http://techgenix.com/Registry-Keys-Tweaking-Windows-Update-Part1/"
    comment -section $section -text "WUServer will provide the update source if using WSUS.  If not set, WSUS is not being used to receive updates."
    $command={ Get-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\" -ErrorAction SilentlyContinue }
        Invoke-MyCommand -section $section -command $command
    comment -section $section -text "AUOptions key means the following"
    comment -section $section -text "  2 - Agent notifies user prior to downloading updates"
    comment -section $section -text "  3 - Automatic download with user notification prior to install"
    comment -section $section -text "  4 - Automatic download and install according to schedule (look for ScheduledInstallDay and ScheduledInstallTime keys)"
    comment -section $section -text "  5 - Automatic updates are required with some user configurability"
    comment -section $section -text "NoAutoUpdate=1 disables automatic updates altogether"
    comment -section $section -text "If the following registry paths are not found, then system updates are managed through another method (e.g. MDM)"
    $command={ Get-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue | format-list }
        Invoke-MyCommand -section $section -command $command
    comment -section $section -text "Here are some additional settings that might be useful, especially if the previous command didn't return any results"
    $command={ Get-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -ErrorAction SilentlyContinue | format-list }
        Invoke-MyCommand -section $section -command $command
    $command={ Get-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\AutoUpdate" -ErrorAction SilentlyContinue | format-list }
        Invoke-MyCommand -section $section -command $command
    comment -section $section -text "This registry section seems to be related to Intune MDM and maybe with other Configuration Service Providers"
    comment -section $section -text "See https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update for interpretation"
    $command={ Get-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update" -ErrorAction SilentlyContinue | format-list }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_ConnectivityTest"
    header -text $section
    $command={ ping www.google.com }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_IPInfo"
    header -text $section
    comment -section $section "IP Address information for each active (AddressState=Preferred) interface.  Compare this information against firewall/router configs and network diagrams."
    $command={ Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object {$_.AddressState -eq "Preferred"} | format-table -Autosize }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_DNSInfo"
    header -text $section
    comment -section $section "DNS information for all interfaces.  Use this to confirm that only trusted DNS servers are being used.  No 8.8.8.8 (Google) and similar."
    $command={ Get-DnsClientServerAddress  -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, Address | format-table -Autosize }
        Invoke-MyCommand -section $section -command $command     
footer -text $section 

$section="Networking_RoutingTable"
    header -text $section
    comment -section $section -text "Compare this information against firewall/router configs and network diagrams.  Especially take note of the default gateway (0.0.0.0/0) entry."
    $command={ Get-NetRoute | Select-Object DestinationPrefix,NextHop,InterfaceAlias | format-table -AutoSize }
        Invoke-MyCommand -section $section -command $command
footer -text $section


$section="Networking_LanmanServerConfig"
    header -text $section
    comment -section $section -text "LanManager is responsible for providing the SMB-based file sharing on Windows servers.  There are both ""SmbServer"" and ""SmbClient"" components."
    comment -section $section -text "   EnableSMBxProtocol              Enable/Disable specific version of the SMB protocol.  No specific recommendations."
    comment -section $section -text "   AutoDisconnectTimeout           SMB sessions will disconnect after (minutes).  Default is 15 which is also CIS recommendation."
    comment -section $section -text "   AutoShareServer/Workstation     Enable/disable the automatic shares.  Recommnedation is disabled."
    comment -section $section -text "   EnableSecuritySignature         Enable the use of signed SMB (does not require it, but permits it.  Recommendation and default is ""enabled""."
    comment -section $section -text "   NullSessionPipes/Shares         Shares and/or pipes that can be accessed through a null session.  Recommendation and default ""blank""."
    comment -section $section -text "   RequireSecuritySignature        Require the use of signed SMB.  Default is ""Disabled"", but recommendation is ""Enabled""."
    comment -section $section -text "   EnableInsecureGuestLogons       This setting disallows guest logons, which could be used directly or as a fall-back for access to network resources.  Recommnedation is Disabled."
    comment -section $section -text "                                   Reference CIS Windows 10 and Windows Server 2016 benchmarks and https://docs.microsoft.com/en-US/troubleshoot/windows-server/networking/guest-access-in-smb2-is-disabled-by-default"

    $command={ Get-SmbServerConfiguration | Select-Object EnableSMB*,AutoDisconnectTimeout,AutoShareServer,AutoShareWorkstation,EnableSecuritySignature,NullSessionPipes,NullSessionShare,RequireSecuritySignature | Format-List }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_LanmanClientConfig"
    header -text $section
    comment -section $section -text "See Networking_LanmanServerConfig for explation of settings"
    $command={ Get-SmbClientConfiguration | Select-Object EnableInsecureGuestLogons,EnableSecuritySignature,RequireSecuritySignature | Format-List }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_ListeningServices"
    header -text $section
    comment -section $section -text "Provide a list of all network listeners and the process that is listening on the port.  This is useful in a wide range of situations including:"
    comment -section $section -text "   - Comparing listening services against documented lists of ports, protocols and services"
    comment -section $section -text "   - Comparing against hardening documentation"
    comment -section $section -text "   - Determining if there are any insecure ports, protocols or services in use that require additional protections."
    $command={ Get-NetworkListeners | Where-Object { $_.state -eq "LISTENING" } | Format-Table -AutoSize }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_Shares"
    header -text $section
    $command={ Get-WMIObject -Query "SELECT * FROM Win32_Share" | format-table -Autosize }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_WLANNetworks"
    header -text $section
    $command={ Get-WifiNetworks | Select-Object Index, SSID, Signal, "Radio Type", Authentication | Sort-Object -property Signal -desc | Format-Table -AutoSize }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_WindowsFirewallStatus"
    header -text $section
    $command={ Get-NetFirewallProfile -ErrorAction silentlycontinue | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogFileName, LogAllowed, LogBlocked, LogIgnored | format-table -Autosize }
        Invoke-MyCommand -section $section -command $command
    $command={ netsh advfirewall show allprofiles state }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_WindowsFirewallRules"
    header -text $section
    $command={ Get-NetFirewallRule -ErrorAction silentlycontinue | Where-Object { $_.Enabled -eq 'True' } | Select-Object DisplayName, Profile, Enabled, Direction, Action, Mandatory, DisplayGroup | sort-object -property Direction | format-table -Autosize }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_IPSecConfig"
    header -text $section
    comment -section $section -text "Provide details of IPSec configuration.  Chances are, IPSec is not being used directly on endpoints, but just in case, we'll grab the config anyway."
    comment -section $section -text "Many of these commands may come back with now results, so if the line just after the ""Processing command"" goes straing to another comment, you'll know why."
    
    $IPSecList="Rule,MainModeRule,MainModeSA,MainModeCryptoSet,Phase1AuthSet,Phase2AuthSet,QuickModeCryptoSet,QuickModeSA"
    $IPSecList=$IPSecList.split(",")
    #MainModeSA and QuickModeSA require special handling as they don't have a "PolicyStore" option
    #Variable substitution inside of a ScriptBlock is a little wonky, so we're making a string first, then we'll convert it to a ScriptBlock
    foreach ($i in $IPSecList) {
        $command = $null
        if ($i -match 'SA$') {
            $commandStr= "Get-NetIPSec$i -ErrorAction silentlycontinue"
        } else {
            $commandstr="Get-NetIPSec$i -PolicyStore ActiveStore -ErrorAction silentlycontinue"
        }
        $section="Networking_IPSecConfig-$i"
        $command=[scriptblock]::Create($commandStr)
        Invoke-MyCommand -section $section -command $command
    }
    
    $section="Networking_IPSecConfig"
footer -text $section

$section="Time_W32TimeRegistry"
    header -text $section
    comment -section $section -text "Two approaches are used to pull time synchronization settings.  The first approach pulls settings directly from the registry."
    comment -section $section -text "The second approach (in the Time_W32TimeConfig section below) uses the w32tm command to pull active configurations."
    comment -section $section -text "Both sources should show similar information.  We may drop the registry method in the future."
    comment -section $section -text "Registry setting reference: https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings#reference-windows-time-service-registry-entries"
    comment -section $section -text "A few settings of particular note:"
    comment -section $section -text "   AnnounceFlags               Controls whether this computer is marked as a reliable time server. A computer is not marked as reliable unless it is also marked as a time server."
    comment -section $section -text "   ClockAdjustmentAuditLimit   Specifies the smallest local clock adjustments that may be logged to the W32time service event log on the target computer."
    comment -section $section -text "   EventLogFlags               Controls which events that the time service logs. 0x1 = Time jump.  0x2 = Source change"

    $section="Time_W32TimeRegistry-Config"
        $command={ Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -ErrorAction silentlycontinue }
            Invoke-MyCommand -section $section -command $command
    $section="Time_W32TimeRegistry-Parameters"
        $command={ Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -ErrorAction silentlycontinue }
            Invoke-MyCommand -section $section -command $command
    $section="Time_W32TimeRegistry-NtpClient"
        $command={ Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" -ErrorAction silentlycontinue }
            Invoke-MyCommand -section $section -command $command
    $section="Time_W32TimeRegistry-NtpServer"
        $command={ Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -ErrorAction silentlycontinue }
            Invoke-MyCommand -section $section -command $command
    $section="Time_W32TimeRegistry"
footer -text $section

$section="Time_ClockPermissions"
    header -text $section
    comment -section $section -text "This section identifies the users/groups that have permissions to manage the clock.  This is needed in PCI audits for requirement 10.4, but should be relevant in many other audits."
    comment -section $section -text "You'll need to match this up against the Users_LocalGroup and Users_LocalUsers sections to match the SIDs."
    secedit /export /cfg secedit.txt 2>&1 > $null
    $command={ Get-Content .\secedit.txt | select-string -pattern "^SeSystemtimePrivilege" }
        Invoke-MyCommand -section $section -command $command
    Remove-Item secedit.txt
footer -text $section


$section="Time_W32TimeConfig"
    header -text $section
    comment -section $section -text "Provides detailed information on the configuration of the Windows Time Service (W32Time)."
    comment -section $section -text "NOTE: For each of the ""TimeW32Time*"" checks, the ""w32tm"" command will complete successfully only if the W32Time service is running."
    comment -section $section -text "In  many situations, the Windows Time Service starts when needed and the stops.  For instance, Windows 10 desktop computers will produce"
    comment -section $section -text "sporadic results.  For servers, the service is more likely to be running especially if it's a domain controller or providing NTP to other systems."
    comment -section $section -text "Reference this page for additional information the output from the W32TM command: https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings"
    $TimeServiceStatus=Get-Service W32Time
    $ScriptStartedTimeService=$false
    if (($StartTimeService -eq $true ) -and ($TimeServiceStatus.status -ne "Running")) {
        $Count=1
        while (($TimeServiceStatus.Status -ne "Running") -and ($Count -le 6)) {
            Write-Host -NoNewline "`rStarting Windows Time Service (attempt $($count))"
            Start-Service W32Time
            $Count++
            Start-Sleep -seconds 15
            $TimeServiceStatus=Get-Service W32Time
        }
        write-host
        if ($TimeServiceStatus.Status -eq "Running") {
            write-host "Time Service successfully started."
            $ScriptStartedTimeService=$True
        }
    } else {
        write-host "No changes made to W32Time service."
    }
    if ($TimeServiceStatus.Status -eq "Running") {
        comment -section $section -text "Windows Time Service is running.  W32Tm results below are reliable."
    } else {
        comment -section $section -text "Windows Time Service is not running.  W32Tm results below are not reliable."
    }
    $command={ w32tm /query /configuration /verbose }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Time_W32TimePeers"
    header -text $section
    comment -section $section -text "Provides detailed information the time source that the system is using."
    comment -section $section -text "Only trusted, internal sources should be used for most devices."
    comment -section $section -text "These trusted time sources should query only trusted external time sources and should also peer with each other."
    $command={ w32tm /query /peers /verbose }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Time_W32TimeStatus"
    header -text $section
    comment -section $section -text "Provides detailed status on the time service.  You probably don't need this for most audits, but it's included if you need to get to the bottom of any time synch issues."
    $command={ w32tm /query /status }
        Invoke-MyCommand -section $section -command $command
    $command={ w32tm /query /source }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Time_W32TimeLogs"
    header -text $section
    comment -section $section -text "Provides logging samples (max 100 items) to use to audit that time sync settings and clock changes are audited."
    comment -section $section -text "Reference: https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-for-traceability"
    comment -section $section -text "NOTE:  As with harvesting all Windows Event Logs using other tools such as Splunk, the first step is to write the event to Event Log.  Harvesting tools will"
    comment -section $section -text "       collect events from there.  If the events aren't written to Event Log, they won't be harvested to centralized log management tools for archive/retention."
    switch -regex ($systemtype) {
        'Server20(16|19|22)|Windows10' {
            $command={ Get-WinEvent -LogName "Microsoft-Windows-Time-Service/Operational" -MaxEvents 100 -ErrorAction SilentlyContinue | format-table -Autosize }
        }
        'Server2012' {
            $command={ Get-EventLog -LogName "System" -Newest 50 -Source "Microsoft-Windows-Time-Service" -ErrorAction SilentlyContinue | format-table -AutoSize }
        }
        Default {
            comment -section $section -text "Unsupported OS detected.  Test skipped."
            $command={}
        }
    }
    Invoke-MyCommand -section $section -command $command
footer -text $section

#Disable the Windows Time Service if we started it.
if ($ScriptStartedTimeService -eq $true) {
    $TimeServiceStatus=Get-Service W32Time
    $Count=1
    while (($TimeServiceStatus.Status -ne "Stopped") -and ($Count -le 6)) {
        Write-Host -NoNewline "`rStopping Windows Time Service (attempt $($count))"
        Stop-Service W32Time
        $Count++
        Start-Sleep -seconds 15
        $TimeServiceStatus=Get-Service W32Time
    }
    write-host
    if ($TimeServiceStatus.Status -eq "Stopped") {
        write-host "Time Service successfully stopped."
    } else {
        write-host "Unable to stop Time Service."
    }
}

$section="Users_LocalAdministrator"
    header -text $section
    comment -section $section -text "Provide information on the local administrator.  We query for the user SID that ends in ""-500"" in case the default ""Administrator"" user has been renamed."
    try {
        if(Get-Command Get-LocalUser -ErrorAction Stop) { 
            comment -section $section -text "Running Get-LocalUser to get local Admin info."
            $command={ Get-LocalUser -ErrorAction SilentlyContinue | Select-Object * | Where-Object {$_.SID -like "S-1-5-*-500"} }
        }
    } catch {
        comment -section $section -text "Get-LocalUser command not found.  Running get-wmiobject to get local users."
        $command={ get-wmiobject -class Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue | Select-Object Name, FullName, Caption, PasswordChangeable, PasswordRequired, SID | Where-Object {$_.SID -like "S-1-5-*-500" } | format-list }
    }
    Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Users_LocalGroupAdministrators"
    #Using Net localgroup command to provide group membership for Administrators as "get-localgroupmember -Group Administrators" was not consistent during testing
    header -text $section
    comment -section $section -text "Provide information, including membership, of the local administrators group."
    $command={ net localgroup Administrators }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Users_LocalPasswordPolicy"
    header -text $section
    comment -section $section -text "Provides the local password policy in effect on the computer.  This should be consistent with any GPO settings in the System_GroupPolicyResults section at the top of the report."
    $command={ net accounts }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Users_LocalUsers"
    header -text $section
    comment -section $section -text "Provides a list of local (non-domain) users.  Use this info to audit local user accounts such as ""Administrator""."
    comment -section $section -text "SIDs are provided so that you can determine which user is referenced in the results of other tests (such as Time_ClockPermissions)."
    comment -section $section -text "Get-LocalUser is preferred, but is not supported on all versions of PowerShell.  If not supported, we fall back to Get-WmiObject."
    #If the version of PowerShell supports it, use Get-LocalUser.  Otherwise, use Get-WmiObject
    try {
        if(Get-Command Get-LocalUser -ErrorAction Stop) { 
            comment -section $section -text "Running Get-LocalUser to get local user list."
            $command={ Get-LocalUser -ErrorAction silentlycontinue | select-object name, Enabled, LastLogon, AccountExpires, UserMayChangePassword, PasswordExpires, PasswordLastSet, SID | format-table -Autosize }
        }
    } catch {
        comment -section $section -text "Get-LocalUser command not found.  Running get-wmiobject to get local users."
        $command={ get-wmiobject -class Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue | Select-Object Name, Disabled, Lockout, PasswordRequired, PasswordChangeable, PasswordExpires, SID | format-table -Autosize }
    }
    Invoke-MyCommand -section $section -command $command

footer -text $section

$section="Users_LocalGroups"
    header -text $section
    comment -section $section -text "Provides a list of local (non-domain) users.  Use this info to audit local user groups such as ""Administrator""."
    comment -section $section -text "SIDs are provided so that you can determine which group is referenced in the results of other tests (such as Time_ClockPermissions)."
    comment -section $section -text "Get-LocalGroup is preferred, but is not supported on all versions of PowerShell.  If not supported, we fall back to Get-WmiObject."
    #If the version of PowerShell in use supports get-localgroup, use that.  Otherwise, use get-wmiobject...
    try {
        if(Get-Command get-localgroup -ErrorAction Stop) { 
            comment -section $section -text "Running get-localgroup to get local user groups"
            $command={ Get-LocalGroup -ErrorAction silentlycontinue | select-object Name,SID,PrincipalSource,Description | format-table -Autosize }
        }
    } catch {
        comment -section $section -text "Get-LocalGroup command not found.  Running get-wmiobject to get local user groups."
        $command={ get-wmiobject -class Win32_Group -Filter "LocalAccount=True" -ErrorAction SilentlyContinue | Select-Object Name, SID, LocalAccount, Description | format-table -Autosize }
    }
    Invoke-MyCommand -section $section -command $command
footer -text $section

$section="AntiVirus_AVStatus"
    header -text $section
    comment -section $section -text "Antivirus in Use: **IF OUTPUT IS BLANK - NO ANTI VIRUS IS INSTALLED OR REQUIRES MANUAL CHECK** "
    comment -section $section -text "   If that happens, you might also review the running process list (System_RunningProcesses) to see if you can find the A/V binaries."
    comment -section $section -text "   This would at least provide that A/V is running, even if other details need to tested manually."
    comment -section $section -text "AVG Antivirus productState https://mspscripts.com/get-installed-antivirus-information-2/"
    comment -section $section -text "  262144 | Definitions = Up to date  | Status = Disabled"
    comment -section $section -text "  266240 | Definitions = Up to date  | Status = Enabled"
    comment -section $section -text "  262160 | Definitions = Out of date | Status = Disabled"
    comment -section $section -text "  266256 | Definitions = Out of date | Status = Enabled"
    comment -section $section -text "  393216 | Definitions = Up to date  | Status = Disabled"
    comment -section $section -text "  393232 | Definitions = Out of date | Status = Disabled"
    comment -section $section -text "  393488 | Definitions = Out of date | Status = Disabled"
    comment -section $section -text "  397312 | Definitions = Up to date  | Status = Enabled"
    comment -section $section -text "  397328 | Definitions = Out of date | Status = Enabled"
    comment -section $section -text "Windows Defender productState https://social.msdn.microsoft.com/Forums/en-US/6501b87e-dda4-4838-93c3-244daa355d7c/wmisecuritycenter2-productstate"
    comment -section $section -text "  393472 | Definitions = Up to date  | Status = Disabled"
    comment -section $section -text "  397584 | Definitions = Out of date | Status = Enabled"
    comment -section $section -text "  397568 | Definitions = Up to date  | Status = Enabled"
    comment -section $section -text "McAfee productState https://kc.mcafee.com/corporate/index?page=content&id=KB90221"
    comment -section $section -text "  ProductState=262144 = Up to Date Defs, On Access Scanning OFF"
    comment -section $section -text "  ProductState=266240 = Up to Date Defs, ON Access Scanning ON"
    comment -section $section -text "  ProductState=393216 = Up to Date Defs, On Access Scanning OFF"
    comment -section $section -text "  ProductState=397312 = Up to Date Defs, ON Access Scanning ON"
    comment -section $section -text " Other antivirus products will need to be researched"
    $command={ Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntivirusProduct" -ErrorAction silentlycontinue | Select-Object -property displayName, productState | Format-list }
        Invoke-MyCommand -section $section -command $command
    comment -section $section -text "The following is known to work at least with Windows Defender on Windows 10 and Server 2016.  As other AV products"
    comment -section $section -text "on other platforms were not available for testing, your mileage may vary."
    comment -section $section -text "Use this to determine if A/V is enabled for all types of protections and the update timestamps for various elements of the software."
    comment -section $section -text "If the results are blank, then the A/V product reports its health through another mechanism and you'll need to test it manually."
    comment -section $section -text "NOTE: The ProductState above and the ProductStatus below are two different items.  Interpretation of the ProductStatus below:"
    comment -section $section -text "   Windows Defender: https://docs.microsoft.com/en-us/graph/api/resources/intune-devices-windowsdefenderproductstatus.  A few codes of interest:"
    comment -section $section -text "       1       Service Not Running"
    comment -section $section -text "       32      AV Signature out of date."
    comment -section $section -text "       64      AS Signature out of date."
    comment -section $section -text "       4096    Product running in evaluation mode."
    comment -section $section -text "       8192    Product running in non-genuine Windows mode."
    comment -section $section -text "       16384   Product expired."
    comment -section $section -text "       524288  No status flags set (well-initialed state) NOTE: This is the desired state.  It means all is well."
    comment -section $section -text "       1048576 Platform is out of date."
    comment -section $section -text "       8388608 Signature or platform end of life is past or is impending."
    $command={ Get-WmiObject -namespace "root\Microsoft\SecurityClient" -query "SELECT * FROM AntimalwareHealthStatus" -ErrorAction silentlycontinue | Select-Object Name, *Version, *Enabled, *SignatureAge, *UpdateDateTime, Last*, ProductStatus, RealTimeScanDirection | Format-List }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Logging_AuditEventsConfig"
    header -text $section
    comment -section $section -text "Provides a detailed report of the events that will be captured by the local Windows Event Log service."
    comment -section $section -text "Reference: https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing-faq"
    $command={ auditpol.exe /get /category:"*" | format-list }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Logging_FSAuditing"
    header -text $section
    comment -section $section -text "This section collects auditing settings and other details for probably-important files and folders."
    comment -section $section -text "For instance, for a PCI audit, it's necessary to log all changes to ""System Level Objects"".  One way that might be manifested for an operating system"
    comment -section $section -text "is ""new files/folders in OS-sensitive areas of the file system -- C:\Windows for instance."

    $FilesList="C:\Windows,C:\Windows\System,C:\Windows\System32,C:\Windows\SystemApps,C:\Windows\SysWOW64,C:\Program Files,C:\Program Files (x86)"
    $FilesList=$FilesList.Split(",")
    foreach ($file in $FilesList) {
        $section="Logging_FSAuditing-$file"
        $command= { get-acl -Path $file -ErrorAction SilentlyContinue | format-list }
            Invoke-MyCommand -section $section -command $command
    }
    $section="Logging_FSAuditing"
footer -text $section

$section="Logging_AuditLogConfig"
    header -text $section
    comment -section $section -text "Provides registry settings for the application, system, and security Event Logs."
    comment -section $section -text "See https://docs.microsoft.com/en-us/windows/win32/eventlog/eventlog-key for details about what each item means."
    comment -section $section -text "NOTE: If log harvesting tools such as Splunk are used to collect Windows Event Logs in real-time, these settings don't carry as much importance."
    $command= { Get-AuditLogConfigs -ErrorAction SilentlyContinue }
        Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Logging_EventLogSamples"
    header -text $section
    comment -section $section -text "Provides samples of Windows Event Logs (50 newest events).  Use this to test that event logs are being actively written to the Windows Event Log system."
    comment -section $section -text "NOTE:  There are many tools that can collect the logs for centralized storage and analysis, but most -- if not all -- rely on the Event Log system in Windows."
    comment -section $section -text "       If Event Log doesn't have the event, then it's unlikely that Splunk, FluentD or other collection agents will have the event."
    comment -section $section -text "Event Logs captured include:"
    comment -section $section -text "   Application     Contains events logged by applications. For example, a database application might record a file error. The application developer decides which events to record."
    comment -section $section -text "   Security        Contains events such as valid and invalid logon attempts, as well as events related to resource use such as creating, opening, or deleting files or other objects."
    comment -section $section -text "   System 	        Contains events logged by system components, such as the failure of a driver or other system component to load during startup."
    
    $LogsList="Application,Security,System,Directory Service"
    $LogsList=$LogsList.split(",")
    foreach ($i in $LogsList) {
        $section="Logging_EventLogSamples"+$i -replace (" ","")
        $command= { Get-EventLog $i -Newest 50 -ErrorAction Stop | format-table -Autosize }
        try {
            Invoke-MyCommand -section $section -command $command
        } catch {
            #Remove the <SPACE>s from $i to make the output consistent
            $command={ "Log ""$i"" does not exist on this computer."}
        }
    }
    $section="Logging_EventLogSamples"
footer -text $section


#Stop-Transcript
# SIG # Begin signature block
# MIIOZwYJKoZIhvcNAQcCoIIOWDCCDlQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU2UmFFXbkJa9OAdBY2OvLf+Zx
# PB+gggw/MIIDeTCCAv6gAwIBAgIQHM+dZ83iGf8S2Zr/NoLlpzAKBggqhkjOPQQD
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
# VsEGdd3ECjAFazn5T00wP02aJxfaMYIBkjCCAY4CAQEwgYwweDELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhT
# U0wgQ29ycDE0MDIGA1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25pbmcgSW50ZXJtZWRp
# YXRlIENBIEVDQyBSMgIQYnyT6ulolooh0mGI8Cl9DzAJBgUrDgMCGgUAoHgwGAYK
# KwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIB
# BDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU
# bC/MXECgbRrxQEA/f4XJM0APy1EwCwYHKoZIzj0CAQUABGgwZgIxALegha/qN+7x
# S/Ws5ApxVUWS4vY0WCdvsuOgilaMSvAEZRkEXIq/h2pXVeDtufyThwIxAN7U9mfV
# rXoyTvcLbZOP9qWfWeJFMLQTL9JdB4eE+LdLlmhAwD0za1FEvttCie5xdQ==
# SIG # End signature block
