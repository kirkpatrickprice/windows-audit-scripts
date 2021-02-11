<#
kpwinaudit.ps1
Version: 0.3.2
Authors: Mark Manousogianis and Randy Bartels
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
#>

Clear-Host

#Requires -RunAsAdministrator

$kpwinauditversion="0.3.4"
$hn = hostname
$osname = Get-CimInstance Win32_OperatingSystem -ErrorAction silentlycontinue | Select-Object Caption
if ($osname -contains "Server") {
  $systemtype="Server"
} else {
  $systemtype="Desktop"
}
$outfile="$home\Desktop\$hn.txt"
write-host "Sending output to $outfile"
Remove-Item -Path $outfile  

function header {
  param (
    [string]$text
  )

  Process {
    write-host "Processing: $text" -ForegroundColor red
    "$text:: ###[BEGIN]" | Out-File -FilePath $outfile -Append

  }
}

function footer {
  param (
    [string]$text
  )
  Process {
    "$text:: ###[END]" | Out-File -FilePath $outfile -Append
  }
}

function comment {
  param (
    [string]$text,
    [string]$section
  )

  Process {
    "$section:: ###$text" | Out-File -FilePath $outfile -Append
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
    "$section:: ###Processing Command: $command" | Out-File -FilePath $outfile -Append
    Invoke-Command -ScriptBlock $command -ErrorAction SilentlyContinue | Out-String -stream | ForEach-Object {
      "$section:: $_" | Out-File -FilePath $outfile -Append 
      if ($error.count -gt $errorCount ) {
        "$section:: Error processing command" | Out-File -FilePath $outfile -Append
        write-debug "$error"
      }
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

Function Get-ListeningTCPConnections { 
  #Deprecating this code in favor of Get-NetworkListeners which also provides the PID and ProcessName
  #Code from https://techibee.com/powershell/query-list-of-listening-ports-in-windows-using-powershell/2344           
  [cmdletbinding()]            
  param(            
  )            
              
  try {            
      $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()            
      $Connections = $TCPProperties.GetActiveTcpListeners()            
      foreach($Connection in $Connections) {            
          if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }            
                      
          $OutputObj = New-Object -TypeName PSobject            
          $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalAddress" -Value $connection.Address            
          $OutputObj | Add-Member -MemberType NoteProperty -Name "ListeningPort" -Value $Connection.Port            
          $OutputObj | Add-Member -MemberType NoteProperty -Name "IPV4Or6" -Value $IPType            
          $OutputObj            
      }            
              
  } catch {            
      Write-Error "Failed to get listening connections. $_"            
  }           
}

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


  Version: $kpwinauditversion                                 
                                       ";

;

$section="DateTime"
  header -text $section
  $command={ Get-Date -Format g }
  	Invoke-MyCommand -section $section -command $command -commandroot $commandroot
footer -text $section

$section="System_PSDetails"
  header -text $section
  $command={ "KPWinAudit Version: $kpwinauditversion" }
  	Invoke-MyCommand -section $section -command $command -commandroot $commandroot
  $command={ $PSVersionTable }
  	Invoke-MyCommand -section $section -command $command -commandroot $commandroot
  $command={ $home }
    Invoke-MyCommand -section $section -command $command -commandroot $commandroot
  $command={ $PSScriptRoot }
  	Invoke-MyCommand -section $section -command $command -commandroot $commandroot

$section="System_Hostname"
  header -text $section
  $command={ $hn }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_BitLockerStatus"
  header -text $section
  $command={ Get-BitLockerVolume | Select-Object MountPoint, EncryptionMethod, AutoUnlock*, KeyProtector, *Status, EncryptionPercentage | Format-Table }
    Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_Disks"
  header -text $section
  $command={ get-disk -ErrorAction SilentlyContinue }
    Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_GroupPolicyResults"
  header -text $section
  $command={ gpresult /z }
    Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_InstalledCapabilities"
  header -text $section
  $command={ Get-WindowsCapability -online | Where-Object {$_.State -ne 'NotPresent'} | format-table }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_InstalledFeatures"
  header -text $section
  if ($systemtype -eq "Server") {
    $command={ Get-WindowsFeature -ErrorAction silentlycontinue | Where-Object {$_.InstallState -eq 'Installed'} }
    	Invoke-MyCommand -section $section -command $command
  }
  $command={ Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq 'Enabled'} | Format-Table }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_InstalledHotfixes"
  header -text $section
  $command={ Get-HotFix -ErrorAction silentlycontinue | Select-Object -Property Description, HotFixID, InstalledOn | Sort-Object -Descending -Property InstalledOn | Format-Table -AutoSize }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_InstalledSoftware"
  header -text $section
  $command={ Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction silentlycontinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_RunningProcesses"
  header -text $section
  $command={ Get-Process * | Select-Object ProcessName, Path, Company, Product, ID | Sort-Object Company, Product | Format-Table -AutoSize }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_OSInfo"
  header -text $section
  comment -section $section -text " Note: Use this information as the most accurate report of Windows version"
  comment -section $section -text " Note: The first result provide an easy-to-search Windows version string (e.g. Windows 10 Pro 1909 18363.1082)."
  comment -section $section -text " Note: The second result provides the entire ""Current Version"" object from the registry."
  $command={ Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction silentlycontinue | Select-Object ProductName, ReleaseID, CurrentBuild, UBR | Format-Table }
  	Invoke-MyCommand -section $section -command $command
  $command={ Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction silentlycontinue | Select-Object * }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_PendingWindowsUpdates"
  header -text $section
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
      $command={ $updates | Format-Table Title, LastDeploymentChangeTime, AutoSelectOnWebSites, IsDownloaded, IsHidden, IsInstalled, IsMandatory, IsPresent, AutoSelection, AutoDownload -AutoSize }
      	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_RDPEncryption"
  header -text $section
  comment -section $section -text "  1 = Low"
  comment -section $section -text "  2 = Negotiated"
  comment -section $section -text "  3 = High"
  $command={ Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction silentlycontinue | Select-Object MinEncryptionLevel | Format-Table -AutoSize }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_RemoteAssistanceConfig"
  header -text $section
  comment -section $section -text " Note: **REMOTE ASSISTANCE SHOULD BE DISABLED** RESULT SHOULD BE 0"
  $command={ Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance\" -ErrorAction silentlycontinue | Select-Object fAllowToGetHelp | Format-Table -AutoSize }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_ScreensaverConfig"
  header -text $section
  comment -section $section -text " This might not be the authoritative source of screensaver settings depending on MDM platforms that might be in use"
  $command={ Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -ErrorAction silentlycontinue | Select-Object ScreenSaveActive, ScreenSaverIsSecure, ScreenSaveTimeOut | Format-Table -AutoSize }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_ScheduledTaskInfo"
  header -text $section
  $command={ Get-ScheduledTask -ErrorAction silentlycontinue | where-object state -eq "ready" | Get-ScheduledTaskInfo | Select-Object Taskname, LastRunTime, LastTaskResult, NumberOfMissedRuns, NextRunTime | sort-object -property LastRunTime -desc | format-table -AutoSize }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="System_Services"
  header -text $section
  $command={ Get-Service | Select-Object DisplayName, Status, StartType | Sort-Object Status -desc |format-table }
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
  $command={ Get-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue }
    Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_ConnectivityTest"
  header -text $section
  $command={ ping www.google.com }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_IPInfo"
  header -text $section
  $command={ ipconfig /all }
  	Invoke-MyCommand -section $section -command $command
footer -text $section 

$section="Networking_LanManConfig"
  header -text $section
  $command={ Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" | Select-Object autodisconnect, enable*, require*, *nullsession* | Format-List }
    Invoke-MyCommand -section $section -command $command
  $command={ Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" | Select-Object Enable*, RequireSecuritySignature | Format-List }
    Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_ListeningServices"
  header -text $section
  #Deprecating Get-ListeningTCPConnections in favor of Get-NetworkListeners for more favorable output
  #$command={ Get-ListeningTCPConnections }
  $command={ Get-NetworkListeners | Where-Object { $_.state -eq "LISTENING" } | Format-Table }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_RoutingTable"
  header -text $section
  $command={ route print }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_Shares"
  header -text $section
  $command={ Get-WMIObject -Query "SELECT * FROM Win32_Share" | Format-Table }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_WLANNetworks"
  header -text $section
  $command={ Get-WifiNetworks | Select-Object Index, SSID, Signal, "Radio Type", Authentication | Sort-Object -property Signal -desc | Format-Table -AutoSize }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_WindowsFirewallStatus"
  header -text $section
  $command={ Get-NetFirewallProfile -ErrorAction silentlycontinue | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogFileName, LogAllowed, LogBlocked, LogIgnored | Format-Table }
  	Invoke-MyCommand -section $section -command $command
  $command={ netsh advfirewall show allprofiles state }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Networking_WindowsFirewallRules"
  header -text $section
  $command={ Get-NetFirewallRule -ErrorAction silentlycontinue | Where-Object { $_.Enabled -eq 'True' } | Select-Object DisplayName, Profile, Enabled, Direction, Action, Mandatory, DisplayGroup | sort-object -property Direction | Format-Table }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Time_NTPRegistry"
  header -text $section
  comment -section $section -text "Two approaches are used to pull time synchronization settings.  The first approach pulls settings directly from the registry."
  comment -section $section -text "The second approach (in the Time_W32TimeConfig section below) uses the w32tm command to pull active configurations."
  comment -section $section -text "Both sources should show similar information.  We may drop the registry method in the future."
  comment -section $section -text "Registry setting reference: https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings#reference-windows-time-service-registry-entries"
  $command={ Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -ErrorAction silentlycontinue }
  	Invoke-MyCommand -section $section -command $command
  $command={ Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -ErrorAction silentlycontinue }
  	Invoke-MyCommand -section $section -command $command
  $command={ Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" -ErrorAction silentlycontinue }
  	Invoke-MyCommand -section $section -command $command
  $command={ Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -ErrorAction silentlycontinue }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Time_W32TimeConfig"
  header -text $section
  $command={ w32tm /query /configuration /verbose }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Time_W32TimePeers"
  header -text $section
  $command={ w32tm /query /peers /verbose }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Time_W32TimeStatus"
  header -text $section
  $command={ w32tm /query /status }
  	Invoke-MyCommand -section $section -command $command
  $command={ w32tm /query /source }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Users_LocalAdministrator"
  header -text $section
  $command={ net user administrator }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Users_LocalGroups"
  header -text $section
  $command={ Get-LocalGroup -ErrorAction silentlycontinue | Format-Table -AutoSize }
    Invoke-MyCommand -section $section -command $command
  comment -section $section -text "Using WMIObject and Get-LocalUser methods for different OS versions.  If run on a more recent OS, this will display"
  comment -section $section -text "duplicate information to the previous command."
  $command={ get-wmiobject -class Win32_Group | Select-Object Name, LocalAccount, Domain, Description | Format-Table -AutoSize }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Users_LocalGroupAdministrators"
#Using Net localgroup command to provide group membership for Administrators as "get-localgroupmember -Group Administrators" was not consistent during testing
  header -text $section
  $command={ net localgroup Administrators }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Users_LocalPasswordPolicy"
  header -text $section
  $command={ net accounts }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Users_LocalUserInfo"
  header -text $section
  comment -section $section -text "Using WMIObject and Get-LocalUser methods for different OS versions.  If run on a more recent OS, this will display"
  comment -section $section -text "duplicate information to the previous command."
  $command={ Get-WmiObject -Class Win32_UserAccount -ErrorAction silentlycontinue | Select-Object PSComputername, Name, Status, Disabled, LastLogin, MinPasswordLength, MaxPasswordAge, MinPasswordAge, MaxBadPasswordsAllowed, AccountType, Lockout, PasswordRequired, PasswordChangeable | format-table -AutoSize }
  	Invoke-MyCommand -section $section -command $command
  $command={ Get-Localuser -ErrorAction silentlycontinue | Select-Object name, Fullname, Enabled, LastLogon, UserMayChangePassword, PasswordExpires, PasswordLastSet | Format-Table }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

$section="AntiVirus_AVStatus"
  header -text $section
  comment -section $section -text " Antivirus in Use: **IF OUTPUT IS BLANK - NO ANTI VIRUS IS INSTALLED / REQUIRES MANUAL CHECK** "
  comment -section $section -text " AVG Antivirus productState https://mspscripts.com/get-installed-antivirus-information-2/"
  comment -section $section -text "  262144 | Definitions = Up to date  | Status = Disabled"
  comment -section $section -text "  266240 | Definitions = Up to date  | Status = Enabled"
  comment -section $section -text "  262160 | Definitions = Out of date | Status = Disabled"
  comment -section $section -text "  266256 | Definitions = Out of date | Status = Enabled"
  comment -section $section -text "  393216 | Definitions = Up to date  | Status = Disabled"
  comment -section $section -text "  393232 | Definitions = Out of date | Status = Disabled"
  comment -section $section -text "  393488 | Definitions = Out of date | Status = Disabled"
  comment -section $section -text "  397312 | Definitions = Up to date  | Status = Enabled"
  comment -section $section -text "  397328 | Definitions = Out of date | Status = Enabled"
  comment -section $section -text " Windows Defender productState https://social.msdn.microsoft.com/Forums/en-US/6501b87e-dda4-4838-93c3-244daa355d7c/wmisecuritycenter2-productstate"
  comment -section $section -text "  393472 | Definitions = Up to date  | Status = Disabled"
  comment -section $section -text "  397584 | Definitions = Out of date | Status = Enabled"
  comment -section $section -text "  397568 | Definitions = Up to date  | Status = Enabled"
  comment -section $section -text " McAfee productState https://kc.mcafee.com/corporate/index?page=content&id=KB90221"
  comment -section $section -text "  ProductState=262144 = Up to Date Defs, On Access Scanning OFF"
  comment -section $section -text "  ProductState=266240 = Up to Date Defs, ON Access Scanning ON"
  comment -section $section -text "  ProductState=393216 = Up to Date Defs, On Access Scanning OFF"
  comment -section $section -text "  ProductState=397312 = Up to Date Defs, ON Access Scanning ON"
  comment -section $section -text " Other antivirus products will need to be researched"
  $command={ Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntivirusProduct" -ErrorAction silentlycontinue | Select-Object -property displayName, productState | Format-table -AutoSize }
    Invoke-MyCommand -section $section -command $command
  comment -section $section -text "The following is known to work at least with Windows Defender on Windows 10 and Server 2016.  As other AV products"
  comment -section $section -text "on other platforms were not available for testing, your mileage may vary."
  $command={ Get-WmiObject -namespace "root\Microsoft\SecurityClient" -query "SELECT * FROM AntimalwareHealthStatus" -ErrorAction silentlycontinue | Select-Object Name, *Version, *Enabled, *SignatureAge, *UpdateDateTime, Last*, ProductStatus, RealTimeScanDirection | Format-List }
    Invoke-MyCommand -section $section -command $command
footer -text $section

$section="Logging_AuditEventsConfig"
  header -text $section
  comment -section $section -text "Note: These values should be set to 3 if they are not being captured by an out of band process."
  comment -section $section -text "   3= Success and Failure"
  comment -section $section -text "   2= Failure"
  comment -section $section -text "   1= Success"
  secedit /export /cfg secedit.txt 2>&1 > $null
  $command={ Get-Content .\secedit.txt | select-string -pattern "^Audit.*" }
  	Invoke-MyCommand -section $section -command $command
  Remove-Item secedit.txt
footer -text $section

$section="Logging_AuditLogConfig"
  header -text $section
  $command= { Get-AuditLogConfigs }
  	Invoke-MyCommand -section $section -command $command
footer -text $section

#Stop-Transcript