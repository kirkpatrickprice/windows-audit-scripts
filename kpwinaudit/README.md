# kpwinaudit.ps1

This script is used by KirkpatrickPrice auditors to collect information from Windows hosts.  Unlike many other tools out there, the approach used in this script is "keep it lite":
* Use only commands that are already built into the operating system -- no installer, no custom libraries
* Built on PowerShell versions that come standard with recent Windows operating systems
* Minimal real-time analysis -- we collect data for off-line analysis and don't report findings during data collection.  This keeps the dependencies to a minimum and the logic simple, especially important for running the script on production machines.

## Critical dependencies ##
* Windows PowerShell 5.1 for Windows 10 or Windows 2016 Server
* Windows PowerShell 4.0 for Windows 2012 Server

NOTE: As of version 0.4.0, the `kpwinaudit.ps1` script is signed with an Authenticode certificate to provide greater trust that the script has not been tampered with.  This should work with PowerShell execution policies of `RemoteSigned` and `AllSigned` for all version of Windows Server starting with 2012 and Windows 10.  Use `Get-AuthenticodeSignature ./kpwinaudit.ps1` to verify the signature's validity.

Additionally, `git commits` are also signed and validated by GitHub.  Check the commit message to confirm that the commit is "verified."

## Installation
Installation is as simple as copying or cloning the PowerShell script to your system.

Git clone:

`git clone https://github.com/kirkpatrickprice/windows-audit-script`

or from PowerShell:
```
Invoke-WebRequest -uri https://raw.githubusercontent.com/kirkpatrickprice/windows-audit-scripts/main/kpwinaudit/kpwinaudit.ps1 -OutFile kpwinaudit.ps1
Get-AuthenticodeSignature .\kpwinaudit.ps1
unblock-file ./kpwinaudit.ps1
```

or click on the script and download the raw file (make sure to click on the "Raw" link or else you'll likely get HTML).

## Usage and Results
Launch a PowerShell window as Administrator and run:

`Get-AuthenticodeSignature .\kpwinaudit.ps1`

to check the script's validity (if it reports the status as `HashMismatch` do not run the script and contact your auditor / only run it if it reports `Valid`)

`kpwinaudit.ps1`

That's it.  The end result is a text file named `<desktop>\hostname.txt`.  

In certain situations, the default location produces output errors.  This seems to be when the Desktop folder is itself synchronized through OneDrive.  If this happens, you can use the `-OutPath` parameter to override the default folder.  The filename will be still be named after the host's name.

The Windows Time Service (`W32Time`) is needed for some of the time synchronization settings, but it is not guaranteed to be running.  This is especially the case on Windows 10 desktops, but might be the case for member servers as well.  There is a parameter `StartTimeService` that will allow the script to start the service if it's not running.  If this parameter is not set, we will also prompt the user if it's OK to start the service.  This defaults to "Yes - it is OK" after 30 seconds.  If the script started the service, then it will also stop it when it is no longer needed.  If we didn't start it, or if it was overridden when prompted, then we leave it alone.

You can also use `Get-Help ./kpwinaudit.ps1` (with the usual variations such as `-Detailed` or `-Examples` to obtain additional information.

Your auditor will ask you to upload all of the output files from the identified sample as a ZIP to the Online Audit Manager portal.
