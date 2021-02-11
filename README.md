# windows-audit-scripts

This script is used by KirkpatrickPrice auditors to collect information from Windows hosts.  Unlike many other tools out there, the approach used in this script is "keep it lite":
* Use only commands that are already built into the operating system -- no installer, no custom libraries
* Built on PowerShell versions that comes standard with recent Windows operating systems
* Minimal real-time analysis -- we collect data for off-line analysis and don't report findings during data collection.  This keeps the dependencies to a minimum and the logic simple, especially important for running the script on production machines.

## Critical dependencies ##
* Windows PowerShell 5.1 for Windows 10 or Windows 2016 Server
* Windows PowerShell 4.0 for Windows 2012 Server

## Installation
Installation is as simple as copying or cloning the PowerShell script to your system.

Git clone:

`git clone https://github.com/kirkpatrickprice/windows-audit-script`

or from PowerShell:
```
Invoke-WebRequest -uri https://raw.githubusercontent.com/kirkpatrickprice/windows-audit-scripts/main/kpwinaudit.ps1 -OutFile kpwinaudit.ps1
Unblock-File .\kpwinaudit.ps1
```

or click on the script and download the raw file.

## Usage and Results
Launch a PowerShell windows as Administrator and run:

`kpwinaudit.ps1`

That's it.  There are no command line options.

The end result is a text file named `<desktop>\hostname.txt`.  Your auditor will ask you to upload all of the files from the identified sample as a ZIP to the Online Audit Manager portal.
