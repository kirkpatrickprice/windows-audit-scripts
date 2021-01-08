# windows-audit-scripts

This script is used by KirkpatrickPrice auditors to collect information from Windows hosts.  Unlike many other tools out there, the approach used in this script is "keep it lite":
* Use only commands that are already built into the operating system -- no installer, no custom libraries
* Built on PowerShell 5 that comes standards with recent Windows operating systems
* Minimal real-time analysis -- we collect data for off-line analysis and don't report findings during data collection.

## Critical dependencies ##
* Windows PowerShell 5.1 for Windows 10 or Windows 2016 Server
* Windows PowerShell 4.0 for Windows 2012 Server

## Installation
Installation is as simple as copying or cloning the bash script to your system.

`git clone https://github.com/kirkpatrickprice/windows-audit-script`

or click on the script and download the raw file.

## Usage and Results
Launch a PowerShell windows as Administrator and
`kpwinaudit.ps1`

That's it.  There are no command line options.

The end result is a text file named as `<desktop>\hostname.txt`.  Your auditor will ask you to upload all of the files from the identified sample as a ZIP to the Online Audit Manager portal.