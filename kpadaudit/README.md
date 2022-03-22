# kpadaudit.ps1

This script is used by KirkpatrickPrice auditors to collect information from Micosoft Active Directory.  Unlike many other tools out there, the approach used in this script is "keep it lite":
* Built on PowerShell modules that come directly from Microsoft as part of the RSAT AD Tools
* Minimal real-time analysis -- we collect data for off-line analysis and don't report findings during data collection.  This keeps the dependencies to a minimum and the logic simple, especially important for running the script on production machines.

## Critical dependencies ##
* Microsoft RSAT module for Active Directory, specifically the following commands
```
Get-ADForest
Get-ADDomain
Get-ADDomainController
Get-ADDefaultDomainPasswordPolicy
Get-ADFineGrainedPasswordPolicy
Get-ADUser
Get-ADDomain
Get-ADGroup
Get-ADGroupMember
Get-ADUserResultantPasswordPolicy
Get-GPO
```

NOTE: The `kpadaudit.ps1` script is signed with an Authenticode certificate to provide greater trust that the script has not been tampered with.  This should work with PowerShell execution policies of `RemoteSigned` and `AllSigned` for all version of Windows Server starting with 2012 and Windows 10.  Use `Get-AuthenticodeSignature ./kpadaudit.ps1` to verify the signature's validity.

Additionally, `git commits` are also signed and validated by GitHub.  Check the commit message to confirm that the commit is "verified."

## Installation
Installation is as simple as copying or cloning the PowerShell script to your system.

Git clone:

`git clone https://github.com/kirkpatrickprice/windows-audit-scripts`

or from PowerShell:
```
Invoke-WebRequest -uri https://raw.githubusercontent.com/kirkpatrickprice/windows-audit-scripts/main/kpadaudit/kpadaudit.ps1 -OutFile kpadaudit.ps1
unblock-file .\kpwinaudit.ps1
```

or click on the script and download the raw file (make sure to click on the "Raw" link or else you'll likely get HTML).

## Usage and Results
Launch a PowerShell window as Administrator and run:

`Get-AuthenticodeSignature ./kpadaudit.ps1`

to check the script's validity (if it reports the status as `HashMismatch` do not run the script and contact your auditor / only run it if it reports `Valid`)

`kpadaudit.ps1`

That's it.  The end result is a text file named `<desktop>\<domain_name>.txt`.  

In certain situations, the default location produces output errors or suffers severe performance problems.  This seems to be when the Desktop folder is itself synchronized through OneDrive or over a WAN link.  If this happens, you can use the `-OutPath` parameter to override the default folder.  The filename will be still be named after the domain name.

You can also use `Get-Help ./kpadaudit.ps1` (with the usual variations such as `-Detailed` or `-Examples` to obtain additional information.

Your auditor will ask you to upload all of the output files from the identified sample as a ZIP to the Online Audit Manager portal.
