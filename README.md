# windows-audit-scripts

The following scripts are part of the toolkit:

* [kpwinaudit.ps1](kpwinaudit/) - Meant to be run against a sample of Windows desktops and servers as selected by your auditor.  This script will produce one text file per system on which it's run.
* [kpadaudit.ps1](kpadaudit/) - Meant to be run against a Microsoft Active Directory environment.  This script will produce one text file per domain on which it's run.

See each tool's README file for additional details and instructions.

NOTE: All KirkpatrickPrice-provided auditing tools are signed with an Authenticode signature.  Be sure to run `Get-AuthenticodeSignature <toolname>.ps1` to validate that the code is KP-authentic.  Additionally, all `git commit`s are also signed.  Click on the commit message following any file to check that it is "Verified."