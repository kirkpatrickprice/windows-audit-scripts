# Summary of kpwinaudit.ps1 Checks

**kpwinaudit.ps1** is a PowerShell script designed for comprehensive Windows operating system auditing, tailored to support information security audits. The script performs read-only checks using built-in Windows commands and WMI queries, ensuring no changes are made to the system. Key areas covered include:

- **System Information:** OS version, BIOS details, hostname, and PowerShell environment.
- **Disk & Encryption:** Lists all attached disks and BitLocker encryption status.
- **Group Policy:** Reports applied Group Policy Objects for both user and system scopes.
- **Installed Software & Features:** Enumerates installed capabilities, features, hotfixes, and software.
- **Windows Update:** Collects update history and pending updates.
- **Network & Security:** Captures network listeners, Wi-Fi networks, IPSec configuration, and file system auditing settings.
- **User & Group Details:** Reports on local users, groups, and administrator accounts.
- **Logging & Audit:** Gathers event log configurations and audit policy settings.
- **Time Service:** Checks Windows Time Service status and configuration.

The script is safe for production environments, requiring no third-party installations. Output is written to a text file for offline analysis, supporting compliance and security review processes.

For further details, see the main [README.md](../README.md).
