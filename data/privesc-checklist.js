/**
 * Static privilege-escalation enumeration checklist — reference only,
 * assumes an authorized low-privilege foothold already exists (CTF or
 * pentest lab context). No command here is executed by this toolkit;
 * these are commands for YOU to run on a box YOU are authorized to test.
 */

export const PRIVESC_CHECKLIST = {
  linux: [
    { command: 'sudo -l', reveals: 'Which commands the current user can run as another user/root via sudo, and under what constraints.', why: 'A NOPASSWD entry or a GTFOBins-listed binary in this list is often an instant path to root.' },
    { command: 'find / -perm -4000 -type f 2>/dev/null', reveals: 'All SUID binaries on the filesystem (run with the file owner\'s privileges, usually root).', why: 'A non-standard or misconfigured SUID binary (check it against GTFOBins) can often be abused to spawn a root shell.' },
    { command: 'find / -perm -2000 -type f 2>/dev/null', reveals: 'All SGID binaries.', why: 'Same idea as SUID, but for group privileges — can grant membership in a privileged group (e.g. docker, disk).' },
    { command: 'id; groups', reveals: 'Current user\'s UID/GID and all group memberships.', why: 'Membership in groups like docker, disk, lxd, or adm is a well-known, direct route to root.' },
    { command: 'uname -a; cat /etc/os-release', reveals: 'Kernel version and distribution.', why: 'Lets you match the box against known local kernel-exploit CVEs (check against searchsploit/GTFOBins/exploit-db before using).' },
    { command: 'cat /etc/crontab; ls -la /etc/cron.*; crontab -l', reveals: 'Scheduled jobs and their owning user.', why: 'A root-owned cron job that executes a world-writable script is a classic escalation path — edit the script, wait for the timer.' },
    { command: 'ps aux | grep root', reveals: 'Processes currently running as root.', why: 'A root process reading from a location you can write to (config, plugin dir, log path) can be hijacked.' },
    { command: 'cat /etc/passwd', reveals: 'All local user accounts and their default shells.', why: 'Confirms which accounts are real login accounts and worth targeting further, and sometimes reveals service accounts with weak configuration.' },
    { command: 'find / -writable -type d 2>/dev/null | grep -v proc', reveals: 'World- or group-writable directories.', why: 'A writable directory in root\'s PATH, a systemd unit directory, or a cron script location is a common escalation vector.' },
    { command: 'getcap -r / 2>/dev/null', reveals: 'Linux capabilities assigned to binaries (e.g. cap_setuid).', why: 'A binary with cap_setuid+ep or similar can be abused the same way a SUID binary would be, and is easy to miss without this check.' },
    { command: 'cat /etc/fstab; mount', reveals: 'Mounted filesystems and mount options.', why: 'A filesystem mounted with a permissive option, or an NFS share with no_root_squash, can be an escalation route.' },
    { command: 'history; cat ~/.bash_history', reveals: 'Recently run commands.', why: 'Frequently contains plaintext credentials, internal hostnames, or hints about how the box is administered.' },
    { command: 'grep -ri password /etc /opt /var/www 2>/dev/null', reveals: 'Plaintext credentials accidentally left in config files.', why: 'Config files, .env files, and deployment scripts are a common place to find a reusable password or API key.' },
    { command: 'linpeas.sh / linenum.sh (run manually, not bundled here)', reveals: 'An automated sweep of everything above plus dozens more checks.', why: 'Widely-used public enumeration scripts (not shipped with this toolkit) that speed up the manual checklist once you understand what they check for.' }
  ],
  windows: [
    { command: 'whoami /priv', reveals: "The current token's enabled privileges (e.g. SeImpersonatePrivilege, SeBackupPrivilege).", why: 'SeImpersonatePrivilege alone is enough for a PrintSpoofer/JuicyPotato-style escalation to SYSTEM on many builds.' },
    { command: 'whoami /groups', reveals: 'Group memberships and their integrity level.', why: 'Membership in a privileged local group, or a high-integrity token, changes what\'s reachable next.' },
    { command: 'systeminfo', reveals: 'OS build, patch level (Hotfix list), and architecture.', why: 'Lets you match against known local privilege-escalation CVEs for that exact build (check Watson/Sherlock output against an exploit database before using).' },
    { command: 'wmic qfe list / Get-Hotfix', reveals: 'Installed security patches.', why: 'A missing patch for a known local-privesc CVE is one of the fastest wins if present.' },
    { command: 'schtasks /query /fo LIST /v', reveals: 'Scheduled tasks and the account each one runs as.', why: 'A SYSTEM-owned task pointing at a file/folder the current user can write to is a direct escalation path.' },
    { command: 'icacls "C:\\Program Files\\..."', reveals: 'File/folder permissions for services and installed applications.', why: 'A service binary that low-privilege users can overwrite gets executed as whatever account runs the service — often SYSTEM.' },
    { command: 'sc qc <servicename>  &  accesschk.exe -uwcqv "Authenticated Users" *', reveals: "A service's binary path, start type, and running account, plus which services low-privileged users can reconfigure.", why: 'Unquoted service paths and weak service permissions are two of the most common Windows privesc classes.' },
    { command: 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\..." /v ImagePath', reveals: 'Whether a service path is unquoted with spaces (e.g. C:\\Program Files\\My App\\service.exe).', why: 'An unquoted path with spaces lets an attacker plant a binary earlier in the path (e.g. C:\\Program.exe) that Windows will execute instead.' },
    { command: 'reg query "HKLM\\...\\Winlogon" /v DefaultPassword', reveals: 'Autologon credentials sometimes stored in the registry in plaintext.', why: 'A leftover autologon password is directly reusable, and often reused elsewhere on the network.' },
    { command: 'findstr /si password *.txt *.ini *.config *.xml 2>nul', reveals: 'Plaintext credentials left in local config/text files.', why: 'Same rationale as the Linux grep check — deployment and config files are a frequent source of a reusable password.' },
    { command: 'net user; net localgroup administrators', reveals: 'Local user accounts and who is in the local Administrators group.', why: 'Confirms which accounts are actually worth targeting, and whether the current user is one privilege away from Administrators.' },
    { command: 'WinPEAS / PowerUp.ps1 / Seatbelt (run manually, not bundled here)', reveals: 'An automated sweep of everything above plus dozens more Windows-specific checks.', why: 'Widely-used public enumeration tools (not shipped with this toolkit) that automate this checklist once you understand what each check means.' }
  ]
};

export const GTFOBINS_URL = 'https://gtfobins.github.io/';
export const LOLBAS_URL = 'https://lolbas-project.github.io/';
