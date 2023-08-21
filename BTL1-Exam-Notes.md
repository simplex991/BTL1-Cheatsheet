*These notes will come handy in exam.*

## SOC Fundamentals

List of common ports.

|Port|Service|Description|
|:---:|:---:|:---:|
|20,21|FTP|File Transfer Protocol used to transfer files b/w systems.|
|22|SSH|Secure Shell Protocol allows users to securely connect to a remote host.|
|23|Telnet|Used before SSH, allows users to connect to a remote host, doesn't offer encryption.|
|25|SMTP|Simple Mail Transfer Protocol used to send emails between servers within the network, or over the internet.|
|53|DNS|Domain Name System converts human-readable domain names to machine-readable IP address.|
|67,68|DHCP|Dynamic Host Configuration Protocol assign IP address-related information to any hosts on the network automatically.|
|80|HTTP|Hypertext Transfer Protocol allows browsers (Chrome, Firefox, etc) to connect to web servers and request contents.|
|443|HTTPS|Hypertext Transfer Protocol Secure is a secure version of HTTP Protocol which allows browsers to securely connect to web servers and request contents.|
|514|Syslog|Syslog server listens for incoming Syslog notifications, transported by UDP packets.|

## Phishing Analysis

### Gathering IOCs

1. **Email Artifacts** :

- [ ] Sending Email Address
- [ ] Subject Line
- [ ] Recipient Email Addresses
- [ ] Sending Server IP & Reverse DNS
- [ ] Reply-To Address
- [ ] Date & Time

2. **X-Headers** :
- [ ] X-Sender-IP
- [ ] test

3. **Web Artifacts** :

- [ ] Full URLs
- [ ] Domain Names

3. **File Artifacts** :

- [ ] Attachment Name
- [ ] MD5, SHA1, SHA256 Hash Value

4. **Email address anotomy**:

<img src="email-anatomy.jpg" alt="drawing" style="width: 400px; margin-left : 25px;"/><br/>
<p style="margin-left: 25px; font-size: 15px;">
	In the above example, we can see that the mailbox (also know as the 'localpart')
	is named <b>"contact"</b> and the domain is <b>securityblue.team</b>.
</p>


5. ***Optional Header Fields***:

|Field|Description|
|:---:|:---:|
|Received|showing various information about the inermediary servers<br>and the date when the message was processed.|
|Reply-To|showing a reply address|
|subject|showing the message's subject|
|message-ID|showing a unique identification for the message|
|message body|containing the message, separated from the header by<br>a line break|

6. ***Text Editor Extraction***
- Search for "http=" as this will identify any http or https addresses<br>
being mentioned within the email.
- Search for anchor HTML tags \<a> which are used to perform hyperlinking.
- Search for the text fro mthe email body that is a hyperlink, in this example,<br>
we could search for "you can cancel it".
![Alt text](<Phising analysis links.png>)


---
### Analyzing Artifacts

1. **Visualization Tools** - [URL2PNG](https://www.url2png.com/), [URLScan](https://urlscan.io/), [AbuseIPDB](https://www.abuseipdb.com/)
2. **URL Reputation Tools** - [VirusTotal](https://www.virustotal.com/gui/), [URLScan](https://urlscan.io/), [URLhaus](https://urlhaus.abuse.ch/), [WannaBrowser](https://www.wannabrowser.net/)
3. **File Reputation Tools** - [VirusTotal](https://www.virustotal.com/gui/), [Talos File Reputation](https://www.talosintelligence.com/talos_file_reputation)
4. **Malware Sandboxing** - [Hybrid Analysis](https://www.hybrid-analysis.com/), [Any.run](https://any.run/), [VirusTotal](https://www.virustotal.com), [Joe Sandbox](https://www.joesandbox.com/)
5. **WhoIs Lookup (IP)** - [DomainTools](https://whois.domaintools.com/)

## Digital Forensics

1. Data Representation can be done in following ways,

- Base64
- Hexadecimal
- Octal
- ASCII
- Binary

### Conversion table

|Denary|Binary|Hexadecimal|
|:---:|:---:|:---:|
|0|0000|0|
|1|0001|1|
|2|0010|2|
|3|0011|3|
|4|0100|4|
|5|0101|5|
|6|0110|6|
|7|0111|7|
|8|1000|8|
|9|1001|9|
|10|1010|A|
|11|1011|B|
|12|1100|C|
|13|1101|D|
|14|1110|E|
|15|1111|F|

### Binary to Octal table
|Binary|Octal|
|:---:|:---:|
|000|0|
|001|1|
|010|2|
|011|3|
|100|4|
|101|5|
|110|6|
|111|7|

### ASCII Code: Character to Binary
|Character|Binary|Character|Binary|Character|Binary|
|:---|:---:|:---:|:---:|:---:|:---:|
|0|0011 0000|O|0100 1111|m|0110 1101|
|1|0011 0001|P|0100 0000|n|0110 1110|
|2|0011 0010|Q|0101 0001|o|0110 1111|
|3|0011 0011|R|0101 0010|p|0111 0000|
|4|0011 0100|S|0101 0011|q|0111 0001|
|5|0011 0101|T|0101 0100|r|0111 0010|
|6|0011 0110|U|0101 0101|s|0111 0011|
|7|0011 0111|V|0101 0110|t|0111 0100|
|8|0011 1000|W|0101 0111|u|0111 0101|
|9|0011 1001|X|0101 1000|v|0111 0110|
|A|0100 0001|Y|0101 1001|w|0111 0111|
|B|0100 0010|Z|0101 1010|x|0111 1000|
|C|0100 0011|a|0110 0001|y|0111 1001|
|D|0100 0100|b|0110 0010|z|0111 1010|
|E|0100 0101|c|0110 0011|.|0010 1110|
|F|0100 0110|d|0110 0100|,|0010 0111|
|G|0100 0111|e|0110 0101|:|0011 1010|
|H|0100 1000|f|0110 0110|;|0011 1011|
|I|0100 1001|g|0110 0111|?|0011 1111|
|J|0100 1010|h|0110 1000|!|0010 0001|
|K|0100 1011|i|0110 1001|'|0010 1100|
|L|0100 1100|j|0110 1010|"|0010 0010|
|M|0100 1101|k|0110 1011|(|0010 1000|
|N|0100 1110|l|0110 1100|)|0010 1001|
|||||space|0010 0000|


2. File Carving :


Scalpel manual
```bash
man scalpel
```

Scalpel configuration file
```md
/etc/scalpel/scalpel.conf
```
![Alt text](<config file.png>)<br>
<br>
after configuring scalpel to understand what files we're looking for,<br>
we can summon the tool using the following command:
```bash
scalpel -b -o <output> <disk image file>
```
- `scalpel` - calls the tool we want to use
- `-o \<name>` - provides a directory for recovered files to be stored.<br>
This MUST be an empty directory, or the name of a non-existent directory,<br>
as scalpel will create one
- `<disk image file>` - tells scalpel the file we want to search for files inside

Its worth mentioning that profiles in scalpel.conf file can be created by a user if you need to search for a custom file


### Creating a custom profile in scalpel.conf
Copy the conf file
```bash
sudo cp /etc/scalpel/scalpel.conf scalpel2.conf
sudo chown ubuntu scalpel2.conf
```

#### Editing the config file we just created using
```bash
sudo nano q4.conf
```
We'll create a new line at the top of the file that will look like this
```bash
# Scalpel configuration file

txt y 10000 BTL1 1LTB
```
- `txt` - extension
- `y` - case sensitive
- `10000` - size
- `BTL1` - Header
- `1LTB` - Footer

---

3. Hashes :

- **Windows** -

By default, `get-filehash` command will generate SHA256 sum of a file

```powershell
get-filehash <file>
```

To generate MD5 hash of a file

```powershell
get-filehash -algorithm MD5 <file>
```

To generate SHA1 hash of a file

```powershell
get-filehash -algorithm SHA1 <file>
```

To chain PowerShell command, use the `;`
```powershell
get-filehash <file> ; get-filehash <file> -algorithm MD5 <file> ; get-filehash <file> -algorithm SH1 <file>
```

Decrypting MD5 hashes<br>
https://www.md5online.org/md5-decrypt.html

- **Linux** - 

```bash
md5sum <file>
sha1sum <file>
sha256sum <file>
```

4. Find digital evidence with 
	- **FTK Imager** - Import .img file in FTK imager
	- **KAPE** - Can be used for fast acquisition of data.

5. **Windows Investigations** :

- **LNK Files** - These files can be found at 

```md
C:\Users\$USER$\AppData\Roaming\Microsoft\Windows\Recent
```

- **Prefetch Files** - 
	- **PECmd** - This tool can be used to view the prefetch files. `PECmd.exe -f <path/to/file.pf>`

These files can be found at 
```md
C:\Windows\Prefetch
```

- **Jumplist Files** - These files can be found at

```md
C:\Users\% USERNAME%\AppData\ Roaming\Microsoft\Windows\Recent\AutomaticDestinations
C:\Users\%USERNAME%\AppData\ Roaming\Microsoft\Windows\Recent\CustomDestinations
```

- **Logon Events**
	- **ID 4624** - successful logons to the system.
	- **ID 4672** - Special Logon events where administrators logs in.
	- **ID 4625** - Failed Logon events.
	- **ID 4634** - Logoffs from the current session.

These event logs can be found at
```md
C:\Windows\System32\winevt\Logs
```

- Capture and view the browser history with 
	- **Browser History Viewer** 
	- **Browser History Capturer**

6. **Linux Investigations** :
	- **/etc/passwd** - contains all information about users in the system. 
	- **/etc/shadow** - contains encrypted passwords
	- **Unshadow** - used to combine the passwd and shadow files.
	- **/var/lib** - In `/var/lib/dpkg/status` location, this file includes a list of all installed software packages.
	- **.bash_history** - contains all the issued commands by the users.
	- **Hidden Files** - isuch files whose name begins with **.**
	- **Clear Files** - files that are accessible through standard means.
	- **Steganography** - practice of concealing messages or information within other non-secret text or data.

7. **Swapfile**<br>
Manage size of a Linux swap file
```bash
sudo fallocate -l [file size] /swapfile
```
Check the amount of swap space available to a system
```bash
free -h
```
Identify whether the sawp space is a file or a partition
```bash
swapon -show
```

7. **Volatility** - 

Find the imageinfo of the file, 

```bash
volatility -f /path/to/file.mem imageinfo
```

List the processes of a system,

```bash
volatility -f /path/to/file.mem --profile=PROFILE pslist
```

View the process listing in tree form,

```bash
volatility -f /path/to/file.mem --profile=PROFILE pstree
```

View command line of the specific process with PID XXXX,

```bash
volatility -f /path/to/file.mem --profile=PROFILE dlllist -p XXXX
```

View Network Connections,

```bash
volatility -f /path/to/file.mem --profile=PROFILE netscan
```

Dumping the process with a specific PID XXXX,

```bash
volatility -f /path/to/file.mem --profile=PROFILE procdump -p XXXX -D /home/ubuntu/Desktop
```

Print all available processes,

```bash
volatility -f memdump.mem --profile=PROFILE psscan
```

Print expected and hidden processes,

```bash
volatility -f memdump.mem --profile=PROFILE psxview
```

Create a timeline of events from the memory image,

```bash
volatility -f memdump.mem --profile=PROFILE timeliner
```

Pull internet browsing history,

```bash
volatility -f memdump.mem --profile=PROFILE iehistory
```

Identify any files on the system from the memory image,

```bash
volatility -f memdump.mem --profile=PROFILE filescan
```

8. **Metadata** - Data about data
	
- **Exiftool** 

```bash
exiftool <file>
```

## Security Information and Event Management

### SPLUNK

Queries must start by referencing the dataset,

```md
index="botsv1"
```

To search for a source IP (src) address with a value of 127.0.0.1,

```md
index="botsv1" src="127.0.0.1"
```

To search for a destination IP (dst) address that this source IP address made a connection with a value of X.X.X.X,

```md
index="botsv1" src="127.0.0.1" dst="X.X.X.X"
```

## Incident Response

1. **Network Analysis** - use Wireshark to import .pcap, .pcapng files.

2. **CMD** : Command prompt can be used to view the valuable information,

To view the network configuration of the system,

```cmd
ipconfig /all
```

To check running processes and programs,

```cmd
tasklist
```

Display running processes and the associated binary file that was executed to create the process,

```cmd
wmic process get description, executablepath
```

To view all number of users in the command prompt

```cmd
net users
```

List all users that are in the administrators user group,

```cmd
net localgroup administrators
```

List all users in RDP group,

```cmd
net localgroup "Remote Desktop Users"
```

List all services and detailed information about each one,

```cmd
sc query | more
```

List open ports on a system, which could show the presence of a backdoor,

```cmd
netstat -ab
```

3. **Powershell** - Can also be used often retrieve much more information.

These commands will get network-related information from the system,

```powershell
Get-NetIPConfiguration
Get-NetIPAddress
```

List all local users on the system,

```powershell
Get-LocalUser
```

Provide a specific user to the command to only get information about them,

```powershell
Get-LocalUser -Name BTLO | select *
```

Quickly identify running services on the system in a nice separate window,

```powershell
Get-Service | Where Status -eq "Running" | Out-GridView
```

Group running processes by their priority value,

```powershell
Get-Process | Format-Table -View priority
```

Collect specific information from a service by including the name in the command (-Name ‘namehere’) or the Id, as shown above and below,

```powershell
Get-Process -Id 'idhere' | Select *
```

Scheduled Tasks are often abused and utilized a common persistence technique,

```powershell
Get-ScheduledTask
```

Specify the task, and retrieving all properties for it,

```powershell
Get-ScheduledTask -TaskName 'PutANameHere' | Select *
```

Changing the Execution Policy applied to our user,

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser
```

4. **DeepBlueCLI** - PowerShell script that was created by SANS to aid with the investigation and triage of Windows Event logs.

To process log.evtx,

```powershell
./DeepBlue.ps1 log.evtx
```

DeepBlue will point at the local system's Security or System event logs directly,

```powershell
# Start the Powershell as Administrator and navigate into the DeepBlueCli tool directory, and run the script

./DeepBlue.ps1 -log security
./DeepBlue.ps1 -log system

# if the script is not running, then we need to bypass the execution policy
Set-ExecutionPolicy Bypass -Scope CurrentUser
```
