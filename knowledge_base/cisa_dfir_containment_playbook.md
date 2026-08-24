# Project DFIR Containment Notes Informed by CISA and NIST Guidance

## 1. Executive Summary & Regulatory Context
This project-authored document condenses and reorganizes general incident-response concepts informed by CISA's 2021 Cybersecurity Incident Response Playbook and NIST SP 800-61r2. It adds Windows-specific commands, event identifiers, tools, registry paths, and operational recommendations for the ForenRAG laboratory. It is not an official CISA or NIST publication, has not been validated or endorsed by either agency, and should be reviewed by a qualified incident responder before use.

---

## 2. Playbook 1: Credential Access & Registry Dump Containment (MITRE T1003.002)

### Target Activity
Unauthorized export of Security Account Manager (SAM), SYSTEM, or SECURITY registry hives via native tools (`reg.exe`) or credential dumping frameworks.

### Phase A: Immediate Host Containment
1. **Network Isolation**: Immediately isolate the target host from local network segments via EDR/firewall rules to prevent NTLM hash reuse or lateral movement.
2. **Process Termination**: Terminate parent process IDs (PIDs) associated with active `reg.exe` exports or remote execution services (`wmiprvse.exe`, `psexec.exe`).
3. **Artifact Quarantine**: Delete exported hive files (`sam.bak`, `system.bak`, `security.bak`) from temporary paths (`C:\Users\Public\`, `%TEMP%`).

### Phase B: Credential Remediation
1. **Local Account Reset**: Force an immediate password rotation for all local Administrator accounts on the affected endpoint.
2. **Domain Credential Audit**: If host is domain-joined, audit Active Directory Event ID 4624/4625 authentication events for suspicious ticket requests or NTLM pass-the-hash activity.

---

## 3. Playbook 2: Ingress Tool Transfer & Malicious Script Execution (MITRE T1105 / T1059.001)

### Target Activity
Download and execution of secondary payloads or script stagers (`__PSScriptPolicyTest_*.ps1`, `payload.exe`) via `powershell.exe`, `certutil.exe`, or `bitsadmin.exe`.

### Phase A: Immediate Host Containment
1. **Process & Thread Termination**: Kill active `powershell.exe`, `certutil.exe`, or `bitsadmin.exe` execution threads.
2. **Network Perimeter Block**: Block originating remote Command-and-Control (C2) IP addresses and domains at the edge firewall/proxy.
3. **File System Quarantine**: Quarantine all executable binaries dropped in writable user directories (`%TEMP%`, `C:\Users\<user>\AppData\Local\Temp`).

### Phase B: Forensic Evidence Preservation
1. **Memory Capture**: Perform full host physical memory acquisition prior to reboot to capture volatile payload code and unencrypted C2 strings.
2. **Script Block Inspection**: Query Windows Event ID 4104 (PowerShell Script Block Logging) to retrieve the decoded script block contents.

---

## 4. Playbook 3: Scheduled Task & Registry Persistence Containment (MITRE T1053.005 / T1547.001)

### Target Activity
Creation of persistent startup tasks or autorun registry keys via `schtasks.exe` or `reg.exe`.

### Phase A: Persistence Remediation
1. **Scheduled Task Deletion**: Forcefully unregister and delete malicious scheduled tasks using command:
   `schtasks /delete /tn "<TaskName>" /f`
2. **Registry Key Cleanup**: Inspect and remove unauthorized run keys under:
   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
   `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

### Phase B: System Hardening
1. **AppLocker / WDAC Policy Enforcement**: Restrict script execution policies and block untrusted binary execution from `%TEMP%`.
2. **Audit Logging**: Verify that Sysmon Event IDs 1 (Process), 11 (File Create), and 13 (Registry Set) are active across enterprise endpoints.
