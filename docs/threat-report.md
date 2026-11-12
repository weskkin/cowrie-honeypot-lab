# 🛡️ CyberTrap Threat Intelligence & Incident Report
**Project:** Cowrie Cloud Honeypot Telemetry & Threat Analysis  
**Analyst:** Homelab Security Operations  
**Date:** November 2026  
**Monitoring Window:** 16 Hours  
**Platform:** Ubuntu 24.04 LTS on Microsoft Azure (Public IPv4: `20.164.216.21`)  
**SIEM Platform:** Wazuh 4.x (5,320+ Processed Security Alerts)  

---

## 1. Executive Summary

Over a 16-hour monitoring period, a medium-interaction Cowrie SSH/Telnet honeypot was exposed to the public internet on standard TCP ports 22 and 23. During this window, the sensor recorded **19,091 total security events** from **146 unique threat actors (IP addresses)** spanning **1,696 discrete interactive sessions**.

Key findings include:
- **Mass Brute-Force Spraying:** Automated bots attempted continuous credential stuffing, overwhelmingly targeting administrative accounts (`root` and `admin`).
- **IoT & Embedded Exploitation Campaign:** Attackers deployed automated reconnaissance probing for HiSilicon and MIPS/ARM embedded Linux architectures.
- **Active Malware Propagation Captured:** Captured live dropper scripts and statically linked ELF 64-bit binaries associated with the **Mirai botnet family**, attempting to establish C2 communication with `160.119.66.206`.
- **Competitor Process Termination:** Captured post-exploitation shell scripts that systematically enumerated `/proc/*` to terminate rival cryptominers and botnet agents.

---

## 2. Threat Metrics & Statistics

| Metric | Recorded Value |
|---|---|
| **Total Logged Events** | 19,091 |
| **Unique Threat Actors (IPs)** | 146 |
| **Unique Sessions** | 1,696 |
| **Processed SIEM Alerts** | 5,321 |
| **Captured Malware Artifacts** | 3 (2 unique C2 payloads + 1 direct dropper) |

---

## 3. Threat Actor & Network Breakdown

### Top 5 Attacking IP Addresses
1. **`109.160.32.109`** — 7,611 events (Persistent, aggressive brute-force scanning)
2. **`221.153.81.149`** — 2,773 events
3. **`195.178.110.232`** — 1,847 events
4. **`92.118.39.77`** — 1,571 events
5. **`92.118.39.64`** — 1,245 events

---

## 4. Credential & Brute-Force Analysis

The vast majority of attacks utilized automated dictionaries targeting standard Linux and network device defaults:

### Top Targeted Usernames
- `root` (899 attempts)
- `admin` (202 attempts)
- `ubuntu` (13 attempts)
- `user` (12 attempts)
- `test` (10 attempts)

### Top Attempted Passwords
- `admin` (173 attempts)
- `123456` (25 attempts)
- `wmL-o` (10 attempts)
- `root` (9 attempts)
- `12345` (8 attempts)
- `P@ssw0rd` (5 attempts)

**Dominant Combo:** `admin:admin` accounted for the vast majority of paired credentials.

---

## 5. Post-Exploitation TTPs & Command Analysis

Once bots were granted access to the emulated shell environment, they executed scripted discovery and defense evasion sequences:

1. **System & Architecture Fingerprinting:**
   ```bash
   uname -s -v -n -r -m
   /bin/busybox HISILICON
   ```
   *Analysis:* Identifies OS kernel release and checks whether the victim device runs on HiSilicon video surveillance / DVR chipsets.

2. **Rival Malware Termination (Botnet Territorial Control):**
   ```bash
   for proc_dir in /proc/*; do
       pid=${proc_dir##*/}
       result=$(ls -l "/proc/$pid/exe" 2> /dev/null)
       if [ "$result" != "${result%(deleted)}" ]; then
           kill -9 "$pid"
       fi
   done
   ```
   *Analysis:* Scans the Linux process table for running executables that have been deleted from disk (a hallmark of running cryptominers and competing Mirai variants) and terminates them with `SIGKILL`.

3. **Stealth Staging & Execution Preparation:**
   ```bash
   >/var/.f && chmod 777 /var/.f && /var/.f && cd /var/;
   >/var/tmp/.f && chmod 777 /var/tmp/.f && /var/tmp/.f && cd /var/tmp/;
   ```

---

## 6. Malware Artifact Triage & Indicators of Compromise (IoCs)

### Captured Payloads:
1. **Mirai Multi-Arch Dropper Script (`kla.sh`)**
   - **SHA-256:** `39be6853a8204ce6455a373a6ffb4cb4672d4a62d90be69f7d6eeb66cda10b96`
   - **Source URL:** `http://160.119.66.206/bins/kla.sh`
   - **Description:** Shell script attempting to fetch cross-compiled binaries (`x86_64`, `mips`, `arm`, `ppc`) into writable temporary directories.

2. **Mirai Botnet Binary (`net.x86_64`)**
   - **SHA-256:** `3674a103804cac96027fe1cf62aaab4948c1d547d1c885542177a263103b4260`
   - **File Type:** ELF 64-bit LSB executable, x86-64, statically linked, stripped
   - **Size:** 189 KB
   - **Source URL:** `http://160.119.66.206/bins/net.x86_64`

3. **Direct Ingress Payload**
   - **SHA-256:** `22c26ebf279faf93bc41635e6e9e5ef260d4f82ee46a5ca45395b288866512d8`
   - **Source IP:** `176.65.149.156`

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| **Credential Access** | T1110.001 | Password Guessing | 1,600+ brute-force login attempts against `root`/`admin` |
| **Execution** | T1059.004 | Unix Shell | Automated execution of commands via `sh` and `busybox` |
| **Discovery** | T1082 | System Information Discovery | `uname -s -v -n -r -m`, checking `/proc/self/exe` |
| **Lateral Movement / Ingress** | T1105 | Ingress Tool Transfer | Automated `wget` and `curl` retrieving payloads from C2 server |
| **Defense Evasion** | T1070 | Indicator Removal | Staging hidden files in `/var/.f` and killing rival processes |

---

## 8. Defensive Recommendations

1. **Disable Password Authentication on Edge-Facing Services:** Enforce public-key authentication (Ed25519/RSA-4096) exclusively.
2. **Non-Standard Management Ports:** Relocate administrative SSH daemons away from default port 22.
3. **Automated IP Shunning:** Implement dynamic rate-limiting tools such as `Fail2ban` or CrowdSec to ban IPs generating consecutive authentication failures.
4. **Outbound Firewall Restrictions:** Block unauthenticated outbound TCP/UDP traffic from IoT/infrastructure servers to prevent payload staging from untrusted external IPs (e.g. `160.119.66.206`).
