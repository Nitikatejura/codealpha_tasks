# Network Intrusion Detection System (NIDS) Implementation Report

**Project:** Snort NIDS Deployment, Rule Configuration, and Threat Monitoring
**Domain:** Network Security & Threat Detection
**Tool Utilized:** Snort (Open Source Network Intrusion Detection System)

---

## 1. Environment Setup & Architecture

Snort was deployed as a network-based intrusion detection system (NIDS) configured to monitor a local network interface in sniffer and packet logging mode. 

* **Network Interface Monitored:** `eth0`
* **Operating Directory:** `/etc/snort/`
* **Main Configuration File:** `/etc/snort/snort.conf`
* **Custom Rules File:** `/etc/snort/rules/local.rules`

---

## 2. Rule Configuration & Alert Design

To protect the network asset against suspicious or malicious activity, three custom rules were appended to the `local.rules` file to detect ICMP flooding (Ping scans), unauthorized SSH brute-force attempts, and basic HTTP cross-site scripting reconnaissance.

```snort
# Rule 1: Detect ICMP (Ping) Flood / Network Reconnaissance
alert icmp any any -> $HOME_NET any (msg:"[ALERT] ICMP Packet Detected - Potential Network Scan"; sid:1000001; rev:1;)

# Rule 2: Detect Unauthorized SSH Access Attempts on Port 22
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"[ALERT] Inbound SSH Connection Attempt Detected"; flags:S; sid:1000002; rev:1;)

# Rule 3: Detect Malicious Web Reconnaissance (Basic XSS Attempt)
alert tcp any any -> $HOME_NET 80 (msg:"[ALERT] Potential Web XSS Reconnaissance Detected"; content:"<script>"; nocase; sid:1000003; rev:1;)
