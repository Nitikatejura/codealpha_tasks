# CodeAlpha Cyber Security Internship Portfolio

This repository contains my completed technical project implementations for the CodeAlpha Cyber Security Internship program. Each project demonstrates hands-on implementation of defensive security concepts, network monitoring, and secure code practices.

---

## 📂 Repository Project Mapping

To assist the evaluation team, here is the direct index mapping files to their respective domain tasks:

### 🔹 Task 1: Basic Network Sniffer
* **Core Implementation:** [`sniffer.py`](./sniffer.py)
* **Description:** A Python-based packet analysis tool utilizing the `scapy` library to capture real-time network traffic. It sniffs packets to extract raw data structures including source/destination IP addresses, protocols (TCP, UDP, ICMP), and text payload slices.

### 🔹 Task 3: Secure Coding Review
* **Vulnerable Application Sandbox:** [`vulnerable_app.py`](./vulnerable_app.py)
* **Remediated Secure Application:** [`secure_app.py`](./secure_app.py)
* **Description:** A secure code auditing lab demonstrating vulnerability detection and remediation in a Python Flask environment. It highlights the exploitation and subsequent defense-in-depth mitigation of critical web application flaws: SQL Injection (SQLi) and Reflective Cross-Site Scripting (XSS).

### 🔹 Task 4: Network Intrusion Detection System (NIDS)
* **Core Implementation:** [`nids.py`](./nids.py)
* **Configuration Report:** [`nids_snort_review.md`](./nids_snort_review.md)
* **Description:** A signature-based live intrusion detection system built to monitor local interfaces for malicious activity trends. The implementation tracks and alerts on live threat vectors, including ICMP network flooding, inbound unauthorized SSH connection sequences, and raw web application scanning strings.

---

## 🛠️ Local Environment & Dependencies
The tools developed in this portfolio rely on the following software frameworks:
* **Language:** Python 3.14+
* **Core Packages:** `scapy`, `flask`
* **Driver Prerequisite (Windows):** Npcap packet capture driver running in WinPcap API-compatible mode.