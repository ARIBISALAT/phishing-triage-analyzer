# Automated Phishing Triage & Email Header Analyzer

A lightweight Python-based security automation tool designed to streamline Tier 1/Tier 2 SOC analyst workflows by automatically parsing suspicious raw email samples (`.eml`), validating authentication headers, extracting Indicators of Compromise (IoCs), and enriching threat intelligence via the VirusTotal API.

---

## 🚀 Features

- **Header Inspection & Spoofing Detection:** Extracts critical metadata (`Subject`, `From`, `Return-Path`, `Reply-To`, `Authentication-Results`) and flags anomalies—such as discrepancies between the `From` and `Reply-To` headers indicative of credential harvesting.
- **IoC Extraction:** Uses regular expressions to harvest URLs from email bodies and computes SHA-256 hashes for any embedded file attachments.
- **Threat Intelligence Enrichment:** Automatically queries the VirusTotal API (v3) to cross-reference extracted URLs against known malicious indicators.
- **CLI-Driven Triage:** Provides instant, structured terminal output for rapid incident response and preliminary classification.

---

## 🛠️ Tech Stack

- **Language:** Python 3
- **Core Libraries:** `email`, `re`, `hashlib`, `requests`, `base64`
- **APIs:** VirusTotal REST API v3

---

## 📦 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/phishing-triage-analyzer.git](https://github.com/your-username/phishing-triage-analyzer.git)
   cd phishing-triage-analyzer
