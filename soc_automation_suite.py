#!/usr/bin/env python3
import os
import sys
import email
from email import policy
import re
import requests

# ==========================================
# MODULE 1: Phishing Email Triage Analyzer
# ==========================================
def analyze_eml(file_path):
    print(f"[-] Analyzing email file: {file_path}")
    if not os.path.exists(file_path):
        print(f"[!] Error: File '{file_path}' not found.")
        return

    with open(file_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    subject = msg.get('Subject', 'N/A')
    from_addr = msg.get('From', 'N/A')
    return_path = msg.get('Return-Path', 'N/A')
    reply_to = msg.get('Reply-To', 'N/A')
    auth_results = msg.get('Authentication-Results', 'N/A')

    print("\n--- EMAIL METADATA ---")
    print(f"Subject: {subject}")
    print(f"From: {from_addr}")
    print(f"Return-Path: {return_path}")
    print(f"Reply-To: {reply_to}")
    print(f"Auth Results: {auth_results}")

    # Simple spoofing check
    if reply_to != 'N/A' and from_addr != 'N/A':
        if extract_email_address(from_addr) != extract_email_address(reply_to):
            print("[!] ALERT: 'Reply-To' header differs from 'From' header (Potential Spoofing/Credential Harvesting Indicator)")

    # Extract URLs
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode(errors='ignore')
    else:
        body = msg.get_payload(decode=True).decode(errors='ignore')

    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
    print(f"\n--- EXTRACTED URLS ({len(urls)}) ---")
    for url in set(urls):
        print(f" - {url}")

# Helper to clean email strings
def extract_email_address(header_value):
    match = re.search(r'<([^>]+)>', header_value)
    return match.group(1) if match else header_value.strip()

# ==========================================
# MODULE 2: Detection Engineering Generator
# ==========================================
def generate_detection_artifacts():
    print("\n[-] Generating Detection Engineering artifacts...")
    os.makedirs("detections", exist_ok=True)

    # 1. PowerShell Sigma Rule
    ps_sigma = """title: Suspicious Encoded or Hidden PowerShell Execution
id: a1b2c3d4-e5f6-7890-abcd-ef0123456789
status: experimental
description: Detects PowerShell execution utilizing encoded commands or hidden windows.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-Enc '
            - '-WindowStyle Hidden'
    condition: selection
level: high
"""
    with open("detections/suspicious_powershell.yml", "w") as f:
        f.write(ps_sigma)

    # 2. LSASS Sigma Rule
    lsass_sigma = """title: Potential LSASS Credential Dumping
id: b2c3d4e5-f6a7-8901-bcde-f01234567890
status: experimental
description: Detects suspicious processes attempting to access LSASS memory.
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1f0fff'
    condition: selection
level: high
"""
    with open("detections/credential_dumping_lsass.yml", "w") as f:
        f.write(lsass_sigma)

    print("[+] Successfully generated Sigma rules in the 'detections/' directory!")

if __name__ == "__main__":
    print("=== SOC AUTOMATION & DETECTION SUITE ===")
    if len(sys.argv) > 1:
        analyze_eml(sys.argv[1])
    else:
        print("[*] No email file provided for parsing. Running detection artifact generator...")
        generate_detection_artifacts()
