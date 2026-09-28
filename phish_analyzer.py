#!/usr/bin/env python3
import base64
import email
from email import policy
import hashlib
import re
import sys
import requests

# === CONFIGURATION ===
VIRUSTOTAL_API_KEY = "402e1f1e2c0b1cd9c9f9651eedab0101a2713ea2ae68bcfb705b2e345660eaa5"

def extract_iocs(email_message):
    urls = set()
    attachments = []
    body_text = ""

    if email_message.is_multipart():
        for part in email_message.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    file_data = part.get_payload(decode=True)
                    sha256 = hashlib.sha256(file_data).hexdigest()
                    attachments.append({"filename": filename, "sha256": sha256})

            elif content_type == "text/plain":
                try:
                    body_text += part.get_payload(decode=True).decode()
                except:
                    pass
    else:
        try:
            body_text = email_message.get_payload(decode=True).decode()
        except:
            pass

    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    found_urls = re.findall(url_pattern, body_text)
    for u in found_urls:
        urls.add(u)

    return list(urls), attachments

def check_virustotal_url(url):
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_VT_API_KEY_HERE":
        print("    [!] VirusTotal API Key not set. Skipping lookup.")
        return

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(vt_url, headers=headers)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            print(f"    [VT Result] Malicious: {malicious} | Suspicious: {suspicious} | Harmless: {harmless}")
            if malicious > 0:
                print(f"    [!] ALERT: URL flagged as MALICIOUS by VirusTotal!")
        elif response.status_code == 404:
            print("    [VT Result] URL not found in VirusTotal database.")
        else:
            print(f"    [VT Error] Status code: {response.status_code}")
    except Exception as e:
        print(f"    [VT Error] Could not connect to API: {e}")

def analyze_email(eml_file_path):
    with open(eml_file_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    print("[-] Parsing Email Headers...")
    subject = msg.get("Subject", "N/A")
    sender = msg.get("From", "N/A")
    return_path = msg.get("Return-Path", "N/A")
    reply_to = msg.get("Reply-To", "N/A")
    auth_results = msg.get("Authentication-Results", "N/A")

    print(f"\n--- EMAIL METADATA ---")
    print(f"Subject: {subject}")
    print(f"From: {sender}")
    print(f"Return-Path: {return_path}")
    print(f"Reply-To: {reply_to}")
    print(f"Auth Results: {auth_results}")

    if reply_to != "N/A" and sender not in reply_to:
        print("[!] ALERT: 'Reply-To' header differs from 'From' header (Potential Spoofing/Credential Harvesting Indicator)")

    print("\n[-] Extracting IoCs...")
    urls, attachments = extract_iocs(msg)

    print(f"\n--- EXTRACTED URLS ({len(urls)}) ---")
    for url in urls:
        print(f" - {url}")
        print(f"   Querying VirusTotal...")
        check_virustotal_url(url)

    print(f"\n--- EXTRACTED ATTACHMENTS ({len(attachments)}) ---")
    for att in attachments:
        print(f" - File: {att['filename']} | SHA256: {att['sha256']}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 phish_analyzer.py <path_to_email.eml>")
    else:
        analyze_email(sys.argv[1])
