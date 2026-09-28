# Detection Engineering Portfolio

This directory contains custom detection artifacts for monitoring and catching suspicious techniques in enterprise environments.

---

## 1. Suspicious PowerShell Execution (T1059.001)

### SIEM Query Translations
#### Elastic KQL (Elastic SIEM)
```kql
event.category: "process" AND event.type: "start" AND process.name: "powershell.exe" AND (process.command_line: "* -EncodedCommand *" OR process.command_line: "* -Enc *" OR process.command_line: "* -WindowStyle Hidden *" OR process.command_line: "* DownloadString *" OR process.command_line: "* Net.WebClient *")

