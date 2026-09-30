# Defender XDR Advanced Hunting — KQL Library

**Microsoft Defender XDR Advanced Hunting queries for threat hunting, incident response, and security posture reviews.**
MDO · MDE · MDI · MDCA · Cross-Pillar XDR Kill Chains

> Platform: `security.microsoft.com` → Hunting → Advanced Hunting  
> Requires: Microsoft 365 E5 or Defender XDR standalone licensing  
> Access: Security Reader minimum for Advanced Hunting  

---

## 📁 Query Index

### Email / MDO — `queries/email/MDO-Email-BEC-Spam-SafeLinks.kql`

| # | Query | Table |
|---|---|---|
| 1.1 | Top spam sources (7d) | `EmailEvents` |
| 1.2 | High-risk recipients by phishing volume | `EmailEvents` |
| 1.3 | Phishing campaign clustering by subject | `EmailEvents` |
| 1.4 | High-volume outbound send anomaly (BEC prep) | `EmailEvents` |
| 1.5 | Phishing block rate by type (posture) | `EmailEvents` |
| 2.1 | Display name spoofing / exec impersonation | `EmailEvents` |
| 2.2 | Wire/payment/ACH keyword in inbound mail | `EmailEvents` |
| 2.3 | Lookalike domain regex detection (typosquatting) | `EmailEvents` |
| 3.1 | Inbox rule creation/modification (all) | `CloudAppEvents` |
| 3.2 | Suspicious inbox rules (external forward / delete) | `CloudAppEvents` |
| 3.3 | Mailbox-level forwarding changes (Set-Mailbox) | `CloudAppEvents` |
| 3.4 | IR: Mailbox rules correlated with risky sign-ins | `AADSignInEventsBeta`, `CloudAppEvents` |
| 4.1 | SafeLinks blocked click trends (posture) | `UrlClickEvents` |
| 4.2 | IR: URL click investigation — SafeLinks events | `UrlClickEvents` |
| 4.3 | IR: URL to email delivery correlation | `EmailUrlInfo`, `EmailEvents` |
| 5.1 | ZAP effectiveness by day | `EmailPostDeliveryEvents` |
| 5.2 | Malicious attachment evasion pattern | `EmailAttachmentInfo` |

---

### Endpoint / MDE — `queries/endpoint/MDE-Process-Network-Persistence.kql`

| # | Query | Table |
|---|---|---|
| 1.1 | LOLBIN execution from Office apps | `DeviceProcessEvents` |
| 1.2 | PowerShell base64 encoded command | `DeviceProcessEvents` |
| 1.3 | Recon commands via cmd.exe (whoami/net/ipconfig) | `DeviceProcessEvents` |
| 1.4 | PsExec / remote execution tool usage | `DeviceProcessEvents` |
| 1.5 | Unusual process from writable paths (AppData/Temp) | `DeviceProcessEvents` |
| 1.6 | LSASS access (credential dumping) | `DeviceEvents` |
| 1.7 | VSS / shadow copy deletion (ransomware precursor) | `DeviceProcessEvents` |
| 1.8 | Mass file encryption indicator (5m bucket, 100+ files) | `DeviceFileEvents` |
| 2.1 | Outbound connections to rare external IPs | `DeviceNetworkEvents` |
| 2.2 | DNS beaconing pattern (C2 indicator) | `DeviceNetworkEvents` |
| 2.3 | SMB lateral movement (port 445, 5+ targets) | `DeviceNetworkEvents` |
| 2.4 | RDP lateral movement (port 3389, 3+ targets) | `DeviceNetworkEvents` |
| 2.5 | IR: Multi-table IP IOC hunt (custom detection compatible) | `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `DeviceEvents` |
| 2.6 | IR: Device network activity for specific IOC domain | `DeviceNetworkEvents` |
| 3.1 | Scheduled task creation | `DeviceProcessEvents` |
| 3.2 | Registry Run key modifications | `DeviceEvents` |
| 3.3 | New service installation | `DeviceEvents` |

---

### Identity / MDI — `queries/identity/MDI-Lateral-Movement-Recon.kql`

| # | Query | Table |
|---|---|---|
| 1.1 | Failed sign-ins by user (>5 failures) | `IdentityLogonEvents` |
| 1.2 | Successful sign-ins from new countries (leftanti) | `IdentityLogonEvents` |
| 1.3 | Legacy auth sign-ins (IMAP/POP/SMTP/EAS) | `AADSignInEventsBeta` |
| 1.4 | Sign-ins outside business hours | `IdentityLogonEvents` |
| 1.5 | Token theft detection (3+ countries / 10+ IPs) | `AADSignInEventsBeta` |
| 1.6 | Password spray (10+ accounts from one IP per hour) | `IdentityLogonEvents` |
| 1.7 | Brute force single account (10+ failures per 15m) | `IdentityLogonEvents` |
| 1.8 | Successful login after multiple failures | `IdentityLogonEvents` |
| 1.9 | Dormant account suddenly active (60d threshold) | `IdentityLogonEvents` |
| 1.10 | Device registration from IP not seen in 29 days | `AADSignInEventsBeta` |
| 2.1 | LDAP bulk enumeration (50+ queries/hr) | `IdentityQueryEvents` |
| 2.2 | SMB share enumeration (SamrEnumerateUsers) | `IdentityQueryEvents` |
| 2.3 | AD admin group enumeration via LDAP | `IdentityQueryEvents` |
| 3.1 | DCSync / DRSR replication rights abuse | `IdentityDirectoryEvents` |
| 3.2 | AdminSDHolder modification (ACL persistence) | `IdentityDirectoryEvents` |
| 3.3 | Privileged group membership changes | `IdentityDirectoryEvents` |
| 3.4 | Sensitive group changes (custom list) | `IdentityDirectoryEvents` |
| 3.5 | Azure AD role assignment changes | `CloudAppEvents` |
| 4.1 | NTLM logon anomalies (Pass-the-Hash) | `IdentityLogonEvents` |
| 4.2 | Kerberoasting — SPN enumeration + TGS requests | `IdentityQueryEvents` |
| 4.3 | Impossible travel (2+ countries in 4 hours) | `IdentityLogonEvents` |

---

### Cloud Apps / MDCA — `queries/cloud-apps/MDCA-OAuth-Exfil-ShadowIT.kql`

| # | Query | Table |
|---|---|---|
| 1.1 | High-privilege OAuth app consent events | `CloudAppEvents` |
| 1.2 | OAuth app granted tenant-wide admin consent | `CloudAppEvents` |
| 1.3 | Unusual OAuth app token refresh from new location | `CloudAppEvents` |
| 2.1 | Bulk SharePoint/OneDrive download (100+ files/hr) | `CloudAppEvents` |
| 2.2 | External file sharing outside tenant domain | `CloudAppEvents` |
| 2.3 | Personal cloud storage uploads (Dropbox/GDrive/Box) | `CloudAppEvents` |
| 3.1 | Impossible travel (3+ countries in 6h window) | `CloudAppEvents` |
| 3.2 | Logon from anonymous proxy / Tor exit node | `CloudAppEvents` |
| 3.3 | First-ever access to a cloud app by user | `CloudAppEvents` |
| 4.1 | Global admin activity outside business hours | `CloudAppEvents` |
| 4.2 | Bulk user account operations (10+ ops/hr) | `CloudAppEvents` |
| 4.3 | Email/message bulk deletion anomaly | `CloudAppEvents` |

---

### Cross-Pillar XDR Kill Chains — `queries/cross-pillar/XDR-Correlation-Playbook.kql`

| # | Scenario | Tables |
|---|---|---|
| C1 | BEC kill chain: phish → click → inbox rule → forward | `EmailEvents`, `UrlClickEvents`, `CloudAppEvents` |
| C2 | Account takeover: risky sign-in → cloud activity spike | `AADSignInEventsBeta`, `CloudAppEvents` |
| C3 | NTLM → SMB → execution lateral movement | `IdentityLogonEvents`, `DeviceNetworkEvents`, `DeviceProcessEvents` |
| C4 | Credential dump → LDAP recon → domain logon | `DeviceEvents`, `IdentityQueryEvents`, `IdentityLogonEvents` |
| C5 | Insider: dormant user + bulk download + external share | `AADSignInEventsBeta`, `CloudAppEvents` |
| C6 | Ransomware: phish → shadow delete → mass encryption | `EmailEvents`, `DeviceProcessEvents`, `DeviceFileEvents` |
| C7 | Orphan high/medium alerts without incidents | `AlertInfo`, `AlertEvidence` |

---

## 🚀 Usage

### Microsoft Defender XDR (Portal)
1. Open [security.microsoft.com](https://security.microsoft.com)
2. Go to **Hunting → Advanced Hunting**
3. Paste any query — each is self-contained with `let` variables at the top
4. Adjust `ago()` lookback windows and environment-specific values as noted in comments

### Customization Points
Each query includes inline comments marking environment-specific values:
- `// replace with your domain`
- `// replace with IOC`
- `// populate per environment`
- `// customize`

### Important Notes
- Cross-pillar kill chain queries (C1–C7) must be run as **individual queries** — each `let` block is scoped to one query
- Custom detection rules require `union` syntax — use query 2.5 for IP IOC hunts instead of `search in`
- Maximum lookback in Advanced Hunting is **30 days** for most tables
- `IPTags` field (used in MDCA queries 3.2) requires MDCA licensing and tag configuration

---

## 📋 Prerequisites
- Microsoft 365 E5 or Defender XDR standalone licenses
- Advanced Hunting access (Security Reader minimum)
- MDCA licensing for IPTags, impossible travel, and unsanctioned app queries

---

## 🔄 Version History

| Version | Date | Changes |
|---|---|---|
| v1.0 | Feb 2025 | Initial MDO queries (13 queries) |
| v2.0 | Mar 2026 | Added BEC, inbox rules, MSAL auth, ZAP, SafeLinks |
| v2.1 | Mar 2026 | Added MDE, MDI, MDCA, cross-pillar XDR kill chains |
| v3.0 | Mar 2026 | Full refresh — all queries consolidated, IR queries added, kill chains updated |

---

*Maintained by [Kevin2083](https://github.com/Kevin2083). Queries are provided as-is — validate in your environment before use.*
