# Defender XDR Advanced Hunting — KQL Library

**Microsoft Defender XDR Advanced Hunting queries for threat hunting, incident response, and security posture reviews.**
MDO · MDE · MDI · MDCA · Cross-Pillar XDR Kill Chains

> Platform: `security.microsoft.com` → Hunting → Advanced Hunting  
> Requires: Microsoft 365 E5 or Defender XDR standalone licensing  
> Access: Security Reader minimum for Advanced Hunting  

---

## ✅ Validation

All **74 queries** are semantically validated with Microsoft's Kusto language parser (`Kusto.Language`) against the Defender XDR table schemas published on Microsoft Learn. The check covers every table, column, function, and type. `ActionType` values are cross-checked against Microsoft's documented examples. Where Microsoft doesn't document an exact string, queries use tolerant matching (`startswith` / `contains`) instead of guessing.

Re-run the check yourself (Node.js 18+):

```bash
cd tools/kql-validate
npm install
node check.js ../../queries      # add -v to show warnings
```

> ⚠️ **`AADSignInEventsBeta` is deprecated on 19 Oct 2026.** This library uses its replacement, **`EntraIdSignInEvents`**. If your tenant doesn't have it yet, swap the table name back — the columns used here exist in both, except `RiskLevelDuringSignIn`, which only `EntraIdSignInEvents` has.

---

## 📁 Query Index

### Email / MDO — `queries/email/MDO-Email-BEC-Spam-SafeLinks.kql`

| # | Query | Table |
|---|---|---|
| 1.1 | Top spam sources (7d) | `EmailEvents` |
| 1.2 | High-risk recipients by phishing volume | `EmailEvents` |
| 1.3 | Phishing campaign clustering by subject | `EmailEvents` |
| 1.4 | High-volume outbound send anomaly (BEC prep) | `EmailEvents` |
| 1.5 | Phishing block rate by detection type (posture) | `EmailEvents` |
| 2.1 | Display name spoofing / exec impersonation | `EmailEvents` |
| 2.2 | Wire/payment/ACH keywords in inbound mail | `EmailEvents` |
| 2.3 | Lookalike domain regex detection (typosquatting) | `EmailEvents` |
| 3.1 | Inbox rule creation/modification (parameters flattened) | `CloudAppEvents` |
| 3.2 | Suspicious inbox rules (forward / redirect / delete / hide) | `CloudAppEvents` |
| 3.3 | Mailbox-level forwarding changes (Set-Mailbox) | `CloudAppEvents` |
| 3.4 | IR: Mailbox rule changes flagged from risky sign-in IPs | `EntraIdSignInEvents`, `CloudAppEvents` |
| 4.1 | SafeLinks blocked click trends (posture) | `UrlClickEvents` |
| 4.2 | IR: URL click investigation for an IOC domain | `UrlClickEvents` |
| 4.3 | IR: URL to email delivery correlation | `EmailUrlInfo`, `EmailEvents` |
| 5.1 | ZAP effectiveness by day | `EmailPostDeliveryEvents` |
| 5.2 | Malicious attachment evasion pattern | `EmailAttachmentInfo` |

---

### Endpoint / MDE — `queries/endpoint/MDE-Process-Network-Persistence.kql`

| # | Query | Table |
|---|---|---|
| 1.1 | LOLBIN execution from Office apps | `DeviceProcessEvents` |
| 1.2 | PowerShell base64 encoded command (with decode) | `DeviceProcessEvents` |
| 1.3 | Recon command burst (3+ per hour) | `DeviceProcessEvents` |
| 1.4 | PsExec / remote execution tool usage | `DeviceProcessEvents` |
| 1.5 | Rare process from user-writable paths | `DeviceProcessEvents` |
| 1.6 | LSASS access (credential dumping) | `DeviceEvents` |
| 1.7 | VSS / shadow copy / backup deletion | `DeviceProcessEvents` |
| 1.8 | Mass file rename to new extension (ransomware) | `DeviceFileEvents` |
| 2.1 | Outbound connections to rare public destinations | `DeviceNetworkEvents` |
| 2.2 | Beaconing / DGA-style subdomain pattern | `DeviceNetworkEvents` |
| 2.3 | SMB fan-out (port 445, 5+ targets/hr) | `DeviceNetworkEvents` |
| 2.4 | RDP fan-out (port 3389, 3+ targets/hr) | `DeviceNetworkEvents` |
| 2.5 | IR: Multi-table IP IOC hunt (custom detection compatible) | `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `DeviceEvents` |
| 2.6 | IR: Device network activity for an IOC domain | `DeviceNetworkEvents` |
| 3.1 | Scheduled task creation | `DeviceProcessEvents`, `DeviceEvents` |
| 3.2 | Registry Run/RunOnce key modifications | `DeviceRegistryEvents` |
| 3.3 | New service installation | `DeviceEvents` |

---

### Identity / MDI — `queries/identity/MDI-Lateral-Movement-Recon.kql`

| # | Query | Table |
|---|---|---|
| 1.1 | Failed sign-ins by account (>5 in 7d) | `IdentityLogonEvents` |
| 1.2 | Successful sign-ins from a new location | `IdentityLogonEvents` |
| 1.3 | Legacy auth sign-ins (IMAP/POP/SMTP/EAS…) | `EntraIdSignInEvents` |
| 1.4 | Sign-ins outside business hours | `IdentityLogonEvents` |
| 1.5 | Token theft indicator (3+ countries / 10+ IPs) | `EntraIdSignInEvents` |
| 1.6 | Password spray (10+ accounts from one IP per hour) | `IdentityLogonEvents` |
| 1.7 | Brute force single account (10+ failures per 15m) | `IdentityLogonEvents` |
| 1.8 | Successful logon after multiple failures | `IdentityLogonEvents` |
| 1.9 | Dormant account suddenly active | `IdentityLogonEvents` |
| 1.10 | Device registration from IP not seen in 29 days | `EntraIdSignInEvents` |
| 2.1 | LDAP bulk enumeration (50+ queries/hr) | `IdentityQueryEvents` |
| 2.2 | SAMR enumeration (net user / net group recon) | `IdentityQueryEvents` |
| 2.3 | Privileged group enumeration (LDAP / SAMR) | `IdentityQueryEvents` |
| 3.1 | Directory replication (DCSync) by non-sync account | `IdentityDirectoryEvents` |
| 3.2 | AdminSDHolder modification (ACL persistence) | `IdentityDirectoryEvents` |
| 3.3 | Built-in privileged group membership changes | `IdentityDirectoryEvents` |
| 3.4 | Custom sensitive group changes | `IdentityDirectoryEvents` |
| 3.5 | Entra ID role assignment changes (incl. PIM) | `CloudAppEvents` |
| 4.1 | NTLM logon fan-out (Pass-the-Hash indicator) | `IdentityLogonEvents` |
| 4.2 | Kerberoasting recon — LDAP SPN searches | `IdentityQueryEvents` |
| 4.3 | Impossible travel (2+ locations in 4 hours) | `IdentityLogonEvents` |

---

### Cloud Apps / MDCA — `queries/cloud-apps/MDCA-OAuth-Exfil-ShadowIT.kql`

| # | Query | Table |
|---|---|---|
| 1.1 | High-privilege OAuth app consent events | `CloudAppEvents` |
| 1.2 | OAuth app granted tenant-wide admin consent | `CloudAppEvents` |
| 1.3 | Same user + app signing in from 3+ countries | `EntraIdSignInEvents` |
| 2.1 | Bulk SharePoint/OneDrive download (100+ files or 100MB/hr) | `CloudAppEvents` |
| 2.2 | External / guest sharing and anonymous links | `CloudAppEvents` |
| 2.3 | Personal cloud storage access from endpoints | `DeviceNetworkEvents` |
| 3.1 | Impossible travel (3+ countries in 6h window) | `EntraIdSignInEvents` |
| 3.2 | Activity from anonymous proxy / Tor / botnet IPs | `CloudAppEvents` |
| 3.3 | First access to a cloud app by user (30d window) | `CloudAppEvents` |
| 4.1 | Privileged directory changes outside business hours | `CloudAppEvents` |
| 4.2 | Bulk user account operations (10+ ops/hr) | `CloudAppEvents` |
| 4.3 | Mailbox bulk deletion anomaly | `CloudAppEvents` |

---

### Cross-Pillar XDR Kill Chains — `queries/cross-pillar/XDR-Correlation-Playbook.kql`

| # | Scenario | Tables |
|---|---|---|
| C1 | BEC: phish delivered → click-through → suspicious inbox rule | `EmailEvents`, `UrlClickEvents`, `CloudAppEvents` |
| C2 | Account takeover: risky sign-in → cloud activity burst | `EntraIdSignInEvents`, `CloudAppEvents` |
| C3 | NTLM logon → SMB → remote execution on target | `IdentityLogonEvents`, `DeviceNetworkEvents`, `DeviceProcessEvents` |
| C4 | Credential dump → AD recon → lateral logons | `DeviceEvents`, `IdentityQueryEvents`, `IdentityLogonEvents` |
| C5 | Insider: bulk download + external share (same day) | `CloudAppEvents` |
| C6 | Ransomware: shadow delete → mass rename (+ phish flag) | `EmailEvents`, `DeviceProcessEvents`, `DeviceFileEvents` |
| C7 | Multi-product alert convergence on one entity | `AlertInfo`, `AlertEvidence` |

---

## 🚀 Usage

### Microsoft Defender XDR (Portal)
1. Open [security.microsoft.com](https://security.microsoft.com)
2. Go to **Hunting → Advanced Hunting**
3. Paste a single query — each is self-contained with `let` variables at the top
4. Adjust `ago()` lookback windows and environment-specific values as noted in comments

### Customization Points
Each query marks environment-specific values with inline comments:
- `// replace with your domain`
- `// replace with IOC`
- `// populate per environment`
- `// customize`

### Important Notes
- Run queries **one at a time** — highlight a single query before running. Each `let` block is scoped to one query.
- **`CloudAppEvents` has no `AccountUpn` column.** For Microsoft 365 events the UPN is `RawEventData.UserId`; queries extend `AccountUpn` from it. Use `AccountObjectId` for joins.
- Timestamps are **UTC**. Adjust the business-hours windows (identity 1.4, MDCA 4.1) for your time zone.
- Maximum lookback in Advanced Hunting is **30 days** for most tables.
- MDE queries return `DeviceId` + `ReportId` where practical, so they can become custom detection rules.
- `IsAnonymousProxy` / `IPTags` (MDCA 3.2) require Defender for Cloud Apps with the Microsoft 365 app connector.

---

## 📋 Prerequisites
- Microsoft 365 E5 or Defender XDR standalone licenses
- Advanced Hunting access (Security Reader minimum)
- Microsoft Entra ID P2 for `EntraIdSignInEvents`
- Defender for Cloud Apps with the Microsoft 365 connector (Microsoft 365 activities) for `CloudAppEvents`
- Defender for Identity sensors on domain controllers for `Identity*` tables

---

## 🔄 Version History

| Version | Date | Changes |
|---|---|---|
| v1.0 | Feb 2025 | Initial MDO queries (13 queries) |
| v2.0 | Mar 2026 | Added BEC, inbox rules, MSAL auth, ZAP, SafeLinks |
| v2.1 | Mar 2026 | Added MDE, MDI, MDCA, cross-pillar XDR kill chains |
| v3.0 | Mar 2026 | Full refresh — all queries consolidated, IR queries added, kill chains updated |
| v3.1 | Sep 2026 | Parser-validated against Microsoft Learn schemas. Fixed 26 queries with schema errors (e.g. `AccountUpn` on `CloudAppEvents`, `BytesSent`, `TargetObjectName`) and many silent logic bugs (wrong `ActionType` strings, inbox-rule parameter parsing, backwards joins, `DeviceRegistryEvents`). Migrated to `EntraIdSignInEvents`. |

---

*Maintained by [Kevin2083](https://github.com/Kevin2083). Queries are provided as-is — validate in your environment before use.*
