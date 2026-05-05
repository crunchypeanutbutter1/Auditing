# Checks Reference

Each check, what it tests, why it matters, and the authoritative source where applicable.

---

## SMB Shares

**What:** Enumerates non-default shares (`Get-SmbShare`) and inspects their ACL (`Get-SmbShareAccess`) for `Everyone`, `BUILTIN\Users`, or `NT AUTHORITY\Authenticated Users` Allow grants.

**Why:** Open shares are the single most common path for ransomware lateral movement and accidental data exposure. The default admin shares (`ADMIN$`, `C$`, `IPC$`) are intentionally excluded — they are gated by SMB authentication.

**Severity:** High when broad principals are granted; Pass otherwise.

**Reference:** CIS Microsoft Windows Server Benchmark — section 2.3.10 (Network access policies).

---

## Password Policy

**What:** Exports the local security policy with `secedit /export` and parses these values:

- `MinimumPasswordLength` — flagged High if < 14
- `PasswordComplexity` — flagged High if disabled
- `LockoutBadCount` — flagged High if 0 (disabled)
- `MaximumPasswordAge` — flagged Medium if 0 or > 365
- Local users without `PasswordRequired` — flagged Critical
- Local users with `PasswordNeverExpires` — flagged Medium

**Why:** Local accounts on member servers are frequently overlooked and inherit the local SAM policy, not domain GPO. A no-password local admin account on one server is a domain compromise away.

**References:**
- NIST SP 800-63B §5.1.1 — minimum length 8, recommended 14+ for sensitive accounts
- CIS Benchmark §1.1 — Account Policies
- DISA STIG WN10-AC-000005 through WN10-AC-000035

---

## Services

**What:** Compares running services against an opinionated risky-list and flags matches as Medium.

| Service | Risk |
|---|---|
| `Telnet`, `TlntSvr` | Cleartext credentials and shell traffic |
| `RemoteRegistry` | Lateral movement and persistence aid |
| `SNMP` | Default community strings (`public`/`private`) common |
| `SSDPSRV`, `upnphost` | UPnP exposure on routable interfaces |
| `Browser` | Legacy NetBIOS — not needed on modern networks |
| `Fax`, `WMPNetworkSvc`, `XblAuthManager`, `lfsvc` | Attack surface with no business need on most servers |

Also checks **SMBv1** (`Get-SmbServerConfiguration -EnableSMB1Protocol`). Flagged Critical if enabled.

**Why:** Each unnecessary service is an attack-surface tax. SMBv1 specifically was the vehicle for WannaCry / NotPetya (MS17-010, EternalBlue).

---

## Firewall

**What:** Iterates `Get-NetFirewallProfile` and flags any profile (`Domain`, `Private`, `Public`) where `Enabled` is `False`.

**Why:** A disabled host firewall removes a critical defense-in-depth layer. The Public profile in particular should always be enabled — it's what guards a laptop on a hotel network.

---

## Privilege

**What:** Lists `Get-LocalGroupMember -Group Administrators`. Flagged Medium when membership exceeds 5 entries.

**Why:** Local admin sprawl makes incident response significantly harder and expands credential-theft blast radius. Use **LAPS** (Local Administrator Password Solution) and remove standing local admin from interactive users where possible.

**Reference:** Microsoft "Securing Privileged Access" reference architecture.

---

## Logging

**What:** Runs `auditpol /get /category:*` and counts subcategories set to "No Auditing".

**Why:** You cannot investigate what you do not log. The minimum viable set includes Logon, Account Logon, Account Management, Privilege Use, and Object Access (Removable Storage at minimum).

**Reference:** Microsoft "Audit Policy Recommendations" and CIS Benchmark §17 (Advanced Audit Policy Configuration).

---

## Patching

**What:** Uses the `Microsoft.Update.Session` COM object to query for updates where `IsInstalled=0 and IsHidden=0`. Reports the count and the first 5 titles.

**Why:** Unpatched software is the #1 vector across most threat reports (Verizon DBIR, M-Trends).

**Caveats:** This check can be slow (10–60 seconds) and depends on a healthy Windows Update client. A failure is reported as Info, never as Pass.

---

## Active Directory (optional)

Only runs when the `ActiveDirectory` module is available (RSAT installed) and `-SkipAD` is not specified.

### Stale users

`Get-ADUser -Filter { Enabled -eq $true }` filtered by `LastLogonDate < (today - StaleAccountDays)`. Flagged High.

### Stale computers

Same logic against `Get-ADComputer`. Flagged Medium.

### PasswordNeverExpires users

`Get-ADUser -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $true }`. Flagged Medium.

**Why:** Stale accounts accumulate silently. They keep group memberships, often have weak or unrotated passwords, and rarely have MFA. Threat actors love them. Disabling > deleting (preserves the SID for forensics).

**Reference:** Microsoft "AD Tier Model" guidance; PingCastle scoring model.

---

## Severity rubric

| Severity | Meaning |
|---|---|
| **Critical** | Active vulnerability or no-credential access path. Fix in days. |
| **High** | Misconfiguration meaningfully increases compromise likelihood. Fix in weeks. |
| **Medium** | Hardening gap or attack-surface excess. Fix in next maintenance window. |
| **Low** | Minor deviation from best practice. |
| **Info** | Context only — no action implied. |
| **Pass** | Check ran and found the configuration in good shape. |
