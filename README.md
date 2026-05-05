# PSSecurityAudit

A read-only PowerShell security auditing tool for Windows endpoints and member servers. Produces a self-contained HTML report covering the misconfigurations that show up most often in real engagements: open shares, weak password policy, risky services, stale Active Directory accounts, missing patches, firewall state, and audit-policy gaps.

Built to be **safe to run anywhere**: zero remediation actions, zero external dependencies, single file.

![Risk Badge](https://img.shields.io/badge/risk-read--only-2ea043) ![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE) ![License](https://img.shields.io/badge/license-MIT-blue) ![Status](https://img.shields.io/badge/status-stable-success)

---

## Why this exists

Most security baselines (CIS, STIG, NIST 800-53) are dense PDFs. Practitioners — sysadmins, junior security analysts, government IT staff — need a fast pulse-check before they dig into a full benchmark scan. PSSecurityAudit gives them a 30-second snapshot in a format they can hand to a manager.

It complements (not replaces) tools like **CIS-CAT**, **Microsoft Security Compliance Toolkit**, or **PingCastle**. Use it for triage; use those for compliance.

---

## What it checks

| Category | Checks |
|---|---|
| **SMB Shares** | Non-default shares with Everyone / Authenticated Users / BUILTIN\Users grants |
| **Password Policy** | Min length < 14, complexity disabled, lockout disabled, max age extremes, local accounts without password requirement, PasswordNeverExpires |
| **Services** | Risky services running (Telnet, RemoteRegistry, SNMP, SSDP, UPnP, Browser, Fax, etc.) |
| **SMBv1** | Protocol enable state (EternalBlue / MS17-010 vector) |
| **Firewall** | Each profile (Domain / Private / Public) enabled state |
| **Privilege** | Local Administrators group membership and size |
| **Logging** | Advanced audit policy subcategories set to "No Auditing" |
| **Patching** | Pending Windows Updates (best-effort via Microsoft.Update.Session COM) |
| **Active Directory** *(if RSAT present)* | Stale enabled users, stale enabled computers, users with PasswordNeverExpires |

Every finding has a **severity**, a **detail line**, and a **specific remediation command or pointer** when applicable.

---

## Quick start

```powershell
# From an elevated PowerShell session
.\src\Invoke-SecurityAudit.ps1
```

The script writes `SecurityAudit_<HOSTNAME>_<TIMESTAMP>.html` to the current directory and prints a summary line.

### Common options

```powershell
# Custom output path
.\Invoke-SecurityAudit.ps1 -OutputPath C:\Reports\baseline.html

# Stricter stale-account threshold (default 90 days)
.\Invoke-SecurityAudit.ps1 -StaleAccountDays 60

# Skip AD checks even on a domain-joined host
.\Invoke-SecurityAudit.ps1 -SkipAD

# Include full running-services inventory in the report
.\Invoke-SecurityAudit.ps1 -IncludeServices
```

### Requirements

- Windows 10 / Server 2016 or newer
- PowerShell 5.1+ (works in PowerShell 7)
- Administrator rights for complete results (script runs without admin but flags itself in the report)
- *Optional:* RSAT `ActiveDirectory` module for AD checks

---

## Sample output

The HTML report opens in any browser and contains:

1. **Header** — hostname, OS, timestamp, run duration, elevation status
2. **Composite Risk Score** — weighted 0–100 with band (LOW / MODERATE / ELEVATED / CRITICAL)
3. **Severity tile counts** — Critical / High / Medium / Low / Info / Pass
4. **Findings grouped by category** — sortable table per section with severity badge, finding, detail, and recommendation

A redacted example report is checked in at [`examples/sample-report.html`](examples/sample-report.html).

### Risk score formula

```
weight     = (Critical × 10) + (High × 5) + (Medium × 2) + (Low × 1)
maxRef     = max(totalFindings × 3, 20)
riskScore  = min(100, round(weight / maxRef × 100))
```

This produces a stable 0–100 number that scales with both the count and the severity of findings, while not punishing small environments with few results.

---

## Output schema

If you want to consume findings programmatically instead of via HTML, the easiest path is to dot-source the script's checks into your own wrapper. Each finding is a `pscustomobject` with:

```
Category       string  e.g. 'SMB Shares', 'Password Policy', 'Active Directory'
Severity       string  Critical | High | Medium | Low | Info | Pass
Title          string  Short, human-readable
Detail         string  Optional longer context
Recommendation string  Optional specific remediation
```

A future release will add `-OutputJson` and `-OutputCsv` switches; PRs welcome.

---

## Safety guarantees

- **Read-only.** The script never sets a registry value, modifies a service, changes a policy, or writes anywhere except the output HTML file.
- **No network calls** other than the local Windows Update COM query (which talks to the configured WSUS / Microsoft endpoint your machine already uses).
- **No telemetry.** Nothing is uploaded anywhere.
- All AD queries are filtered for **enabled** accounts to avoid surfacing already-disabled noise.

You can audit the script yourself — it is one file, ~600 lines, no obfuscation.

---

## Limitations and honest caveats

- The pending-updates check uses the Windows Update COM API, which can be slow or fail on machines with broken WU clients. A failure is reported as `Info`, not as `Pass`.
- The "risky services" list is opinionated. If you have a documented business need for SNMP or RemoteRegistry, treat that finding as informational.
- AD stale-account detection uses `LastLogonDate` (replicated `lastLogonTimestamp`), which is accurate to within ~14 days. For precise data, query `lastLogon` on each DC.
- This is **not a CIS Benchmark scan** and not a substitute for one. It hits roughly 15–20 of the controls a full benchmark covers.
- Tested against Windows Server 2019, Windows Server 2022, and Windows 11. Older versions (Windows 7 / Server 2012) may have missing cmdlets (`Get-LocalUser`, `Get-SmbServerConfiguration`); those checks degrade gracefully to `Info`.

---

## Repository layout

```
PSSecurityAudit/
├── src/
│   └── Invoke-SecurityAudit.ps1        # The script
├── docs/
│   ├── CHECKS.md                       # What each check looks for and why
│   └── INTERPRETING-RESULTS.md         # How to triage findings
├── examples/
│   └── sample-report.html              # Example output (redacted)
├── .github/
│   └── workflows/
│       └── lint.yml                    # PSScriptAnalyzer CI
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── README.md
```

---

## Contributing

PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). The two highest-value additions right now:

1. JSON / CSV output switches
2. Additional checks (LSA Protection, LDAP signing, NTLM auditing, WDigest, PowerShell logging)

Run `Invoke-ScriptAnalyzer -Path .\src\` before submitting; CI will run it too.

---

## License

[MIT](LICENSE) — use it, fork it, ship it inside your org's tooling. Attribution appreciated, not required.

---

## Disclaimer

This tool is provided as-is for defensive security and configuration review. Run it only on systems you are authorized to assess. Findings are advisory; validate against your organization's policies before remediation.
