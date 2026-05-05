# Interpreting Results

A short field guide for triaging the report.

## Read the score, then ignore it

The composite risk score is useful for trending the same host over time. It is **not** a comparable metric across hosts of different roles — a domain controller with 3 Highs is in much worse shape than a workstation with 3 Highs. Always read the actual findings.

## Triage order

1. **Critical first, always.** A no-password local account or SMBv1 enabled is an emergency. Don't move on until those are remediated or have a documented compensating control with a sunset date.
2. **High findings on internet-exposed or high-value hosts.** A high-severity finding on a print server matters less than the same finding on a jump box.
3. **Mediums in batches.** Group them by category and address them in a single change window — don't death-by-a-thousand-cuts your change board.
4. **Info / Pass.** Skim for context. Pass entries are useful when you need to prove to an auditor that something *was* checked.

## Common false positives

| Finding | When to dismiss |
|---|---|
| "Risky service `RemoteRegistry` is running" | If you actively manage the box with SCCM/Intune/Tanium and have the service ACL'd to specific admin groups. |
| "Local Administrators group has > 5 members" | If the extras are well-known admin **groups** (e.g. `Domain Admins`, a tier-0 break-glass group). The check counts entries, not effective users. |
| "Pending Windows updates" | Immediately after a planned reboot is scheduled. Note it in your change record. |
| "PasswordNeverExpires" on AD users | Service accounts protected by gMSA equivalents or vaulted in PAM. Document and move on. |

## What this report does NOT prove

- **It does not prove compliance.** STIG / CIS compliance requires a benchmarked tool (CIS-CAT, SCAP, STIG Viewer + checklist).
- **It does not prove absence of compromise.** A clean report means the configuration baseline is reasonable, not that the host hasn't been touched. Pair with EDR telemetry review.
- **It does not cover application-layer issues.** No web-app, database, or AD-CS misconfig checks here. Different tools.

## Suggested cadence

- **Workstations:** monthly, or after major OS upgrades.
- **Member servers:** weekly to monthly.
- **Domain controllers:** weekly. Combine with **PingCastle** for richer AD-tier analysis.

## Pairing with other tools

| Tool | Why it pairs well |
|---|---|
| **PingCastle** | Deep AD risk model — covers Kerberoast surface, trust risks, etc. |
| **CIS-CAT Pro / Lite** | Authoritative CIS benchmark scoring. |
| **Microsoft Security Compliance Toolkit + Policy Analyzer** | Compares your GPOs against Microsoft baselines. |
| **Sysinternals AccessChk** | Drill into any share or registry ACL flagged here. |
| **Defender for Endpoint Secure Score** | Cloud-side aggregated view if you have E5. |

PSSecurityAudit's job is to be the **fast first pass** that tells you whether to bother running the heavyweights.
