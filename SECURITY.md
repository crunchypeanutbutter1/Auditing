# Security Policy

## Reporting a vulnerability

If you find a bug in PSSecurityAudit that could:

- Cause the script to **modify** the system (it should never write outside the output HTML file), or
- Cause the script to **transmit data** off the host, or
- Cause it to **execute attacker-controlled input**

…please report it privately via GitHub's "Report a vulnerability" feature on the Security tab, **not** via a public issue.

For non-security bugs, open a normal issue.

## Threat model

- **In scope:** the script itself, the HTML report it generates, defaults that are insecure, claims that are wrong.
- **Out of scope:** vulnerabilities in Windows, the ActiveDirectory module, or any service the script enumerates. Those go to MSRC.

## What this tool is not

This is a **defensive configuration auditor**. It is not:
- A vulnerability scanner (no CVE lookups)
- A penetration testing tool (no exploitation)
- An EDR (no behavioral detection)
- A compliance attestation tool (no benchmark scoring)

Do not run this on systems you do not own or have explicit permission to assess.

## Supply chain

The script has no runtime dependencies outside Windows + RSAT. CI uses pinned major versions of `actions/checkout` and the `microsoft/psscriptanalyzer-action`. The repo has Dependabot enabled for GitHub Actions.
