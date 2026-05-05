# Contributing

Thanks for contributing. This project stays intentionally small: one script, focused scope.

## Ground rules

1. **Read-only stays read-only.** No PR will be merged that adds a remediation action to the main script. A separate `Repair-*` companion is welcome but must live in its own file with explicit `-Confirm` semantics.
2. **No external module dependencies.** The whole point is "drop on a box and run." If a check needs a module beyond what ships with Windows + RSAT, it doesn't belong here.
3. **Every finding needs `Title`, `Severity`, and (when actionable) `Recommendation`.** Findings without a remediation pointer are hard to action during incident response.

## Local development

```powershell
# Install the linter once
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force

# Run before every commit
Invoke-ScriptAnalyzer -Path .\src\Invoke-SecurityAudit.ps1 -Severity Warning,Error
```

CI runs the same command on push; warnings will fail the build.

## Adding a check

1. Add a new `#region` block in `Invoke-SecurityAudit.ps1`.
2. Wrap risky calls in `try/catch` and emit an `Info` finding on failure — one broken check should never stop the whole run.
3. Pick a severity using the rubric in [`docs/CHECKS.md`](docs/CHECKS.md). When in doubt, go one level lower.
4. Update `docs/CHECKS.md` with the check name, what it tests, why it matters, and a reference (CIS, NIST, STIG ID).
5. Update the README's "What it checks" table.

## Severity discipline

We deliberately bias *down*. A noisy report nobody reads is worse than a quiet one that flags only real issues. If your check is going to fire on most healthy hosts, it's probably an `Info`, not a `Medium`.

## Pull request checklist

- [ ] PSScriptAnalyzer clean
- [ ] New/changed checks documented in `docs/CHECKS.md`
- [ ] README "What it checks" table updated
- [ ] Tested on at least one Windows 10/11 and one Windows Server build
- [ ] No new dependencies on third-party modules
