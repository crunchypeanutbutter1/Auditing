<#
.SYNOPSIS
    Audits a Windows machine for common security misconfigurations and outputs an HTML report.

.DESCRIPTION
    Invoke-SecurityAudit performs read-only security checks against a local Windows host
    (and optionally Active Directory) covering:
      - Open / unrestricted SMB shares
      - Local account password policy weaknesses
      - Unnecessary or risky running services
      - Stale Active Directory user and computer accounts (when AD module available)
      - Firewall profile state
      - SMBv1 protocol status
      - Pending Windows updates (best-effort)
      - Local administrators group membership
      - Audit policy basics

    Results are written to a self-contained HTML report. No data leaves the machine.

.PARAMETER OutputPath
    Path to write the HTML report. Defaults to .\SecurityAudit_<hostname>_<timestamp>.html

.PARAMETER StaleAccountDays
    Number of days of inactivity before an AD account is flagged as stale. Default: 90.

.PARAMETER SkipAD
    Skip Active Directory checks even if the ActiveDirectory module is available.

.PARAMETER IncludeServices
    Include the full running-services inventory in the report (large output).

.EXAMPLE
    .\Invoke-SecurityAudit.ps1

.EXAMPLE
    .\Invoke-SecurityAudit.ps1 -OutputPath C:\Reports\audit.html -StaleAccountDays 60

.NOTES
    Author : PSSecurityAudit project
    License: MIT
    Run as Administrator for complete results. Read-only — performs no remediation.
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [int]$StaleAccountDays = 90,
    [switch]$SkipAD,
    [switch]$IncludeServices
)

#region --- Setup ---------------------------------------------------------------

$ErrorActionPreference = 'Continue'
$script:Findings = [System.Collections.Generic.List[object]]::new()
$script:StartTime = Get-Date
$Hostname = $env:COMPUTERNAME

if (-not $OutputPath) {
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutputPath = Join-Path -Path (Get-Location) -ChildPath "SecurityAudit_${Hostname}_${stamp}.html"
}

function Add-Finding {
    param(
        [Parameter(Mandatory)] [string]$Category,
        [Parameter(Mandatory)] [ValidateSet('Critical','High','Medium','Low','Info','Pass')] [string]$Severity,
        [Parameter(Mandatory)] [string]$Title,
        [string]$Detail,
        [string]$Recommendation
    )
    $script:Findings.Add([pscustomobject]@{
        Category       = $Category
        Severity       = $Severity
        Title          = $Title
        Detail         = $Detail
        Recommendation = $Recommendation
    })
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$IsAdmin = Test-IsAdmin
if (-not $IsAdmin) {
    Write-Warning "Not running as Administrator — some checks will be skipped or incomplete."
    Add-Finding -Category 'Audit Context' -Severity 'Info' -Title 'Audit not run as Administrator' `
        -Detail 'Several checks require elevation. Re-run from an elevated PowerShell session for complete results.' `
        -Recommendation 'Right-click PowerShell -> Run as Administrator, then re-run this script.'
}

Write-Host "[*] Running security audit on $Hostname ..." -ForegroundColor Cyan

#endregion

#region --- Check: SMB Shares ---------------------------------------------------

Write-Host "  [+] Checking SMB shares..." -ForegroundColor Gray
try {
    $shares = Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '\$$' -or $_.Name -in 'ADMIN$','C$','IPC$' }
    foreach ($s in $shares) {
        # Skip the default admin shares from "open" detection but still record
        if ($s.Name -in 'ADMIN$','C$','IPC$') { continue }

        try {
            $access = Get-SmbShareAccess -Name $s.Name -ErrorAction Stop
            $everyone = $access | Where-Object { $_.AccountName -in 'Everyone','BUILTIN\Users','NT AUTHORITY\Authenticated Users' -and $_.AccessControlType -eq 'Allow' }
            if ($everyone) {
                $perms = ($everyone | ForEach-Object { "$($_.AccountName)=$($_.AccessRight)" }) -join '; '
                Add-Finding -Category 'SMB Shares' -Severity 'High' `
                    -Title "Share '$($s.Name)' grants access to broad principals" `
                    -Detail "Path: $($s.Path) | Access: $perms" `
                    -Recommendation 'Replace Everyone/Authenticated Users grants with specific groups following least-privilege.'
            } else {
                Add-Finding -Category 'SMB Shares' -Severity 'Pass' `
                    -Title "Share '$($s.Name)' has restricted ACL" `
                    -Detail "Path: $($s.Path)"
            }
        } catch {
            Add-Finding -Category 'SMB Shares' -Severity 'Info' `
                -Title "Could not enumerate ACL for '$($s.Name)'" -Detail $_.Exception.Message
        }
    }
    if (-not $shares) {
        Add-Finding -Category 'SMB Shares' -Severity 'Pass' -Title 'No non-default SMB shares present'
    }
} catch {
    Add-Finding -Category 'SMB Shares' -Severity 'Info' -Title 'SMB share enumeration failed' -Detail $_.Exception.Message
}

#endregion

#region --- Check: Local Password Policy ----------------------------------------

Write-Host "  [+] Checking local password policy..." -ForegroundColor Gray
try {
    $tmp = [System.IO.Path]::GetTempFileName()
    $null = secedit /export /cfg $tmp /quiet
    $cfg = Get-Content $tmp -ErrorAction Stop
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue

    $policy = @{}
    foreach ($line in $cfg) {
        if ($line -match '^(MinimumPasswordLength|PasswordComplexity|MaximumPasswordAge|MinimumPasswordAge|PasswordHistorySize|LockoutBadCount|LockoutDuration)\s*=\s*(.+)$') {
            $policy[$matches[1]] = $matches[2].Trim()
        }
    }

    if ($policy.MinimumPasswordLength) {
        $len = [int]$policy.MinimumPasswordLength
        if ($len -lt 14) {
            Add-Finding -Category 'Password Policy' -Severity 'High' `
                -Title "Minimum password length is $len" `
                -Detail 'NIST and CIS recommend a minimum of 14 characters for standard accounts.' `
                -Recommendation 'Set Minimum Password Length to 14 or higher via Group Policy or secedit.'
        } else {
            Add-Finding -Category 'Password Policy' -Severity 'Pass' -Title "Minimum password length is $len (>= 14)"
        }
    }

    if ($policy.PasswordComplexity -eq '0') {
        Add-Finding -Category 'Password Policy' -Severity 'High' -Title 'Password complexity is disabled' `
            -Recommendation 'Enable "Password must meet complexity requirements" in local/group policy.'
    } elseif ($policy.PasswordComplexity -eq '1') {
        Add-Finding -Category 'Password Policy' -Severity 'Pass' -Title 'Password complexity is enabled'
    }

    if ($policy.LockoutBadCount -eq '0') {
        Add-Finding -Category 'Password Policy' -Severity 'High' -Title 'Account lockout is disabled' `
            -Detail 'Bad logon threshold = 0 means accounts will never lock out, allowing unlimited brute-force attempts.' `
            -Recommendation 'Set Account Lockout Threshold to 5–10 invalid attempts.'
    } elseif ($policy.LockoutBadCount) {
        Add-Finding -Category 'Password Policy' -Severity 'Pass' -Title "Account lockout threshold = $($policy.LockoutBadCount)"
    }

    if ($policy.MaximumPasswordAge) {
        $age = [int]$policy.MaximumPasswordAge
        if ($age -eq 0 -or $age -gt 365) {
            Add-Finding -Category 'Password Policy' -Severity 'Medium' `
                -Title "Maximum password age is $age days" `
                -Recommendation 'Modern guidance favors long-lived strong passphrases with breach monitoring; pair this with MFA.'
        }
    }
} catch {
    Add-Finding -Category 'Password Policy' -Severity 'Info' -Title 'Could not export local security policy' `
        -Detail $_.Exception.Message -Recommendation 'Run as Administrator.'
}

# Local accounts with weak settings
try {
    $localUsers = Get-LocalUser -ErrorAction Stop
    foreach ($u in $localUsers) {
        if ($u.Enabled -and -not $u.PasswordRequired) {
            Add-Finding -Category 'Password Policy' -Severity 'Critical' `
                -Title "Local account '$($u.Name)' does not require a password" `
                -Recommendation "Set: Get-LocalUser '$($u.Name)' | Set-LocalUser -PasswordNeverExpires `$false; net user '$($u.Name)' /passwordreq:yes"
        }
        if ($u.Enabled -and $u.PasswordNeverExpires) {
            Add-Finding -Category 'Password Policy' -Severity 'Medium' `
                -Title "Local account '$($u.Name)' is set to never expire password" `
                -Recommendation 'Disable PasswordNeverExpires unless it is a documented service account with compensating controls.'
        }
    }
} catch {
    # Get-LocalUser missing on older Windows; skip silently
}

#endregion

#region --- Check: Risky / Unnecessary Services --------------------------------

Write-Host "  [+] Checking running services..." -ForegroundColor Gray

# Services widely considered risky to leave enabled on a hardened endpoint/server.
$riskyServices = @{
    'Telnet'                 = 'Cleartext remote shell — superseded by SSH.'
    'TlntSvr'                = 'Cleartext Telnet server.'
    'RemoteRegistry'         = 'Allows remote registry editing — common lateral-movement target.'
    'SNMP'                   = 'Often deployed with default community strings (public/private).'
    'SSDPSRV'                = 'SSDP discovery — UPnP exposure vector.'
    'upnphost'               = 'UPnP host — typically unnecessary on servers.'
    'Browser'                = 'Legacy NetBIOS Computer Browser.'
    'Fax'                    = 'Rarely needed; expands attack surface.'
    'XblAuthManager'         = 'Xbox services on a server are unusual.'
    'WMPNetworkSvc'          = 'Windows Media Player network sharing.'
    'lfsvc'                  = 'Geolocation service.'
}

try {
    $services = Get-Service -ErrorAction Stop
    foreach ($name in $riskyServices.Keys) {
        $svc = $services | Where-Object { $_.Name -eq $name }
        if ($svc -and $svc.Status -eq 'Running') {
            Add-Finding -Category 'Services' -Severity 'Medium' `
                -Title "Risky service '$name' is running" `
                -Detail $riskyServices[$name] `
                -Recommendation "If not required: Stop-Service $name; Set-Service $name -StartupType Disabled"
        }
    }

    # SMBv1 — surfaced separately because of WannaCry-class risk
    try {
        $smb1 = Get-SmbServerConfiguration -ErrorAction Stop
        if ($smb1.EnableSMB1Protocol) {
            Add-Finding -Category 'Services' -Severity 'Critical' -Title 'SMBv1 protocol is enabled' `
                -Detail 'SMBv1 has known critical vulnerabilities (e.g. EternalBlue / MS17-010).' `
                -Recommendation 'Disable: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force'
        } else {
            Add-Finding -Category 'Services' -Severity 'Pass' -Title 'SMBv1 protocol is disabled'
        }
    } catch {}

    if ($IncludeServices) {
        $running = $services | Where-Object Status -eq 'Running' | Sort-Object Name
        $list = ($running | ForEach-Object { $_.Name }) -join ', '
        Add-Finding -Category 'Services' -Severity 'Info' -Title "Running services inventory ($($running.Count))" -Detail $list
    }
} catch {
    Add-Finding -Category 'Services' -Severity 'Info' -Title 'Service enumeration failed' -Detail $_.Exception.Message
}

#endregion

#region --- Check: Firewall ----------------------------------------------------

Write-Host "  [+] Checking Windows Firewall..." -ForegroundColor Gray
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    foreach ($p in $profiles) {
        if (-not $p.Enabled) {
            Add-Finding -Category 'Firewall' -Severity 'High' `
                -Title "Firewall profile '$($p.Name)' is disabled" `
                -Recommendation "Enable: Set-NetFirewallProfile -Profile $($p.Name) -Enabled True"
        } else {
            Add-Finding -Category 'Firewall' -Severity 'Pass' -Title "Firewall profile '$($p.Name)' is enabled"
        }
    }
} catch {
    Add-Finding -Category 'Firewall' -Severity 'Info' -Title 'Could not query firewall profiles' -Detail $_.Exception.Message
}

#endregion

#region --- Check: Local Administrators ----------------------------------------

Write-Host "  [+] Checking local Administrators group..." -ForegroundColor Gray
try {
    $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
    $count = ($admins | Measure-Object).Count
    $names = ($admins | ForEach-Object { $_.Name }) -join '; '
    if ($count -gt 5) {
        Add-Finding -Category 'Privilege' -Severity 'Medium' `
            -Title "Local Administrators group has $count members" `
            -Detail $names `
            -Recommendation 'Review membership; remove users that do not require local admin. Prefer LAPS-managed accounts.'
    } else {
        Add-Finding -Category 'Privilege' -Severity 'Info' `
            -Title "Local Administrators members ($count)" -Detail $names
    }
} catch {
    Add-Finding -Category 'Privilege' -Severity 'Info' -Title 'Could not enumerate Administrators group' -Detail $_.Exception.Message
}

#endregion

#region --- Check: Audit Policy ------------------------------------------------

Write-Host "  [+] Checking audit policy..." -ForegroundColor Gray
try {
    $auditOut = auditpol /get /category:* 2>$null
    if ($LASTEXITCODE -eq 0 -and $auditOut) {
        $noAuditing = $auditOut | Select-String -Pattern 'No Auditing'
        if ($noAuditing) {
            Add-Finding -Category 'Logging' -Severity 'Medium' `
                -Title "$($noAuditing.Count) audit subcategories set to 'No Auditing'" `
                -Detail 'Critical events (logon, account management, privilege use) may not be logged.' `
                -Recommendation 'Apply CIS Benchmark advanced audit policy via Group Policy.'
        } else {
            Add-Finding -Category 'Logging' -Severity 'Pass' -Title 'All audit subcategories have auditing configured'
        }
    }
} catch {
    Add-Finding -Category 'Logging' -Severity 'Info' -Title 'Could not query audit policy' -Detail $_.Exception.Message
}

#endregion

#region --- Check: Pending Updates (best-effort) -------------------------------

Write-Host "  [+] Checking for pending updates (best-effort)..." -ForegroundColor Gray
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result   = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    if ($result.Updates.Count -gt 0) {
        $sev = if ($result.Updates.Count -gt 10) { 'High' } else { 'Medium' }
        $titles = ($result.Updates | Select-Object -First 5 | ForEach-Object { $_.Title }) -join ' | '
        Add-Finding -Category 'Patching' -Severity $sev `
            -Title "$($result.Updates.Count) pending Windows updates" `
            -Detail "First 5: $titles" `
            -Recommendation 'Install pending updates and verify automatic update configuration.'
    } else {
        Add-Finding -Category 'Patching' -Severity 'Pass' -Title 'No pending Windows updates detected'
    }
} catch {
    Add-Finding -Category 'Patching' -Severity 'Info' -Title 'Could not query Windows Update' -Detail $_.Exception.Message
}

#endregion

#region --- Check: Active Directory --------------------------------------------

if (-not $SkipAD -and (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "  [+] Checking Active Directory (stale accounts)..." -ForegroundColor Gray
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $cutoff = (Get-Date).AddDays(-$StaleAccountDays)

        $staleUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate, PasswordLastSet -ErrorAction Stop |
            Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $cutoff }
        if ($staleUsers) {
            $sample = ($staleUsers | Select-Object -First 10 | ForEach-Object { "$($_.SamAccountName) (last: $($_.LastLogonDate.ToString('yyyy-MM-dd')))" }) -join '; '
            Add-Finding -Category 'Active Directory' -Severity 'High' `
                -Title "$($staleUsers.Count) enabled AD users inactive > $StaleAccountDays days" `
                -Detail "Sample: $sample" `
                -Recommendation 'Disable or remove stale accounts; consider an automated lifecycle workflow.'
        } else {
            Add-Finding -Category 'Active Directory' -Severity 'Pass' -Title "No stale enabled AD users (> $StaleAccountDays days)"
        }

        $staleComputers = Get-ADComputer -Filter { Enabled -eq $true } -Properties LastLogonDate -ErrorAction Stop |
            Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $cutoff }
        if ($staleComputers) {
            Add-Finding -Category 'Active Directory' -Severity 'Medium' `
                -Title "$($staleComputers.Count) enabled AD computers inactive > $StaleAccountDays days" `
                -Recommendation 'Confirm decommissioning and disable/delete stale computer objects.'
        } else {
            Add-Finding -Category 'Active Directory' -Severity 'Pass' -Title "No stale enabled AD computers (> $StaleAccountDays days)"
        }

        # Users with PasswordNeverExpires
        $pwNeverExp = Get-ADUser -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $true } -ErrorAction Stop
        if ($pwNeverExp) {
            Add-Finding -Category 'Active Directory' -Severity 'Medium' `
                -Title "$(($pwNeverExp | Measure-Object).Count) enabled AD users with PasswordNeverExpires" `
                -Recommendation 'Restrict to documented service accounts; protect with gMSA where possible.'
        }
    } catch {
        Add-Finding -Category 'Active Directory' -Severity 'Info' -Title 'AD checks failed' `
            -Detail $_.Exception.Message -Recommendation 'Run on a domain-joined host with the RSAT AD module and appropriate permissions.'
    }
} else {
    Add-Finding -Category 'Active Directory' -Severity 'Info' `
        -Title 'AD checks skipped' `
        -Detail 'ActiveDirectory module not present or -SkipAD specified.'
}

#endregion

#region --- Build HTML Report --------------------------------------------------

Write-Host "[*] Building HTML report..." -ForegroundColor Cyan

$counts = @{
    Critical = ($script:Findings | Where-Object Severity -eq 'Critical').Count
    High     = ($script:Findings | Where-Object Severity -eq 'High').Count
    Medium   = ($script:Findings | Where-Object Severity -eq 'Medium').Count
    Low      = ($script:Findings | Where-Object Severity -eq 'Low').Count
    Info     = ($script:Findings | Where-Object Severity -eq 'Info').Count
    Pass     = ($script:Findings | Where-Object Severity -eq 'Pass').Count
}
$total    = $script:Findings.Count
$duration = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 1)

# Risk score: weighted, normalized 0-100 (higher = worse)
$weight   = ($counts.Critical * 10) + ($counts.High * 5) + ($counts.Medium * 2) + ($counts.Low * 1)
$maxRef   = [math]::Max($total * 3, 20)
$riskScore = [math]::Min(100, [math]::Round(($weight / $maxRef) * 100))
$riskBand = switch ($riskScore) {
    { $_ -ge 70 } { 'CRITICAL'; break }
    { $_ -ge 40 } { 'ELEVATED'; break }
    { $_ -ge 15 } { 'MODERATE'; break }
    default       { 'LOW' }
}

function HtmlEncode([string]$s) {
    if ($null -eq $s) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($s)
}

# Group findings by category for display
$grouped = $script:Findings | Group-Object Category | Sort-Object Name

$rows = foreach ($g in $grouped) {
    $catRows = foreach ($f in ($g.Group | Sort-Object @{e={
        switch ($_.Severity) { 'Critical' {0} 'High' {1} 'Medium' {2} 'Low' {3} 'Info' {4} 'Pass' {5} }
    }})) {
        @"
      <tr class="sev-$($f.Severity.ToLower())">
        <td class="sev-cell"><span class="badge badge-$($f.Severity.ToLower())">$($f.Severity)</span></td>
        <td class="title-cell">$(HtmlEncode $f.Title)</td>
        <td class="detail-cell">$(HtmlEncode $f.Detail)</td>
        <td class="rec-cell">$(HtmlEncode $f.Recommendation)</td>
      </tr>
"@
    }
    @"
    <section class="cat">
      <h2>$(HtmlEncode $g.Name) <span class="cat-count">$($g.Count)</span></h2>
      <table>
        <thead><tr><th>Severity</th><th>Finding</th><th>Detail</th><th>Recommendation</th></tr></thead>
        <tbody>
$($catRows -join "`n")
        </tbody>
      </table>
    </section>
"@
}

$os = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { 'Unknown' }
$generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Audit Report — $Hostname</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=IBM+Plex+Sans:wght@400;500;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0d1117;
    --panel: #161b22;
    --panel-2: #1c232c;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --accent: #58a6ff;
    --crit: #f85149;
    --high: #ff7b39;
    --med: #d29922;
    --low: #3fb950;
    --info: #58a6ff;
    --pass: #2ea043;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: 'IBM Plex Sans', system-ui, sans-serif;
    line-height: 1.5;
  }
  header {
    border-bottom: 1px solid var(--border);
    padding: 32px 48px;
    background: linear-gradient(180deg, #161b22 0%, #0d1117 100%);
  }
  header h1 {
    font-family: 'JetBrains Mono', monospace;
    margin: 0 0 4px 0;
    font-size: 24px;
    letter-spacing: -0.5px;
  }
  header .sub { color: var(--muted); font-size: 14px; }
  header .meta { margin-top: 16px; display: flex; flex-wrap: wrap; gap: 24px; font-size: 13px; color: var(--muted); }
  header .meta span b { color: var(--text); font-family: 'JetBrains Mono', monospace; }

  .container { padding: 32px 48px; max-width: 1400px; margin: 0 auto; }

  .summary {
    display: grid;
    grid-template-columns: 1.2fr 2fr;
    gap: 24px;
    margin-bottom: 40px;
  }
  .risk-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 28px;
    position: relative;
    overflow: hidden;
  }
  .risk-card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 1.5px; }
  .risk-card .score {
    font-family: 'JetBrains Mono', monospace;
    font-size: 72px;
    font-weight: 700;
    line-height: 1;
    margin: 8px 0;
  }
  .risk-card .band {
    font-family: 'JetBrains Mono', monospace;
    font-size: 16px;
    letter-spacing: 2px;
    padding: 4px 12px;
    border-radius: 4px;
    display: inline-block;
  }
  .band.CRITICAL { background: var(--crit); color: #fff; }
  .band.ELEVATED { background: var(--high); color: #1a0f08; }
  .band.MODERATE { background: var(--med); color: #1f1607; }
  .band.LOW      { background: var(--pass); color: #06200e; }

  .counts-grid {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 12px;
  }
  .count-tile {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px 16px;
    text-align: center;
  }
  .count-tile .num {
    font-family: 'JetBrains Mono', monospace;
    font-size: 36px;
    font-weight: 700;
    line-height: 1;
  }
  .count-tile .lbl {
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    margin-top: 8px;
  }
  .count-tile.crit .num { color: var(--crit); }
  .count-tile.high .num { color: var(--high); }
  .count-tile.med  .num { color: var(--med); }
  .count-tile.low  .num { color: var(--low); }
  .count-tile.info .num { color: var(--info); }
  .count-tile.pass .num { color: var(--pass); }

  .cat {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 24px;
    overflow: hidden;
  }
  .cat h2 {
    margin: 0;
    padding: 16px 20px;
    font-size: 16px;
    font-family: 'JetBrains Mono', monospace;
    background: var(--panel-2);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .cat-count {
    background: var(--border);
    color: var(--muted);
    font-size: 12px;
    padding: 2px 8px;
    border-radius: 10px;
  }

  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { text-align: left; padding: 12px 16px; vertical-align: top; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 500; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; background: var(--panel-2); }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: rgba(88, 166, 255, 0.04); }

  .sev-cell { width: 110px; }
  .title-cell { width: 28%; font-weight: 500; }
  .detail-cell, .rec-cell { color: var(--muted); }

  .badge {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 700;
    padding: 3px 10px;
    border-radius: 3px;
    letter-spacing: 1px;
    display: inline-block;
  }
  .badge-critical { background: var(--crit); color: #fff; }
  .badge-high     { background: var(--high); color: #1a0f08; }
  .badge-medium   { background: var(--med); color: #1f1607; }
  .badge-low      { background: var(--low); color: #06200e; }
  .badge-info     { background: var(--info); color: #08182b; }
  .badge-pass     { background: var(--pass); color: #06200e; }

  footer {
    text-align: center;
    padding: 32px;
    color: var(--muted);
    font-size: 12px;
    border-top: 1px solid var(--border);
    margin-top: 40px;
  }
  footer code { font-family: 'JetBrains Mono', monospace; color: var(--accent); }

  @media (max-width: 900px) {
    header, .container { padding: 20px; }
    .summary { grid-template-columns: 1fr; }
    .counts-grid { grid-template-columns: repeat(3, 1fr); }
  }
</style>
</head>
<body>
<header>
  <h1>// SECURITY AUDIT REPORT</h1>
  <div class="sub">Read-only configuration assessment</div>
  <div class="meta">
    <span>HOST <b>$Hostname</b></span>
    <span>OS <b>$(HtmlEncode $os)</b></span>
    <span>GENERATED <b>$generated</b></span>
    <span>DURATION <b>${duration}s</b></span>
    <span>ELEVATED <b>$IsAdmin</b></span>
  </div>
</header>

<div class="container">
  <div class="summary">
    <div class="risk-card">
      <div class="label">Composite Risk Score</div>
      <div class="score">$riskScore</div>
      <span class="band $riskBand">$riskBand</span>
    </div>
    <div class="counts-grid">
      <div class="count-tile crit"><div class="num">$($counts.Critical)</div><div class="lbl">Critical</div></div>
      <div class="count-tile high"><div class="num">$($counts.High)</div><div class="lbl">High</div></div>
      <div class="count-tile med"><div class="num">$($counts.Medium)</div><div class="lbl">Medium</div></div>
      <div class="count-tile low"><div class="num">$($counts.Low)</div><div class="lbl">Low</div></div>
      <div class="count-tile info"><div class="num">$($counts.Info)</div><div class="lbl">Info</div></div>
      <div class="count-tile pass"><div class="num">$($counts.Pass)</div><div class="lbl">Pass</div></div>
    </div>
  </div>

  $($rows -join "`n")
</div>

<footer>
  Generated by <code>Invoke-SecurityAudit.ps1</code> &middot; PSSecurityAudit project &middot; MIT License<br>
  This report is informational. Validate findings against your environment's policies before remediation.
</footer>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "[+] Audit complete." -ForegroundColor Green
Write-Host "    Findings: $total  |  Critical: $($counts.Critical)  High: $($counts.High)  Medium: $($counts.Medium)  Pass: $($counts.Pass)"
Write-Host "    Risk score: $riskScore ($riskBand)"
Write-Host "    Report:    $OutputPath" -ForegroundColor Cyan

#endregion
