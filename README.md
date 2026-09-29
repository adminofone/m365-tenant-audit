# M365 Tenant Audit

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/Invoke-M365TenantAudit?label=PowerShell%20Gallery)](https://www.powershellgallery.com/packages/Invoke-M365TenantAudit) [![Downloads](https://img.shields.io/powershellgallery/dt/Invoke-M365TenantAudit)](https://www.powershellgallery.com/packages/Invoke-M365TenantAudit)

**A free, read-only security check for Microsoft 365. One command, one HTML report, a score out of 100.**

Built for the one-person IT department: small and mid-size companies on Microsoft 365 Business Premium that have no security team, but still get the phishing emails.

```powershell
./Invoke-M365TenantAudit.ps1
```

> **Read-only.** The script requests read permissions only and makes no changes to your tenant.

---

## What it checks

| Area | Checks |
|---|---|
| **Identity** | Security Defaults / Conditional Access MFA for all users, legacy auth blocked, admin MFA strength, break-glass exclusions, report-only policies, password expiration |
| **Privileged access** | Global Administrator count, admins without MFA registered |
| **Accounts** | MFA registration rate, stale member and guest accounts, guest invitation settings |
| **Applications** | User consent to third-party apps, who can register apps, expiring or expired app secrets and certificates |
| **Devices** | Intune compliance policies |
| **Posture** | Microsoft Secure Score |
| **Email** | SPF, DMARC and DKIM for every custom domain |

Every finding comes with the exact place to fix it.

## Quick start

**1. Install PowerShell 7**

```bash
# Windows
winget install --id Microsoft.PowerShell --source winget
# macOS
brew install powershell
```

**2. Install and run (PowerShell Gallery, recommended)**

```powershell
pwsh
Install-Script -Name Invoke-M365TenantAudit -Scope CurrentUser
Invoke-M365TenantAudit.ps1
```

Say **Yes** if it asks to add the scripts folder to your PATH, then open a new `pwsh` window.

**Or download directly from GitHub**

```powershell
pwsh
cd ~/Downloads
Invoke-WebRequest https://raw.githubusercontent.com/adminofone/m365-tenant-audit/main/Invoke-M365TenantAudit.ps1 -OutFile Invoke-M365TenantAudit.ps1
./Invoke-M365TenantAudit.ps1
```

On Windows, if you see *"running scripts is disabled"*, run `Unblock-File ./Invoke-M365TenantAudit.ps1` once.

Sign in with a **Global Reader** (recommended) or Global Administrator account and accept the read-only permissions. The report opens in your browser when the scan finishes.

**Options**

```powershell
./Invoke-M365TenantAudit.ps1 -StaleDays 60 -CsvPath ./findings.csv   # custom stale threshold + CSV export
./Invoke-M365TenantAudit.ps1 -UseDeviceCode                           # sign in from another device
```

## Requirements

- PowerShell 7+ (Windows, macOS, Linux)
- `Microsoft.Graph.Authentication` module (installed automatically on first run)
- Some checks (sign-in activity, MFA registration) need Entra ID P1, which is included in Microsoft 365 Business Premium. Without it those checks show as *Info* rather than failing.

## Notes on new tenants

- The MFA registration report and Secure Score can take **24–48 hours** to populate. Re-run later.
- Email DNS checks use DNS-over-HTTPS (Cloudflare, falling back to Google).

## Alternatives

This script is a quick first look, not a full benchmark. If you need more depth, these free tools are excellent:

| Tool | Best for | Runs on |
|---|---|---|
| [ScubaGear](https://github.com/cisagov/ScubaGear) (CISA) | The full CISA SCuBA baseline across Entra ID, Defender, Exchange Online, SharePoint, Teams, Power Platform and Power BI | Windows PowerShell 5.1 + OPA |
| [Maester](https://maester.dev) | Continuous testing: 360+ Pester tests (CISA, CIS, EIDSCA, ORCA) that can run on a schedule in CI pipelines with alerts | PowerShell + Pester |
| [Monkey365](https://github.com/silverhack/monkey365) | CIS Microsoft 365 and Azure Foundations benchmark reports | Windows, Linux |
| [365Inspect](https://github.com/soteria-security/365Inspect) | 200+ inspection points across the Microsoft 365 services | Windows |
| [Microsoft Secure Score](https://security.microsoft.com/securescore) | Microsoft's own built-in posture score and improvement actions | Browser |

**When to use this one:** you want a read-only answer in a few minutes, from a single file with one module dependency, on Windows, macOS or Linux, with one score and the fix next to each finding.

## Fix what it finds

The audit tells you what's wrong. **[Tenant Lockdown Kit](https://adminofone.gumroad.com/l/tenant-lockdown-kit)** fixes it: Conditional Access policies (report-only first, with a break-glass account), Exchange Online hardening and an Intune baseline, each with `-WhatIf` and a rollback command, plus an 8-page implementation guide. The **[Complete Edition](https://adminofone.gumroad.com/l/tenant-lockdown-kit-complete)** adds one-command user onboarding and offboarding.

## License

MIT. Provided as-is, without warranty. Not affiliated with or endorsed by Microsoft.
