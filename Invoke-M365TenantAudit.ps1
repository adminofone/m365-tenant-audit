<#PSScriptInfo
.VERSION 1.0.3
.GUID 7d3f2a91-5c4e-4b8a-9f61-2e0c8d4b7a13
.AUTHOR Admin of One
.COMPANYNAME Admin of One
.COPYRIGHT (c) 2026 Admin of One. MIT License.
.TAGS M365 Microsoft365 Security Audit EntraID ConditionalAccess Intune MFA
.LICENSEURI https://github.com/adminofone/m365-tenant-audit/blob/main/LICENSE
.PROJECTURI https://github.com/adminofone/m365-tenant-audit
.ICONURI
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
    1.0.3 - Admin MFA check now honours CA exclusions (excluded roles, users and groups) and only passes 'strong MFA' for a phishing-resistant authentication strength. The script no longer installs modules on its own; it tells you what to install and exits.
    1.0.2 - Report footer links to the Tenant Lockdown Kit.
    1.0.1 - Real-tenant fixes.
#>

<#
.SYNOPSIS
    M365 Tenant Security Audit (Free Edition) - READ-ONLY.

.DESCRIPTION
    Connects to Microsoft Graph with read-only permissions, checks common
    Microsoft 365 / Entra ID security baseline items and writes a
    self-contained HTML report.

    THIS SCRIPT MAKES NO CHANGES TO YOUR TENANT.

    Checks:
      - Licensing (Entra ID P1/P2 detection)
      - Security Defaults / Conditional Access (MFA for all, legacy auth block,
        admin MFA, break-glass exclusions, report-only policies)
      - Global Administrator count
      - MFA registration (all users + admins)
      - Stale / never-used accounts and guests
      - User consent to apps, guest invite settings, app creation
      - App registration secrets/certificates (expired / expiring)
      - Microsoft Secure Score
      - Intune compliance policies
      - Email DNS: SPF, DMARC, DKIM for each custom domain
      - Password expiration policy

.PARAMETER OutputPath
    Path of the HTML report. Default: ./M365-Audit-<date>.html

.PARAMETER StaleDays
    Accounts with no sign-in for this many days are flagged. Default: 90

.PARAMETER UseDeviceCode
    Use device-code sign-in (useful on servers / remote shells).

.PARAMETER CsvPath
    Optional: also export raw findings to CSV.

.EXAMPLE
    ./Invoke-M365TenantAudit.ps1

.EXAMPLE
    ./Invoke-M365TenantAudit.ps1 -StaleDays 60 -CsvPath ./findings.csv

.NOTES
    Requirements : PowerShell 7+, module Microsoft.Graph.Authentication
    Sign-in role : Global Reader (recommended) or Global Administrator
    License      : Provided AS-IS without warranty. MIT License.
#>
#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath ("M365-Audit-{0}.html" -f (Get-Date -Format 'yyyyMMdd-HHmm'))),
    [ValidateRange(7, 3650)]
    [int]$StaleDays = 90,
    [switch]$UseDeviceCode,
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.3'

# ---------------------------------------------------------------------------
# 0. Prerequisites
# ---------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host "Microsoft.Graph.Authentication module not found." -ForegroundColor Yellow
    Write-Host "This script does not install modules on its own. Install it from the PowerShell Gallery, then run the script again:" -ForegroundColor Yellow
    Write-Host "  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser" -ForegroundColor White
    exit 1
}
Import-Module Microsoft.Graph.Authentication

$Scopes = @(
    'Organization.Read.All',
    'Directory.Read.All',
    'Policy.Read.All',
    'AuditLog.Read.All',
    'Reports.Read.All',
    'RoleManagement.Read.Directory',
    'Application.Read.All',
    'SecurityEvents.Read.All',
    'DeviceManagementConfiguration.Read.All'
)

Write-Host "`n=== M365 Tenant Security Audit v$ScriptVersion (read-only) ===`n" -ForegroundColor Cyan
Write-Host "A browser window will open. Sign in with a Global Reader or Global Admin account." -ForegroundColor Gray

$connectParams = @{ Scopes = $Scopes; NoWelcome = $true; ContextScope = 'Process' }
if ($UseDeviceCode) { $connectParams.UseDeviceCode = $true }
Connect-MgGraph @connectParams

# ---------------------------------------------------------------------------
# 1. Helpers
# ---------------------------------------------------------------------------
$Results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Warn', 'Fail', 'Info', 'Error')][string]$Status,
        [string]$Detail = '',
        [string]$Recommendation = '',
        [ValidateRange(1, 5)][int]$Weight = 1
    )
    $Results.Add([pscustomobject]@{
            Category       = $Category
            Check          = $Check
            Status         = $Status
            Detail         = $Detail
            Recommendation = $Recommendation
            Weight         = $Weight
        })
    $color = switch ($Status) { 'Pass' { 'Green' } 'Warn' { 'Yellow' } 'Fail' { 'Red' } 'Error' { 'DarkGray' } default { 'Gray' } }
    Write-Host ("  [{0,-5}] {1} - {2}" -f $Status.ToUpper(), $Category, $Check) -ForegroundColor $color
}

function Get-GraphObject {
    param([Parameter(Mandatory)][string]$Uri)
    Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
        foreach ($v in @($resp.value)) { if ($null -ne $v) { $items.Add($v) } }
        $next = $resp.'@odata.nextLink'
    }
    return , $items.ToArray()
}

function Get-ShortError {
    param($ErrorRecord)
    $msg = $ErrorRecord.Exception.Message
    if ($msg -match 'Forbidden|403|Authorization_RequestDenied') { return "Access denied - check sign-in role or license (Entra ID P1 may be required)." }
    if ($msg -match 'NotFound|404') { return "Not available in this tenant (feature not licensed or not provisioned)." }
    if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) + '...' }
    return $msg
}

function Resolve-DohRecord {
    # DNS-over-HTTPS lookup (works on macOS, Linux and Windows)
    param([Parameter(Mandatory)][string]$Name, [ValidateSet('TXT', 'CNAME')][string]$Type = 'TXT')
    $q = "name=$([uri]::EscapeDataString($Name))&type=$Type"
    $r = $null
    foreach ($endpoint in @("https://cloudflare-dns.com/dns-query?$q", "https://dns.google/resolve?$q")) {
        try { $r = Invoke-RestMethod -Uri $endpoint -Headers @{ accept = 'application/dns-json' } -TimeoutSec 15; break }
        catch { $r = $null }
    }
    if ($null -eq $r) { throw "DNS lookup failed for $Name (could not reach DNS-over-HTTPS resolvers - check internet/proxy)." }
    if (-not $r.Answer) { return @() }
    $typeCode = if ($Type -eq 'TXT') { 16 } else { 5 }
    return @($r.Answer | Where-Object { $_.type -eq $typeCode } | ForEach-Object {
            ($_.data -replace '"\s*"', '').Trim('"')
        })
}

function Test-RequiresMfa {
    param($Policy)
    $g = $Policy.grantControls
    if (-not $g) { return $false }
    return (($g.builtInControls -contains 'mfa') -or ($null -ne $g.authenticationStrength))
}

$PhishingResistantMethods = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor')
function Test-PhishingResistantStrength {
    param($Policy)
    $st = $Policy.grantControls.authenticationStrength
    if (-not $st) { return $false }
    if ($st.id -eq '00000000-0000-0000-0000-000000000004') { return $true }   # built-in "Phishing-resistant MFA"
    $combos = @($st.allowedCombinations | Where-Object { $_ })
    if ($combos.Count -eq 0) { return $false }
    foreach ($c in $combos) {
        $parts = @($c -split ',' | ForEach-Object { $_.Trim() })
        if (@($parts | Where-Object { $_ -notin $PhishingResistantMethods }).Count -gt 0) { return $false }
    }
    return $true
}

$GroupMemberCache = @{}
function Get-GroupMemberIds {
    param([Parameter(Mandatory)][string]$GroupId)
    if (-not $GroupMemberCache.ContainsKey($GroupId)) {
        $ids = @()
        try { $ids = @(Get-GraphCollection -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/transitiveMembers?`$select=id" | ForEach-Object { $_.id }) }
        catch { $ids = $null }
        $GroupMemberCache[$GroupId] = $ids
    }
    return $GroupMemberCache[$GroupId]
}

function Get-AdminCoverage {
    # Returns $null if the policy does not cover Global Admins, otherwise an object with the admins it leaves out.
    param($Policy, [string[]]$GaIds)
    $u = $Policy.conditions.users
    if (@($u.excludeRoles) -contains $GlobalAdminRoleId) { return $null }
    if (-not ((@($u.includeRoles) -contains $GlobalAdminRoleId) -or (@($u.includeUsers) -contains 'All'))) { return $null }
    $excluded = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($id in @($u.excludeUsers | Where-Object { $_ })) { [void]$excluded.Add($id) }
    $unresolved = 0
    foreach ($g in @($u.excludeGroups | Where-Object { $_ })) {
        $members = Get-GroupMemberIds -GroupId $g
        if ($null -eq $members) { $unresolved++ } else { foreach ($m in $members) { [void]$excluded.Add($m) } }
    }
    $gaExcluded = @($GaIds | Where-Object { $excluded.Contains($_) })
    if ($GaIds.Count -gt 0 -and $gaExcluded.Count -ge $GaIds.Count) { return $null }
    return [pscustomobject]@{ Policy = $Policy; ExcludedAdmins = $gaExcluded.Count; UnresolvedGroups = $unresolved }
}

function ConvertTo-Html-Safe { param([string]$Text) [System.Net.WebUtility]::HtmlEncode($Text) }

$GlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'
$Now = Get-Date
$HasP1 = $false
$TenantName = 'Unknown tenant'
$TenantId = ''
$CustomDomains = @()

# ---------------------------------------------------------------------------
# 2. Tenant & licensing
# ---------------------------------------------------------------------------
Write-Host "`n[1/9] Tenant & licensing" -ForegroundColor Cyan
try {
    $org = @(Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/organization')[0]
    $TenantName = $org.displayName
    $TenantId = $org.id
    Add-Result -Category 'Tenant' -Check 'Tenant information' -Status 'Info' -Detail "$TenantName ($TenantId)"
}
catch { Add-Result -Category 'Tenant' -Check 'Tenant information' -Status 'Error' -Detail (Get-ShortError $_) }

try {
    $skus = Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus'
    $planNames = @($skus | ForEach-Object { $_.servicePlans.servicePlanName })
    $HasP1 = ($planNames -contains 'AAD_PREMIUM') -or ($planNames -contains 'AAD_PREMIUM_P2')
    $skuList = ($skus | Where-Object { $_.capabilityStatus -eq 'Enabled' } | ForEach-Object { "$($_.skuPartNumber) ($($_.consumedUnits)/$($_.prepaidUnits.enabled))" }) -join ', '
    Add-Result -Category 'Tenant' -Check 'Active licenses' -Status 'Info' -Detail $skuList
    if ($HasP1) {
        Add-Result -Category 'Tenant' -Check 'Entra ID P1/P2 available' -Status 'Pass' -Detail 'Conditional Access and sign-in reporting are available.'
    }
    else {
        Add-Result -Category 'Tenant' -Check 'Entra ID P1/P2 available' -Status 'Warn' -Weight 2 `
            -Detail 'No Entra ID P1/P2 found. Conditional Access is not available; rely on Security Defaults.' `
            -Recommendation 'Consider Microsoft 365 Business Premium (includes Entra ID P1 and Intune).'
    }
}
catch { Add-Result -Category 'Tenant' -Check 'Active licenses' -Status 'Error' -Detail (Get-ShortError $_) }

# ---------------------------------------------------------------------------
# 3. Security Defaults & Conditional Access
# ---------------------------------------------------------------------------
Write-Host "`n[2/9] MFA enforcement (Security Defaults / Conditional Access)" -ForegroundColor Cyan
$SecurityDefaultsOn = $false
$CaPolicies = @()
try {
    $sd = Get-GraphObject -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    $SecurityDefaultsOn = [bool]$sd.isEnabled
}
catch { Add-Result -Category 'Identity' -Check 'Security Defaults' -Status 'Error' -Detail (Get-ShortError $_) }

try { $CaPolicies = Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' }
catch { if ($HasP1) { Add-Result -Category 'Identity' -Check 'Conditional Access policies' -Status 'Error' -Detail (Get-ShortError $_) } }

$enabledCa = @($CaPolicies | Where-Object { $_.state -eq 'enabled' })
$reportOnlyCa = @($CaPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' })

if ($SecurityDefaultsOn) {
    Add-Result -Category 'Identity' -Check 'MFA enforcement' -Status 'Pass' -Weight 5 `
        -Detail 'Security Defaults are ON (MFA required, legacy authentication blocked).' `
        -Recommendation $(if ($HasP1) { 'You have Entra ID P1: consider replacing Security Defaults with Conditional Access for finer control.' } else { '' })
}
elseif ($enabledCa.Count -eq 0) {
    Add-Result -Category 'Identity' -Check 'MFA enforcement' -Status 'Fail' -Weight 5 `
        -Detail 'Security Defaults are OFF and no Conditional Access policy is enabled. MFA is NOT enforced.' `
        -Recommendation 'Immediately enable Security Defaults, or deploy Conditional Access policies requiring MFA for all users.'
}
else {
    # MFA for all users
    $mfaAll = @($enabledCa | Where-Object {
            ($_.conditions.users.includeUsers -contains 'All') -and
            ($_.conditions.applications.includeApplications -contains 'All') -and
            (Test-RequiresMfa $_)
        })
    if ($mfaAll.Count -gt 0) {
        Add-Result -Category 'Identity' -Check 'MFA for all users (CA)' -Status 'Pass' -Weight 5 -Detail ("Policy: " + (($mfaAll.displayName) -join ', '))
    }
    else {
        Add-Result -Category 'Identity' -Check 'MFA for all users (CA)' -Status 'Fail' -Weight 5 `
            -Detail 'No enabled CA policy requires MFA for All users on All cloud apps.' `
            -Recommendation 'Create a CA policy: Users = All (exclude break-glass), Apps = All, Grant = Require MFA.'
    }

    # Legacy authentication block
    $legacy = @($enabledCa | Where-Object {
            ($_.conditions.clientAppTypes -contains 'exchangeActiveSync') -and
            ($_.conditions.clientAppTypes -contains 'other') -and
            ($_.grantControls.builtInControls -contains 'block')
        })
    if ($legacy.Count -gt 0) {
        Add-Result -Category 'Identity' -Check 'Legacy authentication blocked' -Status 'Pass' -Weight 4 -Detail ("Policy: " + (($legacy.displayName) -join ', '))
    }
    else {
        Add-Result -Category 'Identity' -Check 'Legacy authentication blocked' -Status 'Fail' -Weight 4 `
            -Detail 'No enabled CA policy blocks legacy authentication (Exchange ActiveSync + Other clients).' `
            -Recommendation 'Create a CA policy: Users = All, Client apps = Exchange ActiveSync + Other clients, Grant = Block.'
    }

    # Admin MFA (honours CA exclusions: excluded roles, users and groups)
    $gaIds = @()
    try {
        $gaIds = @(Get-GraphCollection -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$GlobalAdminRoleId'&`$select=principalId" | ForEach-Object { $_.principalId })
    }
    catch { $gaIds = @() }
    $adminCoverage = @($enabledCa | Where-Object { Test-RequiresMfa $_ } | ForEach-Object { Get-AdminCoverage -Policy $_ -GaIds $gaIds } | Where-Object { $_ })
    $adminMfa = @($adminCoverage | ForEach-Object { $_.Policy })
    $adminStrength = @($adminCoverage | Where-Object { Test-PhishingResistantStrength $_.Policy })
    $exclNote = ''
    $maxExcl = ($adminCoverage | Measure-Object -Property ExcludedAdmins -Maximum).Maximum
    if ($maxExcl -gt 0) { $exclNote += " Note: $maxExcl Global Admin(s) are excluded from a covering policy (fine if that is your break-glass account)." }
    if (@($adminCoverage | Where-Object { $_.UnresolvedGroups -gt 0 }).Count -gt 0) { $exclNote += ' Some excluded groups could not be read, so admin exclusions may be incomplete.' }
    if ($adminStrength.Count -gt 0) {
        Add-Result -Category 'Identity' -Check 'Admins require strong MFA' -Status 'Pass' -Weight 4 -Detail ("Phishing-resistant authentication strength enforced by: " + (($adminStrength.Policy.displayName) -join ', ') + $exclNote)
    }
    elseif ($adminMfa.Count -gt 0) {
        Add-Result -Category 'Identity' -Check 'Admins require strong MFA' -Status 'Warn' -Weight 4 `
            -Detail ('Admins require MFA, but not a phishing-resistant authentication strength. Policies: ' + (($adminMfa.displayName) -join ', ') + $exclNote) `
            -Recommendation 'Create a CA policy for admin roles with Grant = Require authentication strength "Phishing-resistant MFA".'
    }
    else {
        Add-Result -Category 'Identity' -Check 'Admins require strong MFA' -Status 'Fail' -Weight 4 `
            -Detail 'No enabled CA policy requires MFA for Global Administrators once exclusions (roles, users, groups) are taken into account.' `
            -Recommendation 'Create a CA policy targeting admin roles requiring phishing-resistant MFA.'
    }

    # Break-glass exclusion
    $allUserPolicies = @($enabledCa | Where-Object { $_.conditions.users.includeUsers -contains 'All' })
    $noExclusion = @($allUserPolicies | Where-Object {
            @($_.conditions.users.excludeUsers | Where-Object { $_ }).Count -eq 0 -and
            @($_.conditions.users.excludeGroups | Where-Object { $_ }).Count -eq 0
        })
    if ($allUserPolicies.Count -gt 0 -and $noExclusion.Count -gt 0) {
        Add-Result -Category 'Identity' -Check 'Break-glass account excluded' -Status 'Warn' -Weight 2 `
            -Detail ("Policies targeting All users with no exclusion: " + (($noExclusion.displayName) -join ', ')) `
            -Recommendation 'Exclude 1-2 emergency access (break-glass) accounts from CA policies to avoid tenant lockout.'
    }
    elseif ($allUserPolicies.Count -gt 0) {
        Add-Result -Category 'Identity' -Check 'Break-glass account excluded' -Status 'Pass' -Weight 2 -Detail 'All-user policies have exclusions configured.'
    }
}

if ($reportOnlyCa.Count -gt 0) {
    Add-Result -Category 'Identity' -Check 'Report-only CA policies' -Status 'Info' `
        -Detail ("$($reportOnlyCa.Count) policy(ies) in report-only mode: " + (($reportOnlyCa.displayName) -join ', ')) `
        -Recommendation 'Review sign-in logs for impact, then switch to On.'
}

# ---------------------------------------------------------------------------
# 4. Privileged roles
# ---------------------------------------------------------------------------
Write-Host "`n[3/9] Privileged roles" -ForegroundColor Cyan
try {
    $gaAssign = Get-GraphCollection -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$GlobalAdminRoleId'&`$expand=principal"
    $gaNames = @($gaAssign | ForEach-Object { if ($_.principal.userPrincipalName) { $_.principal.userPrincipalName } else { $_.principal.displayName } })
    $gaCount = $gaNames.Count
    $detail = "$gaCount permanent Global Admin(s): " + ($gaNames -join ', ')
    if ($gaCount -lt 2) {
        Add-Result -Category 'Privileged access' -Check 'Global Administrator count' -Status 'Warn' -Weight 3 -Detail $detail `
            -Recommendation 'Keep at least 2 Global Admins (including one break-glass account) to avoid lockout.'
    }
    elseif ($gaCount -gt 4) {
        Add-Result -Category 'Privileged access' -Check 'Global Administrator count' -Status 'Fail' -Weight 3 -Detail $detail `
            -Recommendation 'Reduce Global Admins to 2-4. Use least-privilege roles (User/Exchange/Intune Administrator) instead.'
    }
    else {
        Add-Result -Category 'Privileged access' -Check 'Global Administrator count' -Status 'Pass' -Weight 3 -Detail $detail
    }
}
catch { Add-Result -Category 'Privileged access' -Check 'Global Administrator count' -Status 'Error' -Detail (Get-ShortError $_) }

# ---------------------------------------------------------------------------
# 5. MFA registration
# ---------------------------------------------------------------------------
Write-Host "`n[4/9] MFA registration" -ForegroundColor Cyan
try {
    $reg = Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
    if ($reg.Count -eq 0) { throw 'REPORT_EMPTY' }
    $members = @($reg | Where-Object { $_.userType -eq 'member' })
    $notReg = @($members | Where-Object { -not $_.isMfaRegistered })
    $adminsNotReg = @($reg | Where-Object { $_.isAdmin -and -not $_.isMfaRegistered })

    if ($members.Count -gt 0) {
        $pct = [math]::Round((($members.Count - $notReg.Count) / $members.Count) * 100, 1)
        $sample = ($notReg | Select-Object -First 10 | ForEach-Object { $_.userPrincipalName }) -join ', '
        $status = if ($pct -ge 95) { 'Pass' } elseif ($pct -ge 80) { 'Warn' } else { 'Fail' }
        Add-Result -Category 'Identity' -Check 'Users registered for MFA' -Status $status -Weight 4 `
            -Detail ("$pct% of $($members.Count) member users registered. Not registered ($($notReg.Count)): $sample" + $(if ($notReg.Count -gt 10) { ' ...' } else { '' })) `
            -Recommendation $(if ($status -ne 'Pass') { 'Run an MFA registration campaign (Entra > Protection > Authentication methods > Registration campaign).' } else { '' })
    }
    if ($adminsNotReg.Count -gt 0) {
        Add-Result -Category 'Privileged access' -Check 'Admins registered for MFA' -Status 'Fail' -Weight 5 `
            -Detail ("Admins without MFA: " + (($adminsNotReg.userPrincipalName) -join ', ')) `
            -Recommendation 'Require these admins to register MFA immediately.'
    }
    else {
        Add-Result -Category 'Privileged access' -Check 'Admins registered for MFA' -Status 'Pass' -Weight 5 -Detail 'All admin accounts have MFA registered.'
    }
}
catch {
    if ($_.Exception.Message -match 'REPORT_EMPTY') {
        Add-Result -Category 'Identity' -Check 'MFA registration report' -Status 'Info' -Detail 'Registration report is empty (new tenants can take up to 48 hours to populate). Re-run later.'
    }
    else { Add-Result -Category 'Identity' -Check 'MFA registration report' -Status 'Error' -Detail (Get-ShortError $_) }
}

# ---------------------------------------------------------------------------
# 6. Stale accounts & guests
# ---------------------------------------------------------------------------
Write-Host "`n[5/9] Stale accounts & guests" -ForegroundColor Cyan
$users = @()
$hasSignIn = $true
try {
    $users = Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity&$top=120'
}
catch {
    $hasSignIn = $false
    try { $users = Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName,accountEnabled,userType,createdDateTime&$top=999' }
    catch { Add-Result -Category 'Accounts' -Check 'User inventory' -Status 'Error' -Detail (Get-ShortError $_) }
}

if ($users.Count -gt 0) {
    $enabled = @($users | Where-Object { $_.accountEnabled })
    $guests = @($enabled | Where-Object { $_.userType -eq 'Guest' })
    Add-Result -Category 'Accounts' -Check 'User inventory' -Status 'Info' `
        -Detail "$($users.Count) total users, $($enabled.Count) enabled, $($guests.Count) enabled guests."

    if ($hasSignIn) {
        $cutoff = $Now.AddDays(-$StaleDays)
        $stale = @($enabled | Where-Object {
                $last = $_.signInActivity.lastSignInDateTime
                $created = if ($_.createdDateTime) { [datetime]$_.createdDateTime } else { $Now }
                if ($last) { [datetime]$last -lt $cutoff } else { $created -lt $cutoff }
            })
        $staleMembers = @($stale | Where-Object { $_.userType -ne 'Guest' })
        $staleGuests = @($stale | Where-Object { $_.userType -eq 'Guest' })

        foreach ($set in @(@{ Name = 'Stale member accounts'; Items = $staleMembers; W = 2 }, @{ Name = 'Stale guest accounts'; Items = $staleGuests; W = 2 })) {
            $items = @($set.Items)
            if ($items.Count -eq 0) {
                Add-Result -Category 'Accounts' -Check $set.Name -Status 'Pass' -Weight $set.W -Detail "No enabled accounts without sign-in for $StaleDays+ days."
            }
            else {
                $sample = ($items | Select-Object -First 10 | ForEach-Object { $_.userPrincipalName }) -join ', '
                Add-Result -Category 'Accounts' -Check $set.Name -Status 'Warn' -Weight $set.W `
                    -Detail ("$($items.Count) enabled account(s) with no sign-in for $StaleDays+ days: $sample" + $(if ($items.Count -gt 10) { ' ...' } else { '' })) `
                    -Recommendation 'Review and disable/remove unused accounts. Note: shared mailboxes and service accounts may appear here.'
            }
        }
    }
    else {
        Add-Result -Category 'Accounts' -Check 'Stale accounts' -Status 'Info' -Detail 'Sign-in activity not available (requires Entra ID P1 and AuditLog.Read.All).'
    }
}

# ---------------------------------------------------------------------------
# 7. Authorization policy (consent, guests, app creation)
# ---------------------------------------------------------------------------
Write-Host "`n[6/9] User consent & collaboration settings" -ForegroundColor Cyan
try {
    $authz = Get-GraphObject -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
    if ($authz.value) { $authz = @($authz.value)[0] }
    $grant = @($authz.defaultUserRolePermissions.permissionGrantPoliciesAssigned)

    if ($grant | Where-Object { $_ -like '*microsoft-user-default-legacy*' }) {
        Add-Result -Category 'Applications' -Check 'User consent to apps' -Status 'Fail' -Weight 4 `
            -Detail 'Users can consent to ANY third-party app accessing company data (legacy setting).' `
            -Recommendation 'Entra > Enterprise apps > Consent and permissions: allow consent only for verified publishers (low-risk) or disable and enable admin consent workflow.'
    }
    elseif ($grant | Where-Object { $_ -like '*microsoft-user-default-low*' }) {
        Add-Result -Category 'Applications' -Check 'User consent to apps' -Status 'Pass' -Weight 4 -Detail 'Users can only consent to low-risk permissions from verified publishers.'
    }
    elseif ($grant | Where-Object { $_ -like '*microsoft-user-default-recommended*' }) {
        Add-Result -Category 'Applications' -Check 'User consent to apps' -Status 'Pass' -Weight 4 -Detail 'Microsoft-managed (recommended) user consent policy.'
    }
    elseif (@($grant | Where-Object { $_ -like 'ManagePermissionGrantsForSelf.*' }).Count -eq 0) {
        Add-Result -Category 'Applications' -Check 'User consent to apps' -Status 'Pass' -Weight 4 -Detail 'User consent is disabled (admin approval required).'
    }
    else {
        Add-Result -Category 'Applications' -Check 'User consent to apps' -Status 'Warn' -Weight 4 `
            -Detail ('Custom consent policy assigned: ' + (($grant | Where-Object { $_ -like 'ManagePermissionGrantsForSelf.*' }) -join ', ')) `
            -Recommendation 'Review the custom permission grant policy to confirm it only allows low-risk permissions.'
    }

    if ($authz.defaultUserRolePermissions.allowedToCreateApps) {
        Add-Result -Category 'Applications' -Check 'Users can register apps' -Status 'Warn' -Weight 2 `
            -Detail 'All users can create app registrations.' `
            -Recommendation 'Entra > Users > User settings: set "Users can register applications" to No.'
    }
    else {
        Add-Result -Category 'Applications' -Check 'Users can register apps' -Status 'Pass' -Weight 2 -Detail 'Only admins can register applications.'
    }

    $invite = $authz.allowInvitesFrom
    if ($invite -eq 'everyone') {
        Add-Result -Category 'Accounts' -Check 'Guest invitation settings' -Status 'Warn' -Weight 2 `
            -Detail 'Anyone in the organization, including guests, can invite guests.' `
            -Recommendation 'Entra > External Identities > External collaboration settings: restrict to admins or members with Guest Inviter role.'
    }
    else {
        Add-Result -Category 'Accounts' -Check 'Guest invitation settings' -Status 'Pass' -Weight 2 -Detail "Guest invitations allowed from: $invite"
    }
}
catch { Add-Result -Category 'Applications' -Check 'Authorization policy' -Status 'Error' -Detail (Get-ShortError $_) }

# ---------------------------------------------------------------------------
# 8. App registration credentials
# ---------------------------------------------------------------------------
Write-Host "`n[7/9] App registration credentials" -ForegroundColor Cyan
try {
    $apps = Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/applications?$select=displayName,appId,passwordCredentials,keyCredentials&$top=999'
    $expired = [System.Collections.Generic.List[string]]::new()
    $expiring = [System.Collections.Generic.List[string]]::new()
    foreach ($a in $apps) {
        foreach ($c in @($a.passwordCredentials) + @($a.keyCredentials)) {
            if (-not $c -or -not $c.endDateTime) { continue }
            $end = [datetime]$c.endDateTime
            if ($end -lt $Now) { $expired.Add("$($a.displayName) (expired $($end.ToString('yyyy-MM-dd')))") }
            elseif ($end -lt $Now.AddDays(30)) { $expiring.Add("$($a.displayName) (expires $($end.ToString('yyyy-MM-dd')))") }
        }
    }
    if ($expiring.Count -gt 0) {
        Add-Result -Category 'Applications' -Check 'Secrets/certificates expiring in 30 days' -Status 'Warn' -Weight 2 `
            -Detail ($expiring -join '; ') -Recommendation 'Rotate these credentials before expiry to avoid outages.'
    }
    else {
        Add-Result -Category 'Applications' -Check 'Secrets/certificates expiring in 30 days' -Status 'Pass' -Weight 2 -Detail "$($apps.Count) app registration(s) checked."
    }
    if ($expired.Count -gt 0) {
        Add-Result -Category 'Applications' -Check 'Expired secrets/certificates' -Status 'Info' `
            -Detail ($expired -join '; ') -Recommendation 'Remove expired credentials to keep app registrations clean.'
    }
}
catch { Add-Result -Category 'Applications' -Check 'App registration credentials' -Status 'Error' -Detail (Get-ShortError $_) }

# ---------------------------------------------------------------------------
# 9. Secure Score & Intune
# ---------------------------------------------------------------------------
Write-Host "`n[8/9] Secure Score & device compliance" -ForegroundColor Cyan
try {
    $ss = @(Get-GraphObject -Uri 'https://graph.microsoft.com/v1.0/security/secureScores?$top=1').value
    if ($ss.Count -gt 0 -and $ss[0].maxScore -gt 0) {
        $s = $ss[0]
        $pct = [math]::Round(($s.currentScore / $s.maxScore) * 100, 1)
        $status = if ($pct -ge 70) { 'Pass' } elseif ($pct -ge 50) { 'Warn' } else { 'Fail' }
        Add-Result -Category 'Posture' -Check 'Microsoft Secure Score' -Status $status -Weight 3 `
            -Detail "$([math]::Round($s.currentScore,1)) / $([math]::Round($s.maxScore,1)) ($pct%)" `
            -Recommendation $(if ($status -ne 'Pass') { 'Review improvement actions at security.microsoft.com > Exposure management > Secure Score.' } else { '' })
    }
    else { Add-Result -Category 'Posture' -Check 'Microsoft Secure Score' -Status 'Info' -Detail 'No Secure Score data yet (new tenants can take 24-48 hours).' }
}
catch { Add-Result -Category 'Posture' -Check 'Microsoft Secure Score' -Status 'Error' -Detail (Get-ShortError $_) }

try {
    $cp = Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies'
    if ($cp.Count -eq 0) {
        Add-Result -Category 'Devices' -Check 'Intune compliance policies' -Status 'Warn' -Weight 3 `
            -Detail 'No device compliance policies found.' `
            -Recommendation 'Create compliance policies (BitLocker/FileVault, OS version, Defender) and require compliant devices in CA.'
    }
    else {
        Add-Result -Category 'Devices' -Check 'Intune compliance policies' -Status 'Pass' -Weight 3 -Detail ("$($cp.Count) policy(ies): " + (($cp.displayName) -join ', '))
    }
}
catch { Add-Result -Category 'Devices' -Check 'Intune compliance policies' -Status 'Info' -Detail ('Could not read Intune: ' + (Get-ShortError $_)) }

# ---------------------------------------------------------------------------
# 10. Domains: email DNS & password policy
# ---------------------------------------------------------------------------
Write-Host "`n[9/9] Email DNS (SPF / DMARC / DKIM) & password policy" -ForegroundColor Cyan
try {
    $domains = Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/domains'
    $CustomDomains = @($domains | Where-Object { $_.isVerified -and $_.id -notlike '*.onmicrosoft.com' })

    $expiringPw = @($domains | Where-Object { $_.isVerified -and $_.passwordValidityPeriodInDays -and $_.passwordValidityPeriodInDays -lt 2147483647 })
    if ($expiringPw.Count -gt 0) {
        Add-Result -Category 'Identity' -Check 'Password expiration' -Status 'Info' `
            -Detail ("Passwords expire on: " + (($expiringPw | ForEach-Object { "$($_.id) ($($_.passwordValidityPeriodInDays) days)" }) -join ', ')) `
            -Recommendation 'With MFA enforced, Microsoft and NIST recommend passwords that never expire.'
    }
    else {
        Add-Result -Category 'Identity' -Check 'Password expiration' -Status 'Pass' -Detail 'Passwords set to never expire (recommended with MFA).'
    }
}
catch { Add-Result -Category 'Email' -Check 'Domain list' -Status 'Error' -Detail (Get-ShortError $_) }

if ($CustomDomains.Count -eq 0) {
    Add-Result -Category 'Email' -Check 'Custom domains' -Status 'Info' -Detail 'No verified custom domains - email DNS checks skipped.'
}
foreach ($d in $CustomDomains) {
    $name = $d.id
    try {
        # SPF
        $spf = @(Resolve-DohRecord -Name $name -Type TXT | Where-Object { $_ -like 'v=spf1*' })
        if ($spf.Count -eq 0) {
            Add-Result -Category 'Email' -Check "SPF - $name" -Status 'Fail' -Weight 3 -Detail 'No SPF record.' `
                -Recommendation "Add TXT record: v=spf1 include:spf.protection.outlook.com -all"
        }
        elseif ($spf.Count -gt 1) {
            Add-Result -Category 'Email' -Check "SPF - $name" -Status 'Fail' -Weight 3 -Detail "Multiple SPF records found (invalid): $($spf -join ' | ')" `
                -Recommendation 'Merge into a single SPF TXT record.'
        }
        elseif ($spf[0] -match '[-~]all\s*$') {
            Add-Result -Category 'Email' -Check "SPF - $name" -Status 'Pass' -Weight 3 -Detail $spf[0]
        }
        else {
            Add-Result -Category 'Email' -Check "SPF - $name" -Status 'Warn' -Weight 3 -Detail $spf[0] `
                -Recommendation 'End SPF with -all (or ~all), not ?all / +all.'
        }

        # DMARC
        $dmarc = @(Resolve-DohRecord -Name "_dmarc.$name" -Type TXT | Where-Object { $_ -like 'v=DMARC1*' })
        if ($dmarc.Count -eq 0) {
            Add-Result -Category 'Email' -Check "DMARC - $name" -Status 'Fail' -Weight 3 -Detail 'No DMARC record.' `
                -Recommendation "Add TXT record _dmarc.$name : v=DMARC1; p=none; rua=mailto:dmarc@$name  (then move to quarantine/reject)"
        }
        elseif ($dmarc[0] -match 'p\s*=\s*(quarantine|reject)') {
            Add-Result -Category 'Email' -Check "DMARC - $name" -Status 'Pass' -Weight 3 -Detail $dmarc[0]
        }
        else {
            Add-Result -Category 'Email' -Check "DMARC - $name" -Status 'Warn' -Weight 3 -Detail $dmarc[0] `
                -Recommendation 'Policy is p=none (monitoring only). After reviewing reports, move to p=quarantine, then p=reject.'
        }

        # DKIM (Microsoft 365 selectors)
        $dkim1 = @(Resolve-DohRecord -Name "selector1._domainkey.$name" -Type CNAME)
        $dkim2 = @(Resolve-DohRecord -Name "selector2._domainkey.$name" -Type CNAME)
        if ($dkim1.Count -gt 0 -and $dkim2.Count -gt 0) {
            Add-Result -Category 'Email' -Check "DKIM - $name" -Status 'Pass' -Weight 2 -Detail 'selector1 and selector2 CNAME records found.'
        }
        else {
            Add-Result -Category 'Email' -Check "DKIM - $name" -Status 'Warn' -Weight 2 -Detail 'Microsoft 365 DKIM CNAME records (selector1/selector2) not found.' `
                -Recommendation 'Defender portal > Email & collaboration > Policies > Email authentication settings > DKIM: publish CNAMEs and enable signing. (Ignore if mail is sent via another provider.)'
        }
    }
    catch { Add-Result -Category 'Email' -Check "DNS - $name" -Status 'Error' -Detail $_.Exception.Message }
}

# ---------------------------------------------------------------------------
# 11. Score & HTML report
# ---------------------------------------------------------------------------
$scored = @($Results | Where-Object { $_.Status -in 'Pass', 'Warn', 'Fail' })
$max = ($scored | Measure-Object -Property Weight -Sum).Sum
$got = 0
foreach ($r in $scored) {
    if ($r.Status -eq 'Pass') { $got += $r.Weight }
    elseif ($r.Status -eq 'Warn') { $got += $r.Weight / 2 }
}
$score = if ($max -gt 0) { [math]::Round(($got / $max) * 100) } else { 0 }
$counts = @{}
foreach ($s in 'Pass', 'Warn', 'Fail', 'Info', 'Error') { $counts[$s] = @($Results | Where-Object Status -eq $s).Count }
$grade = if ($score -ge 85) { 'Good' } elseif ($score -ge 60) { 'Needs attention' } else { 'At risk' }
$gradeColor = if ($score -ge 85) { '#1a7f37' } elseif ($score -ge 60) { '#b35900' } else { '#c62828' }

$KitUrl = 'https://adminofone.gumroad.com/l/tenant-lockdown-kit?utm_source=audit-report&utm_medium=script'
$issues = $counts.Fail + $counts.Warn
$ctaHeadline = "$issues open finding(s). Most of them can be fixed in one afternoon."
$ctaHtml = if ($issues -eq 0) { '' } else { @"
<div class="cta">
<div class="cta-t">$ctaHeadline</div>
<div class="cta-d">Tenant Lockdown Kit deploys the fixes for the Conditional Access, Exchange Online and Intune findings above: 8 CA policies in report-only mode with a break-glass account, 10 Exchange hardening settings, and Windows/macOS compliance baselines. Every script supports -WhatIf and has a rollback.</div>
<a class="cta-b" href="$KitUrl" target="_blank" rel="noopener">See the kit &rarr;</a>
</div>
"@ }

$order = @{ 'Fail' = 0; 'Warn' = 1; 'Error' = 2; 'Pass' = 3; 'Info' = 4 }
$rows = foreach ($r in ($Results | Sort-Object @{ Expression = { $order[$_.Status] } }, Category, Check)) {
    $cls = $r.Status.ToLower()
    "<tr><td><span class='badge $cls'>$($r.Status)</span></td><td>$(ConvertTo-Html-Safe $r.Category)</td><td><strong>$(ConvertTo-Html-Safe $r.Check)</strong><div class='detail'>$(ConvertTo-Html-Safe $r.Detail)</div></td><td>$(ConvertTo-Html-Safe $r.Recommendation)</td></tr>"
}

$html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>M365 Security Audit - $(ConvertTo-Html-Safe $TenantName)</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--text:#1f2328;--muted:#656d76;--border:#d0d7de}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--text:#e6edf3;--muted:#8d96a0;--border:#30363d}}
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{margin:0 0 4px;font-size:24px}.sub{color:var(--muted);font-size:14px;margin-bottom:24px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px}
.card .n{font-size:28px;font-weight:700}.card .l{color:var(--muted);font-size:13px}
.score .n{color:$gradeColor;font-size:40px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top;font-size:14px}
th{font-size:12px;text-transform:uppercase;color:var(--muted)}
.detail{color:var(--muted);font-size:13px;margin-top:2px;word-break:break-word}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#fff}
.pass{background:#1a7f37}.warn{background:#b35900}.fail{background:#c62828}.info{background:#57606a}.error{background:#8250df}
.foot{color:var(--muted);font-size:12px;margin-top:24px}
.cta{margin-top:24px;background:var(--card);border:1px solid var(--border);border-left:4px solid #0969da;border-radius:10px;padding:16px 20px}
.cta-t{font-size:17px;font-weight:700;margin-bottom:4px}.cta-d{color:var(--muted);font-size:14px;margin-bottom:12px}
.cta-b{display:inline-block;background:#0969da;color:#fff;text-decoration:none;font-weight:600;font-size:14px;padding:8px 16px;border-radius:6px}
@media (max-width:700px){th:nth-child(2),td:nth-child(2){display:none}}
</style></head><body><div class="wrap">
<h1>Microsoft 365 Security Audit</h1>
<div class="sub">$(ConvertTo-Html-Safe $TenantName) &middot; $TenantId &middot; $($Now.ToString('yyyy-MM-dd HH:mm')) &middot; v$ScriptVersion (read-only)</div>
<div class="cards">
<div class="card score"><div class="n">$score</div><div class="l">Baseline score / 100 &middot; $grade</div></div>
<div class="card"><div class="n" style="color:#c62828">$($counts.Fail)</div><div class="l">Fail</div></div>
<div class="card"><div class="n" style="color:#b35900">$($counts.Warn)</div><div class="l">Warning</div></div>
<div class="card"><div class="n" style="color:#1a7f37">$($counts.Pass)</div><div class="l">Pass</div></div>
<div class="card"><div class="n">$($counts.Info + $counts.Error)</div><div class="l">Info / Not checked</div></div>
</div>
<table><thead><tr><th>Status</th><th>Area</th><th>Check</th><th>Recommendation</th></tr></thead><tbody>
$($rows -join "`n")
</tbody></table>
$ctaHtml
<div class="foot">Generated by the free Tenant Lockdown Kit audit (Admin of One). Read-only: no changes were made to the tenant. Findings are guidance, not a guarantee of security. Provided AS-IS without warranty.</div>
</div></body></html>
"@

$html | Out-File -FilePath $OutputPath -Encoding utf8
if ($CsvPath) { $Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding utf8 }

Disconnect-MgGraph | Out-Null

Write-Host "`nScore: $score/100 ($grade)  |  Fail: $($counts.Fail)  Warn: $($counts.Warn)  Pass: $($counts.Pass)" -ForegroundColor Cyan
Write-Host "Report saved: $OutputPath`n" -ForegroundColor Green
if ($issues -gt 0) {
    Write-Host "Want to fix these automatically? Tenant Lockdown Kit: https://adminofone.gumroad.com/l/tenant-lockdown-kit`n" -ForegroundColor Yellow
}

try {
    if ($IsMacOS) { & open $OutputPath }
    elseif ($IsWindows) { Invoke-Item $OutputPath }
}
catch { }
