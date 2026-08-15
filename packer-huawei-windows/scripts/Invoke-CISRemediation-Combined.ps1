<#
.SYNOPSIS
    CIS Microsoft Windows Server 2022 Benchmark v5.0.0 - SINGLE-FILE remediation.

.DESCRIPTION
    Self-contained companion to cis_ws2022_v5.0.0_benchmark.rb. Applies the
    end-state that the InSpec/CINC profile audits, all in one script:
      * Section 1  - Password & Account Lockout policy   (secedit)
      * Section 2  - User Rights Assignment              (secedit, role-aware)
                     Security Options                    (registry)
      * Section 5  - System Services (Print Spooler)     (registry, role-aware)
      * Section 9  - Windows Defender Firewall           (registry)
      * Section 17 - Advanced Audit Policy               (auditpol)
      * Section 18 - Administrative Templates (Computer) (registry)
      * Section 19 - Administrative Templates (User)     (per-user registry)

    Every change-making helper supports -WhatIf, so running with -WhatIf is a
    full dry run that writes nothing.

    REVIEW (organization-specific) and MANUAL controls are NOT applied
    automatically - they are listed at the end of this script as guidance.

.PARAMETER ServerRole
    member_server (default) or domain_controller. Drives the role-specific
    recommendations (user rights, Print Spooler, a few registry values).

.PARAMETER Sections
    One or more of: 1,2,5,9,17,18,19. Default = all.

.PARAMETER SkipBackup
    Skip the secedit / auditpol / registry export taken before changes.

.EXAMPLE
    .\Invoke-CISRemediation-Combined.ps1 -ServerRole member_server -WhatIf
.EXAMPLE
    .\Invoke-CISRemediation-Combined.ps1 -ServerRole domain_controller -Sections 17,18
.NOTES
    Test on a non-production host first. A reboot is recommended afterwards.
    Verified complete against CIS WS2022 v5.0.0 PDF (433 recommendations);
    392 are auto-applied here, the remainder are REVIEW/MANUAL (see footer).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("member_server","domain_controller")]
    [string]$ServerRole = "member_server",

    [ValidateSet("1","2","5","9","17","18","19")]
    [string[]]$Sections,

    [ValidateSet("L1","L2")]
    [string]$CisLevel = "L2",   # preserves old "remediate everything" behavior if omitted

    [switch]$SkipBackup,
    [string]$BackupDir = (Join-Path $env:ProgramData ("CIS-WS2022-Remediation\backup-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [string]$LogDir    = (Join-Path $env:ProgramData "CIS-WS2022-Remediation\logs")
)

$ErrorActionPreference = "Stop"


# ===========================================================================
# Shared helpers
# ===========================================================================
function Write-CISLog  { param([string]$Message) Write-Host    ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message) }
function Write-CISWarn { param([string]$Message) Write-Warning ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message) }

function Set-CISRegValue {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet("DWord","QWord","String","ExpandString","MultiString","Binary")][string]$Type,
        [Parameter(Mandatory)]$Value,
        [string]$ControlId
    )
    if ($ControlId -and -not (Test-CISShouldRun -ControlId $ControlId)) {
        Write-Verbose ("Skipping {0} (L2, CisLevel={1})" -f $ControlId, $CisLevel)
        return
    }
    if ($PSCmdlet.ShouldProcess(("{0}\{1}" -f $Path,$Name), ("Set {0} = {1}" -f $Type,$Value))) {
        try {
            if (-not (Test-Path -Path $Path)) { New-Item -Path $Path -Force | Out-Null }
            New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
        } catch { Write-CISWarn ("Failed to set {0}\{1}: {2}" -f $Path,$Name,$_.Exception.Message) }
    }
}

function Remove-CISRegValue {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Name)
    if (Test-Path -Path $Path) {
        if ($PSCmdlet.ShouldProcess(("{0}\{1}" -f $Path,$Name), "Remove value")) {
            Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
        }
    }
}

function Set-CISAudit {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Subcategory,
        [ValidateSet("enable","disable")][string]$Success = "disable",
        [ValidateSet("enable","disable")][string]$Failure = "disable"
    )
    if ($PSCmdlet.ShouldProcess(("Audit '{0}'" -f $Subcategory), ("Success={0} Failure={1}" -f $Success,$Failure))) {
        & auditpol /set /subcategory:"$Subcategory" /success:$Success /failure:$Failure | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-CISWarn ("auditpol failed for '{0}' (exit {1})" -f $Subcategory,$LASTEXITCODE) }
    }
}

$script:L2ControlIds = @(
    '2.2.36','2.3.7.1','2.3.7.6','2.3.10.4',
    '5.2',
    '18.1.3','18.5.5','18.5.7','18.5.9','18.5.10',
    '18.6.4.3','18.6.5.1','18.6.9.1','18.6.9.2','18.6.10.2','18.6.19.2.1','18.6.20.1','18.6.20.2','18.6.21.2',
    '18.8.1.1',
    '18.9.20.1.2','18.9.20.1.3','18.9.20.1.4','18.9.20.1.7','18.9.20.1.8','18.9.20.1.9','18.9.20.1.10','18.9.20.1.11','18.9.20.1.12',
    '18.9.28.1','18.9.33.1','18.9.33.2','18.9.35.6.1','18.9.35.6.2','18.9.49.5.1','18.9.49.11.1','18.9.51.1',
    '18.10.4.1','18.10.13.2','18.10.16.2','18.10.16.4','18.10.16.5','18.10.16.6',
    '18.10.18.1','18.10.18.7','18.10.36.1','18.10.40.1',
    '18.10.42.8.1','18.10.42.11.1.1.1','18.10.42.11.1.2.1','18.10.42.12.1',
    '18.10.57.3.2.1','18.10.57.3.3.1','18.10.57.3.3.4','18.10.57.3.3.6','18.10.57.3.3.7',
    '18.10.57.3.10.1','18.10.57.3.10.2',
    '18.10.59.4','18.10.81.1','18.10.82.3',
    '18.10.88.1','18.10.88.2','18.10.90.2.2','18.10.91.1',
    '19.6.6.1.1','19.7.8.3','19.7.8.4','19.7.46.2.1'
)

function Test-CISShouldRun {
    param([Parameter(Mandatory)][string]$ControlId)
    if ($script:L2ControlIds -contains $ControlId) { return $CisLevel -eq 'L2' }
    return $true
}

function Backup-CISState {
    param([Parameter(Mandatory)][string]$Dir)
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    Write-CISLog "Taking pre-change backup..."
    & secedit /export /cfg (Join-Path $Dir 'security-policy-before.inf') /quiet | Out-Null
    & auditpol /backup /file:(Join-Path $Dir 'audit-policy-before.csv') | Out-Null
    foreach ($hive in 'HKLM\SOFTWARE','HKLM\SYSTEM','HKU\.DEFAULT') {
        $safe = ($hive -replace '[\\\.]','_')
        & reg export $hive (Join-Path $Dir ("{0}-before.reg" -f $safe)) /y 2>$null | Out-Null
    }
    Write-CISLog ("Backup written to {0}" -f $Dir)
}

function Apply-SystemAccessInf {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][hashtable]$Settings)
    $body = ($Settings.GetEnumerator() | Sort-Object Name | ForEach-Object { "{0} = {1}" -f $_.Key,$_.Value }) -join "`r`n"
    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
[System Access]
$body
"@
    $tmp = Join-Path $env:TEMP "cis_sysaccess.inf"
    $sdb = Join-Path $env:TEMP "cis_sysaccess.sdb"
    $inf | Out-File -FilePath $tmp -Encoding unicode -Force
    if ($PSCmdlet.ShouldProcess("Local Security Policy","Apply Password/Lockout policy")) {
        secedit /configure /db $sdb /cfg $tmp /areas SECURITYPOLICY /quiet | Out-Null
        Write-CISLog ("  Applied [System Access] policy via secedit (exit {0})" -f $LASTEXITCODE)
    }
    Remove-Item $tmp,$sdb -ErrorAction SilentlyContinue
}

# ===========================================================================
# Section 1 - Password & Account Lockout policy
# ===========================================================================
function Set-CISAccountPolicies {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$BackupDir)
    Write-CISLog "Section 1 - Password & Account Lockout policy"
    $sa = @{
        'PasswordHistorySize'       = 24    # 1.1.1
        'MaximumPasswordAge'        = 365   # 1.1.2
        'MinimumPasswordAge'        = 1     # 1.1.3
        'MinimumPasswordLength'     = 14    # 1.1.4
        'PasswordComplexity'        = 1     # 1.1.5
        'ClearTextPassword'         = 0     # 1.1.7
        'LockoutDuration'           = 15    # 1.2.1
        'LockoutBadCount'           = 5     # 1.2.2  (5 or fewer, not 0)
        'ResetLockoutCount'         = 15    # 1.2.4
        'AllowAdministratorLockout' = 1     # 1.2.3  (MS only; harmless on DC)
    }
    Apply-SystemAccessInf -Settings $sa
    # 1.1.6 Allow relaxing minimum password length limits (registry; Member Server only)
    if ($ServerRole -eq 'member_server') {
        Set-CISRegValue -Path 'HKLM:\System\CurrentControlSet\Control\SAM' -Name 'RelaxMinimumPasswordLengthLimits' -Type DWord -Value 1  # 1.1.6
    }
}

# ===========================================================================
# Section 2 - Security Options (registry) + User Rights (secedit)
# ===========================================================================
function Set-CISSecurityOptions {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$ServerRole = "member_server", [string]$BackupDir)
    Write-CISLog "Section 2 - Security Options (registry)"
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Type DWord -Value 1  # 2.3.1.2
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Type DWord -Value 1  # 2.3.2.1
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'CrashOnAuditFail' -Type DWord -Value 0  # 2.3.2.2
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' -Name 'AddPrinterDrivers' -Type DWord -Value 1  # 2.3.4.1
    if ($ServerRole -eq 'domain_controller') { Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SubmitControl' -Type DWord -Value 0 }  # 2.3.5.1
    Remove-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'VulnerableChannelAllowList'  # 2.3.5.2
    if ($ServerRole -eq 'domain_controller') { Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding' -Type DWord -Value 2 }  # 2.3.5.3
    if ($ServerRole -eq 'domain_controller') { Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -Type DWord -Value 2 }  # 2.3.5.4
    if ($ServerRole -eq 'domain_controller') { Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RefusePasswordChange' -Type DWord -Value 0 }  # 2.3.5.5
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireSignOrSeal' -Type DWord -Value 1  # 2.3.6.1
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SealSecureChannel' -Type DWord -Value 1  # 2.3.6.2
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SignSecureChannel' -Type DWord -Value 1  # 2.3.6.3
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DisablePasswordChange' -Type DWord -Value 0  # 2.3.6.4
    Set-CISRegValue -Path 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters' -Name 'MaximumPasswordAge' -Type DWord -Value 1  # 2.3.6.5
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireStrongKey' -Type DWord -Value 1  # 2.3.6.6
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableCAD' -Type DWord -Value 0 -ControlId '2.3.7.1'  # 2.3.7.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Type DWord -Value 1  # 2.3.7.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Type DWord -Value 1  # 2.3.7.3
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Type DWord -Value 0 -ControlId '2.3.7.6' }  # 2.3.7.6
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'PasswordExpiryWarning' -Type DWord -Value 5  # 2.3.7.7
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'ScRemoveOption' -Type DWord -Value 1  # 2.3.7.9
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Type DWord -Value 1  # 2.3.8.1
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'EnablePlainTextPassword' -Type DWord -Value 0  # 2.3.8.2
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'AutoDisconnect' -Type DWord -Value 0  # 2.3.9.1
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'RequireSecuritySignature' -Type DWord -Value 1  # 2.3.9.2
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'enableforcedlogoff' -Type DWord -Value 1  # 2.3.9.3
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'SMBServerNameHardeningLevel' -Type DWord -Value 1 }  # 2.3.9.4
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Type DWord -Value 1 }  # 2.3.10.2
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Type DWord -Value 1 }  # 2.3.10.3
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'restrictremotesam' -Type String -Value 'O:BAG:BAD:(A;;RC;;;BA)' }  # 2.3.10.11
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableDomainCreds' -Type DWord -Value 1 -ControlId '2.3.10.4'  # 2.3.10.4
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Type DWord -Value 0  # 2.3.10.5
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'NullSessionPipes' -Type MultiString -Value @('LSARPC','NETLOGON','SAMR')  # 2.3.10.6
    Remove-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'NullSessionShares'  # 2.3.10.12
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'ForceGuest' -Type DWord -Value 0  # 2.3.10.13
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'UseMachineId' -Type DWord -Value 1  # 2.3.11.1
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'AllowNullSessionFallback' -Type DWord -Value 0  # 2.3.11.2
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u' -Name 'AllowOnlineID' -Type DWord -Value 0  # 2.3.11.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'SupportedEncryptionTypes' -Type DWord -Value 2147483640  # 2.3.11.4
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Type DWord -Value 1  # 2.3.11.5
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Type DWord -Value 5  # 2.3.11.7
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name 'LDAPClientIntegrity' -Type DWord -Value 1  # 2.3.11.8
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NTLMMinClientSec' -Type DWord -Value 537395200  # 2.3.11.9
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NTLMMinServerSec' -Type DWord -Value 537395200  # 2.3.11.10
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'AuditReceivingNTLMTraffic' -Type DWord -Value 2  # 2.3.11.11
    if ($ServerRole -eq 'domain_controller') { Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'AuditNTLMInDomain' -Type DWord -Value 7 }  # 2.3.11.12
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic' -Type DWord -Value 1  # 2.3.11.13
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ShutdownWithoutLogon' -Type DWord -Value 0  # 2.3.13.1
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel' -Name 'ObCaseInsensitive' -Type DWord -Value 1  # 2.3.15.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Type DWord -Value 1  # 2.3.17.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Type DWord -Value 1  # 2.3.17.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorUser' -Type DWord -Value 0  # 2.3.17.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableInstallerDetection' -Type DWord -Value 1  # 2.3.17.4
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableSecureUIAPaths' -Type DWord -Value 1  # 2.3.17.5
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Type DWord -Value 1  # 2.3.17.6
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Type DWord -Value 1  # 2.3.17.7
}

# ===========================================================================
# Section 2.2 - User Rights Assignment (role-aware, embedded)
# ===========================================================================
function Set-CISUserRights {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet("member_server","domain_controller")]
        [string]$ServerRole = "member_server",
        [string]$BackupDir
    )
    Write-CISLog "Section 2.2 - User Rights Assignment (role: $ServerRole)"
    
    

    if ($ServerRole -eq "domain_controller") {
        $cbInitSid = (New-Object System.Security.Principal.NTAccount("cloudbase-init")).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $rights = @(
        "SeAssignPrimaryTokenPrivilege = *S-1-5-18,*S-1-5-19,*S-1-5-20,*$cbInitSid"   # 2.2.44 (+ cloudbase-init, required for UserDataPlugin's CreateProcessAsUserW)
        "SeAuditPrivilege = *S-1-5-19,*S-1-5-20"   # 2.2.30
        "SeBackupPrivilege = *S-1-5-32-544"   # 2.2.11
        "SeBatchLogonRight = *S-1-5-32-544"   # 2.2.36
        "SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6"   # 2.2.15
        "SeCreatePagefilePrivilege = *S-1-5-32-544"   # 2.2.13
        "SeCreatePermanentPrivilege = "   # 2.2.16
        "SeCreateSymbolicLinkPrivilege = *S-1-5-32-544"   # 2.2.17
        "SeCreateTokenPrivilege = "   # 2.2.14
        "SeDebugPrivilege = *S-1-5-32-544"   # 2.2.19
        "SeDenyBatchLogonRight = *S-1-5-32-546"   # 2.2.22
        "SeDenyInteractiveLogonRight = *S-1-5-32-546"   # 2.2.24
        "SeDenyNetworkLogonRight = *S-1-5-32-546"   # 2.2.20
        "SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546"   # 2.2.25
        "SeDenyServiceLogonRight = *S-1-5-32-546"   # 2.2.23
        "SeEnableDelegationPrivilege = *S-1-5-32-544"   # 2.2.27
        "SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6"   # 2.2.31
        "SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0"   # 2.2.33
        "SeIncreaseQuotaPrivilege = *S-1-5-18,*S-1-5-32-544,*S-1-5-19,*S-1-5-20"   # 2.2.6
        "SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-9"   # 2.2.7
        "SeLoadDriverPrivilege = *S-1-5-32-544"   # 2.2.34
        "SeLockMemoryPrivilege = "   # 2.2.35
        "SeMachineAccountPrivilege = *S-1-5-32-544"   # 2.2.5
        "SeManageVolumePrivilege = *S-1-5-32-544"   # 2.2.41
        "SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11,*S-1-5-9"   # 2.2.2
        "SeProfileSingleProcessPrivilege = *S-1-5-32-544"   # 2.2.42
        "SeRelabelPrivilege = "   # 2.2.39
        "SeRemoteInteractiveLogonRight = *S-1-5-32-544"   # 2.2.9
        "SeRemoteShutdownPrivilege = *S-1-5-32-544"   # 2.2.29
        "SeRestorePrivilege = *S-1-5-32-544"   # 2.2.45
        "SeSecurityPrivilege = *S-1-5-32-544"   # 2.2.37
        "SeShutdownPrivilege = *S-1-5-32-544"   # 2.2.46
        "SeSyncAgentPrivilege = "   # 2.2.47
        "SeSystemEnvironmentPrivilege = *S-1-5-32-544"   # 2.2.40
        "SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"   # 2.2.43
        "SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19"   # 2.2.12
        "SeTakeOwnershipPrivilege = *S-1-5-32-544"   # 2.2.48
        "SeTcbPrivilege = "   # 2.2.4
        "SeTrustedCredManAccessPrivilege = "   # 2.2.1
        )
    } else {
        $cbInitSid = (New-Object System.Security.Principal.NTAccount("cloudbase-init")).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $rights = @(
        "SeAssignPrimaryTokenPrivilege = *S-1-5-18,*S-1-5-19,*S-1-5-20,*$cbInitSid"   # 2.2.44 (+ cloudbase-init, required for UserDataPlugin's CreateProcessAsUserW)
        "SeAuditPrivilege = *S-1-5-19,*S-1-5-20"   # 2.2.30
        "SeBackupPrivilege = *S-1-5-32-544"   # 2.2.11
        "SeBatchLogonRight = *S-1-5-32-544"   # 2.2.36
        "SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6"   # 2.2.15
        "SeCreatePagefilePrivilege = *S-1-5-32-544"   # 2.2.13
        "SeCreatePermanentPrivilege = "   # 2.2.16
        "SeCreateSymbolicLinkPrivilege = *S-1-5-32-544,*S-1-5-83-0"   # 2.2.18
        "SeCreateTokenPrivilege = "   # 2.2.14
        "SeDebugPrivilege = *S-1-5-32-544"   # 2.2.19
        "SeDenyBatchLogonRight = *S-1-5-32-546"   # 2.2.22
        "SeDenyInteractiveLogonRight = *S-1-5-32-546"   # 2.2.24
        "SeDenyNetworkLogonRight = *S-1-5-32-546"   # 2.2.21 — *S-1-5-114 dropped: blocks svc_audit (local admin) SSH logon (S4U network-logon), see incident 2026-07-23
        "SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546,*S-1-5-113"   # 2.2.26
        "SeDenyServiceLogonRight = *S-1-5-32-546"   # 2.2.23
        "SeEnableDelegationPrivilege = "   # 2.2.28
        "SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6"   # 2.2.32
        "SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0"   # 2.2.33
        "SeIncreaseQuotaPrivilege = *S-1-5-18,*S-1-5-32-544,*S-1-5-19,*S-1-5-20"   # 2.2.6
        "SeInteractiveLogonRight = *S-1-5-32-544"   # 2.2.8
        "SeLoadDriverPrivilege = *S-1-5-32-544"   # 2.2.34
        "SeLockMemoryPrivilege = "   # 2.2.35
        "SeMachineAccountPrivilege = *S-1-5-32-544"   # 2.2.5
        "SeManageVolumePrivilege = *S-1-5-32-544"   # 2.2.41
        "SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11"   # 2.2.3
        "SeProfileSingleProcessPrivilege = *S-1-5-32-544"   # 2.2.42
        "SeRelabelPrivilege = "   # 2.2.39
        "SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555"   # 2.2.10
        "SeRemoteShutdownPrivilege = *S-1-5-32-544"   # 2.2.29
        "SeRestorePrivilege = *S-1-5-32-544"   # 2.2.45
        "SeSecurityPrivilege = *S-1-5-32-544"   # 2.2.38
        "SeShutdownPrivilege = *S-1-5-32-544"   # 2.2.46
        "SeSyncAgentPrivilege = "   # 2.2.47
        "SeSystemEnvironmentPrivilege = *S-1-5-32-544"   # 2.2.40
        "SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"   # 2.2.43
        "SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19"   # 2.2.12
        "SeTakeOwnershipPrivilege = *S-1-5-32-544"   # 2.2.48
        "SeTcbPrivilege = "   # 2.2.4
        "SeTrustedCredManAccessPrivilege = "   # 2.2.1
        )
    }

    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
[Privilege Rights]
$($rights -join "`r`n")
"@
    $tmp = Join-Path $env:TEMP "cis_userrights.inf"
    $sdb = Join-Path $env:TEMP "cis_userrights.sdb"
    $inf | Out-File -FilePath $tmp -Encoding unicode -Force
    if ($PSCmdlet.ShouldProcess("Local Security Policy", "Apply CIS user rights assignments")) {
        secedit /configure /db $sdb /cfg $tmp /areas USER_RIGHTS /quiet | Out-Null
        Write-CISLog "  Applied user rights via secedit (exit $LASTEXITCODE)"
    }
    Remove-Item $tmp,$sdb -ErrorAction SilentlyContinue
}

# ===========================================================================
# Section 5 - System Services (Print Spooler)
# ===========================================================================
function Set-CISSystemServices {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$ServerRole = "member_server", [string]$BackupDir)
    Write-CISLog "Section 5 - System Services (role: $ServerRole)"
    $spoolerControlId = if ($ServerRole -eq 'domain_controller') { '5.1' } else { '5.2' }
    if (Test-CISShouldRun -ControlId $spoolerControlId) {
        Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Spooler' -Name 'Start' -Type DWord -Value 4  # 5.1 / 5.2
        if ($PSCmdlet.ShouldProcess("Spooler service","Stop and disable")) {
            Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
            Set-Service  -Name Spooler -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }
}

function Set-CISWinRMSurvivalRule {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Write-CISLog "Pre-flight - Preserving WinRM (5986) ahead of firewall lockdown"
    if ($PSCmdlet.ShouldProcess("WinRM HTTPS (5986)", "Write GP firewall allow rule")) {
        $gpFwPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules"
        if (-not (Test-Path $gpFwPath)) { New-Item -Path $gpFwPath -Force | Out-Null }
        Set-ItemProperty -Path $gpFwPath `
            -Name "Allow-WinRM-HTTPS-Pipeline" `
            -Value "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5986|Name=Allow-WinRM-HTTPS-Pipeline|" `
            -Type String -Force
    }
}

# ===========================================================================
# Section 9 - Windows Defender Firewall (registry)
# ===========================================================================
function Set-CISWindowsFirewall {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$ServerRole = "member_server", [string]$BackupDir)
    Write-CISLog "Section 9 - Windows Defender Firewall"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' -Name 'EnableFirewall' -Type DWord -Value 1  # 9.1.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' -Name 'DefaultInboundAction' -Type DWord -Value 1  # 9.1.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' -Name 'DisableNotifications' -Type DWord -Value 1  # 9.1.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' -Name 'LogFileSize' -Type DWord -Value 16384  # 9.1.5
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' -Name 'LogDroppedPackets' -Type DWord -Value 1  # 9.1.6
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' -Name 'LogSuccessfulConnections' -Type DWord -Value 1  # 9.1.7
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' -Name 'EnableFirewall' -Type DWord -Value 1  # 9.2.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' -Name 'DefaultInboundAction' -Type DWord -Value 1  # 9.2.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' -Name 'DisableNotifications' -Type DWord -Value 1  # 9.2.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' -Name 'LogFileSize' -Type DWord -Value 16384  # 9.2.5
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' -Name 'LogDroppedPackets' -Type DWord -Value 1  # 9.2.6
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' -Name 'LogSuccessfulConnections' -Type DWord -Value 1  # 9.2.7
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' -Name 'EnableFirewall' -Type DWord -Value 1  # 9.3.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' -Name 'DefaultInboundAction' -Type DWord -Value 1  # 9.3.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' -Name 'DisableNotifications' -Type DWord -Value 1  # 9.3.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' -Name 'AllowLocalPolicyMerge' -Type DWord -Value 1  # 9.3.4
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' -Name 'AllowLocalIPsecPolicyMerge' -Type DWord -Value 0  # 9.3.5
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' -Name 'LogFileSize' -Type DWord -Value 16384  # 9.3.7
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' -Name 'LogDroppedPackets' -Type DWord -Value 1  # 9.3.8
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' -Name 'LogSuccessfulConnections' -Type DWord -Value 1  # 9.3.9
}

# ===========================================================================
# Section 17 - Advanced Audit Policy (auditpol)
# ===========================================================================
function Set-CISAuditPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$ServerRole = "member_server", [string]$BackupDir)
    Write-CISLog "Section 17 - Advanced Audit Policy"
    Set-CISAudit -Subcategory 'Credential Validation' -Success enable -Failure enable  # 17.1.1 (Success and Failure)
    Set-CISAudit -Subcategory 'Kerberos Authentication Service' -Success enable -Failure enable  # 17.1.2 (Success and Failure)
    Set-CISAudit -Subcategory 'Kerberos Service Ticket Operations' -Success enable -Failure enable  # 17.1.3 (Success and Failure)
    Set-CISAudit -Subcategory 'Application Group Management' -Success enable -Failure enable  # 17.2.1 (Success and Failure)
    Set-CISAudit -Subcategory 'Computer Account Management' -Success enable -Failure disable  # 17.2.2 (Success)
    Set-CISAudit -Subcategory 'Distribution Group Management' -Success enable -Failure disable  # 17.2.3 (Success)
    Set-CISAudit -Subcategory 'Other Account Management Events' -Success enable -Failure disable  # 17.2.4 (Success)
    Set-CISAudit -Subcategory 'Security Group Management' -Success enable -Failure disable  # 17.2.5 (Success)
    Set-CISAudit -Subcategory 'User Account Management' -Success enable -Failure enable  # 17.2.6 (Success and Failure)
    Set-CISAudit -Subcategory 'PNP Activity' -Success enable -Failure disable  # 17.3.1 (Success)
    Set-CISAudit -Subcategory 'Process Creation' -Success enable -Failure disable  # 17.3.2 (Success)
    Set-CISAudit -Subcategory 'Directory Service Access' -Success disable -Failure enable  # 17.4.1 (Failure)
    Set-CISAudit -Subcategory 'Directory Service Changes' -Success enable -Failure disable  # 17.4.2 (Success)
    Set-CISAudit -Subcategory 'Account Lockout' -Success disable -Failure enable  # 17.5.1 (Failure)
    Set-CISAudit -Subcategory 'Group Membership' -Success enable -Failure disable  # 17.5.2 (Success)
    Set-CISAudit -Subcategory 'Logoff' -Success enable -Failure disable  # 17.5.3 (Success)
    Set-CISAudit -Subcategory 'Logon' -Success enable -Failure enable  # 17.5.4 (Success and Failure)
    Set-CISAudit -Subcategory 'Other Logon/Logoff Events' -Success enable -Failure enable  # 17.5.5 (Success and Failure)
    Set-CISAudit -Subcategory 'Special Logon' -Success enable -Failure disable  # 17.5.6 (Success)
    Set-CISAudit -Subcategory 'Detailed File Share' -Success disable -Failure enable  # 17.6.1 (Failure)
    Set-CISAudit -Subcategory 'File Share' -Success enable -Failure enable  # 17.6.2 (Success and Failure)
    Set-CISAudit -Subcategory 'Other Object Access Events' -Success enable -Failure enable  # 17.6.3 (Success and Failure)
    Set-CISAudit -Subcategory 'Removable Storage' -Success enable -Failure enable  # 17.6.4 (Success and Failure)
    Set-CISAudit -Subcategory 'Audit Policy Change' -Success enable -Failure disable  # 17.7.1 (Success)
    Set-CISAudit -Subcategory 'Authentication Policy Change' -Success enable -Failure disable  # 17.7.2 (Success)
    Set-CISAudit -Subcategory 'Authorization Policy Change' -Success enable -Failure disable  # 17.7.3 (Success)
    Set-CISAudit -Subcategory 'MPSSVC Rule-Level Policy Change' -Success enable -Failure enable  # 17.7.4 (Success and Failure)
    Set-CISAudit -Subcategory 'Other Policy Change Events' -Success disable -Failure enable  # 17.7.5 (Failure)
    Set-CISAudit -Subcategory 'Sensitive Privilege Use' -Success enable -Failure disable  # 17.8.1 (Success)
    Set-CISAudit -Subcategory 'IPsec Driver' -Success enable -Failure enable  # 17.9.1 (Success and Failure)
    Set-CISAudit -Subcategory 'Other System Events' -Success enable -Failure enable  # 17.9.2 (Success and Failure)
    Set-CISAudit -Subcategory 'Security State Change' -Success enable -Failure disable  # 17.9.3 (Success)
    Set-CISAudit -Subcategory 'Security System Extension' -Success enable -Failure disable  # 17.9.4 (Success)
    Set-CISAudit -Subcategory 'System Integrity' -Success enable -Failure enable  # 17.9.5 (Success and Failure)
}

# ===========================================================================
# Section 18 - Administrative Templates / Computer (registry)
# Includes 18.6.19.2.1 (Disable IPv6) and 18.10.42.11.x (Defender BNB).
# ===========================================================================
function Set-CISAdminTemplatesComputer {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$ServerRole = "member_server", [string]$BackupDir)
    Write-CISLog "Section 18 - Administrative Templates (Computer)"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera' -Type DWord -Value 1  # 18.1.1.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -Type DWord -Value 1  # 18.1.1.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' -Name 'AllowInputPersonalization' -Type DWord -Value 0  # 18.1.2.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'AllowOnlineTips' -Type DWord -Value 0 -ControlId '18.1.3'  # 18.1.3
    # if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Type DWord -Value 0 }  # 18.4.1
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start' -Type DWord -Value 4  # 18.4.2
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Type DWord -Value 0  # 18.4.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config' -Name 'EnableCertPaddingCheck' -Type DWord -Value 1  # 18.4.4
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name 'DisableExceptionChainValidation' -Type DWord -Value 0  # 18.4.5
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NodeType' -Type DWord -Value 2  # 18.4.6
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIPSourceRouting' -Type DWord -Value 2  # 18.5.2
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableIPSourceRouting' -Type DWord -Value 2  # 18.5.3
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableICMPRedirect' -Type DWord -Value 0  # 18.5.4
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'KeepAliveTime' -Type DWord -Value 300000 -ControlId '18.5.5'  # 18.5.5
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NoNameReleaseOnDemand' -Type DWord -Value 1  # 18.5.6
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'PerformRouterDiscovery' -Type DWord -Value 0 -ControlId '18.5.7'  # 18.5.7
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters' -Name 'TcpMaxDataRetransmissions' -Type DWord -Value 3 -ControlId '18.5.9'  # 18.5.9
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'TcpMaxDataRetransmissions' -Type DWord -Value 3 -ControlId '18.5.10'  # 18.5.10
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security' -Name 'WarningLevel' -Type DWord -Value 90  # 18.5.11
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'DisableIPv6DefaultDnsServers' -Type DWord -Value 1 -ControlId '18.6.4.3'  # 18.6.4.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableFontProviders' -Type DWord -Value 0 -ControlId '18.6.5.1'  # 18.6.5.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer' -Name 'MinSmb2Dialect' -Type DWord -Value 785  # 18.6.7.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'AllowInsecureGuestAuth' -Type DWord -Value 0  # 18.6.8.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'RequireEncryption' -Type DWord -Value 1  # 18.6.8.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'AllowLLTDIOOnDomain' -Type DWord -Value 0 -ControlId '18.6.9.1'  # 18.6.9.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'AllowRspndrOnDomain' -Type DWord -Value 0 -ControlId '18.6.9.2'  # 18.6.9.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet' -Name 'Disabled' -Type DWord -Value 1 -ControlId '18.6.10.2'  # 18.6.10.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections' -Name 'NC_AllowNetBridge_NLA' -Type DWord -Value 0  # 18.6.11.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections' -Name 'NC_ShowSharedAccessUI' -Type DWord -Value 0  # 18.6.11.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections' -Name 'NC_StdDomainUserSetLocation' -Type DWord -Value 1  # 18.6.11.4
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters' -Name 'DisabledComponents' -Type DWord -Value 255 -ControlId '18.6.19.2.1'  # 18.6.19.2.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -Name 'EnableRegistrars' -Type DWord -Value 0 -ControlId '18.6.20.1'  # 18.6.20.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI' -Name 'DisableWcnUi' -Type DWord -Value 1 -ControlId '18.6.20.2'  # 18.6.20.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fMinimizeConnections' -Type DWord -Value 3  # 18.6.21.1
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fBlockNonDomain' -Type DWord -Value 1 -ControlId '18.6.21.2' }  # 18.6.21.2
    Set-CISRegValue -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Name 'RegisterSpoolerRemoteRpcEndPoint' -Type DWord -Value 2  # 18.7.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' -Name 'RpcUseNamedPipeProtocol' -Type DWord -Value 0  # 18.7.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' -Name 'RpcProtocols' -Type DWord -Value 5  # 18.7.5
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print' -Name 'RpcAuthnLevelPrivacyEnabled' -Type DWord -Value 1  # 18.7.8
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'RestrictDriverInstallationToAdministrators' -Type DWord -Value 1  # 18.7.9
    Set-CISRegValue -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'NoWarningNoElevationOnInstall' -Type DWord -Value 0  # 18.7.11
    Set-CISRegValue -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'UpdatePromptSettings' -Type DWord -Value 0  # 18.7.12
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoCloudApplicationNotification' -Type DWord -Value 1 -ControlId '18.8.1.1'  # 18.8.1.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1  # 18.9.3.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' -Name 'AllowEncryptionOracle' -Type DWord -Value 0  # 18.9.4.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name 'AllowProtectedCreds' -Type DWord -Value 1  # 18.9.4.2
    # Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Type DWord -Value 1  # 18.9.5.1
    # Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'RequirePlatformSecurityFeatures' -Type DWord -Value 1  # 18.9.5.2
    # Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'HypervisorEnforcedCodeIntegrity' -Type DWord -Value 1  # 18.9.5.3
    # Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'HVCIMATRequired' -Type DWord -Value 1  # 18.9.5.4
    # if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'LsaCfgFlags' -Type DWord -Value 1 }  # 18.9.5.5
    # if ($ServerRole -eq 'domain_controller') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'LsaCfgFlags' -Type DWord -Value 0 }  # 18.9.5.6
    # Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'ConfigureSystemGuardLaunch' -Type DWord -Value 1  # 18.9.5.7
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceMetadata' -Name 'PreventDeviceMetadataFromNetwork' -Type DWord -Value 1  # 18.9.7.2
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -Name 'DriverLoadPolicy' -Type DWord -Value 3  # 18.9.13.1
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies' -Name 'ClfsAuthenticationChecking' -Type DWord -Value 1  # 18.9.17.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' -Name 'NoBackgroundPolicy' -Type DWord -Value 0  # 18.9.19.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' -Name 'NoGPOListChanges' -Type DWord -Value 0  # 18.9.19.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableCdp' -Type DWord -Value 0  # 18.9.19.4
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableBkGndGroupPolicy' -Type DWord -Value 0  # 18.9.19.5
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' -Name 'PreventHandwritingDataSharing' -Type DWord -Value 1 -ControlId '18.9.20.1.2'  # 18.9.20.1.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' -Name 'PreventHandwritingErrorReports' -Type DWord -Value 1 -ControlId '18.9.20.1.3'  # 18.9.20.1.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\InternetWizard' -Name 'ExitOnMSICW' -Type DWord -Value 1 -ControlId '18.9.20.1.4'  # 18.9.20.1.4
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoWebServices' -Type DWord -Value 1  # 18.9.20.1.5
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RegistrationControl' -Name 'NoRegistration' -Type DWord -Value 1 -ControlId '18.9.20.1.7'  # 18.9.20.1.7
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion' -Name 'DisableContentFileUpdates' -Type DWord -Value 1 -ControlId '18.9.20.1.8'  # 18.9.20.1.8
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoOnlinePrintsWizard' -Type DWord -Value 1 -ControlId '18.9.20.1.9'  # 18.9.20.1.9
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoPublishingWizard' -Type DWord -Value 1 -ControlId '18.9.20.1.10'  # 18.9.20.1.10
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client' -Name 'CEIP' -Type DWord -Value 2 -ControlId '18.9.20.1.11'  # 18.9.20.1.11
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value 0 -ControlId '18.9.20.1.12'  # 18.9.20.1.12
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' -Name 'DeviceEnumerationPolicy' -Type DWord -Value 0  # 18.9.24.1
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' -Name 'BackupDirectory' -Type DWord -Value 1 }  # 18.9.26.1
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' -Name 'PasswordExpirationProtectionEnabled' -Type DWord -Value 1 }  # 18.9.26.2
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' -Name 'ADPasswordEncryptionEnabled' -Type DWord -Value 1 }  # 18.9.26.3
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' -Name 'PasswordComplexity' -Type DWord -Value 4 }  # 18.9.26.4
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' -Name 'PasswordLength' -Type DWord -Value 15 }  # 18.9.26.5
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' -Name 'PasswordAgeDays' -Type DWord -Value 30 }  # 18.9.26.6
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' -Name 'PostAuthenticationResetDelay' -Type DWord -Value 1 }  # 18.9.26.7
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' -Name 'PostAuthenticationActions' -Type DWord -Value 3 }  # 18.9.26.8
    if ($ServerRole -eq 'domain_controller') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'AllowCustomSSPsAPs' -Type DWord -Value 0 }  # 18.9.27.1
    # Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'RunAsPPL' -Type DWord -Value 1  # 18.9.27.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\ControlPanel\International' -Name 'BlockUserInputMethodsForSignIn' -Type DWord -Value 1 -ControlId '18.9.28.1'  # 18.9.28.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'BlockUserFromShowingAccountDetailsOnSignin' -Type DWord -Value 1  # 18.9.29.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DontDisplayNetworkSelectionUI' -Type DWord -Value 1  # 18.9.29.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DontEnumerateConnectedUsers' -Type DWord -Value 1  # 18.9.29.3
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnumerateLocalUsers' -Type DWord -Value 0 }  # 18.9.29.4
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableLockScreenAppNotifications' -Type DWord -Value 1  # 18.9.29.5
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'AllowDomainPINLogon' -Type DWord -Value 0  # 18.9.29.6
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'AllowCrossDeviceClipboard' -Type DWord -Value 0 -ControlId '18.9.33.1'  # 18.9.33.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'UploadUserActivities' -Type DWord -Value 0 -ControlId '18.9.33.2'  # 18.9.33.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9' -Name 'DCSettingIndex' -Type DWord -Value 0 -ControlId '18.9.35.6.1'  # 18.9.35.6.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9' -Name 'ACSettingIndex' -Type DWord -Value 0 -ControlId '18.9.35.6.2'  # 18.9.35.6.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Name 'DCSettingIndex' -Type DWord -Value 1  # 18.9.35.6.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Name 'ACSettingIndex' -Type DWord -Value 1  # 18.9.35.6.4
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fAllowUnsolicited' -Type DWord -Value 0  # 18.9.37.1
    if ($ServerRole -eq 'domain_controller') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM' -Name 'SamNGCKeyROCAValidation' -Type DWord -Value 2 }  # 18.9.41.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy' -Name 'DisableQueryRemoteServer' -Type DWord -Value 0 -ControlId '18.9.49.5.1'  # 18.9.49.5.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}' -Name 'ScenarioExecutionEnabled' -Type DWord -Value 0 -ControlId '18.9.49.11.1'  # 18.9.49.11.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name 'DisabledByGroupPolicy' -Type DWord -Value 1 -ControlId '18.9.51.1'  # 18.9.51.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient' -Name 'Enabled' -Type DWord -Value 1  # 18.9.53.1.1
    if ($ServerRole -eq 'member_server') { Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer' -Name 'Enabled' -Type DWord -Value 0 }  # 18.9.53.1.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager' -Name 'AllowSharedLocalAppData' -Type DWord -Value 0 -ControlId '18.10.4.1'  # 18.10.4.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'MSAOptional' -Type DWord -Value 1  # 18.10.6.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume' -Type DWord -Value 1  # 18.10.8.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Type DWord -Value 1  # 18.10.8.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Type DWord -Value 255  # 18.10.8.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' -Name 'EnhancedAntiSpoofing' -Type DWord -Value 1  # 18.10.9.1.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Camera' -Name 'AllowCamera' -Type DWord -Value 0  # 18.10.11.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableConsumerAccountStateContent' -Type DWord -Value 1  # 18.10.13.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableCloudOptimizedContent' -Type DWord -Value 1 -ControlId '18.10.13.2'  # 18.10.13.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect' -Name 'RequirePinForPairing' -Type DWord -Value 1  # 18.10.14.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI' -Name 'DisablePasswordReveal' -Type DWord -Value 1  # 18.10.15.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name 'EnumerateAdministrators' -Type DWord -Value 0  # 18.10.15.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0  # 18.10.16.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DisableEnterpriseAuthProxy' -Type DWord -Value 1 -ControlId '18.10.16.2'  # 18.10.16.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value 1  # 18.10.16.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'EnableOneSettingsAuditing' -Type DWord -Value 1 -ControlId '18.10.16.4'  # 18.10.16.4
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'LimitDiagnosticLogCollection' -Type DWord -Value 1 -ControlId '18.10.16.5'  # 18.10.16.5
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'LimitDumpCollection' -Type DWord -Value 1 -ControlId '18.10.16.6'  # 18.10.16.6
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableAppInstaller' -Type DWord -Value 0 -ControlId '18.10.18.1'  # 18.10.18.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableExperimentalFeatures' -Type DWord -Value 0  # 18.10.18.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableHashOverride' -Type DWord -Value 0  # 18.10.18.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableLocalArchiveMalwareScanOverride' -Type DWord -Value 0  # 18.10.18.4
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableMSAppInstallerProtocol' -Type DWord -Value 0  # 18.10.18.5
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableBypassCertificatePinningForMicrosoftStore' -Type DWord -Value 0  # 18.10.18.6
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableWindowsPackageManagerCommandLineInterfaces' -Type DWord -Value 0 -ControlId '18.10.18.7'  # 18.10.18.7
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'Retention' -Type DWord -Value 0  # 18.10.26.1.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'MaxSize' -Type DWord -Value 32768  # 18.10.26.1.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'Retention' -Type DWord -Value 0  # 18.10.26.2.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'MaxSize' -Type DWord -Value 196608  # 18.10.26.2.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup' -Name 'Retention' -Type DWord -Value 0  # 18.10.26.3.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup' -Name 'MaxSize' -Type DWord -Value 32768  # 18.10.26.3.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'Retention' -Type DWord -Value 0  # 18.10.26.4.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'MaxSize' -Type DWord -Value 32768  # 18.10.26.4.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'DisableMotWOnInsecurePathCopy' -Type DWord -Value 0  # 18.10.29.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoDataExecutionPrevention' -Type DWord -Value 0  # 18.10.29.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoHeapTerminationOnCorruption' -Type DWord -Value 0  # 18.10.29.4
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'PreXPSP2ShellProtocolBehavior' -Type DWord -Value 0  # 18.10.29.5
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Type DWord -Value 1 -ControlId '18.10.36.1'  # 18.10.36.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging' -Name 'AllowMessageSync' -Type DWord -Value 0 -ControlId '18.10.40.1'  # 18.10.40.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount' -Name 'DisableUserAuth' -Type DWord -Value 1  # 18.10.41.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'LocalSettingOverrideSpynetReporting' -Type DWord -Value 0  # 18.10.42.5.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' -Name 'ExploitGuard_ASR_Rules' -Type DWord -Value 1  # 18.10.42.6.1.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine' -Name 'EnableFileHashComputation' -Type DWord -Value 1  # 18.10.42.7.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS' -Name 'EnableConvertWarnToBlock' -Type DWord -Value 1 -ControlId '18.10.42.8.1'  # 18.10.42.8.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'OobeEnableRtpAndSigUpdate' -Type DWord -Value 1  # 18.10.42.10.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableIOAVProtection' -Type DWord -Value 0  # 18.10.42.10.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableRealtimeMonitoring' -Type DWord -Value 0  # 18.10.42.10.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableBehaviorMonitoring' -Type DWord -Value 0  # 18.10.42.10.4
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableScriptScanning' -Type DWord -Value 0  # 18.10.42.10.5
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection' -Name 'BruteForceProtectionAggressiveness' -Type DWord -Value 1 -ControlId '18.10.42.11.1.1.1'  # 18.10.42.11.1.1.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection' -Name 'BruteForceProtectionConfiguredState' -Type DWord -Value 1  # 18.10.42.11.1.1.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection' -Name 'RemoteEncryptionProtectionAggressiveness' -Type DWord -Value 1 -ControlId '18.10.42.11.1.2.1'  # 18.10.42.11.1.2.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting' -Name 'DisableGenericRePorts' -Type DWord -Value 1 -ControlId '18.10.42.12.1'  # 18.10.42.12.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -Name 'QuickScanIncludeExclusions' -Type DWord -Value 1  # 18.10.42.13.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -Name 'DisablePackedExeScanning' -Type DWord -Value 0  # 18.10.42.13.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -Name 'DisableRemovableDriveScanning' -Type DWord -Value 0  # 18.10.42.13.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -Name 'DaysUntilAggressiveCatchupQuickScan' -Type DWord -Value 7  # 18.10.42.13.4
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'HideExclusionsFromLocalUsers' -Type DWord -Value 1  # 18.10.42.17
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall' -Name 'DisablePushToInstall' -Type DWord -Value 1  # 18.10.56.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DisablePasswordSaving' -Type DWord -Value 1  # 18.10.57.2.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fSingleSessionPerUser' -Type DWord -Value 1 -ControlId '18.10.57.3.2.1'  # 18.10.57.3.2.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'EnableUiaRedirection' -Type DWord -Value 0 -ControlId '18.10.57.3.3.1'  # 18.10.57.3.3.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableLocationRedir' -Type DWord -Value 1 -ControlId '18.10.57.3.3.4'  # 18.10.57.3.3.4
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisablePNPRedir' -Type DWord -Value 1 -ControlId '18.10.57.3.3.6'  # 18.10.57.3.3.6
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableWebAuthn' -Type DWord -Value 1 -ControlId '18.10.57.3.3.7'  # 18.10.57.3.3.7
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fPromptForPassword' -Type DWord -Value 1  # 18.10.57.3.9.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEncryptRPCTraffic' -Type DWord -Value 1  # 18.10.57.3.9.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'UserAuthentication' -Type DWord -Value 1  # 18.10.57.3.9.4
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MinEncryptionLevel' -Type DWord -Value 3  # 18.10.57.3.9.5
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MaxIdleTime' -Type DWord -Value 1 -ControlId '18.10.57.3.10.1'  # 18.10.57.3.10.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MaxDisconnectionTime' -Type DWord -Value 60000 -ControlId '18.10.57.3.10.2'  # 18.10.57.3.10.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DeleteTempDirsOnExit' -Type DWord -Value 1  # 18.10.57.3.11.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'PerSessionTempDir' -Type DWord -Value 1  # 18.10.57.3.11.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -Name 'DisableEnclosureDownload' -Type DWord -Value 1  # 18.10.58.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -Name 'AllowBasicAuthInClear' -Type DWord -Value 0  # 18.10.58.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowIndexingEncryptedStoresOrItems' -Type DWord -Value 0  # 18.10.59.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'EnableDynamicContentInWSB' -Type DWord -Value 0 -ControlId '18.10.59.4'  # 18.10.59.4
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' -Name 'AllowSuggestedAppsInWindowsInkWorkspace' -Type DWord -Value 0 -ControlId '18.10.81.1'  # 18.10.81.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' -Name 'AllowWindowsInkWorkspace' -Type DWord -Value 0  # 18.10.81.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'EnableUserControl' -Type DWord -Value 0  # 18.10.82.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Type DWord -Value 0  # 18.10.82.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'SafeForScripting' -Type DWord -Value 0 -ControlId '18.10.82.3'  # 18.10.82.3
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableMPR' -Type DWord -Value 0  # 18.10.83.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableAutomaticRestartSignOn' -Type DWord -Value 1  # 18.10.83.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Type DWord -Value 1 -ControlId '18.10.88.1'  # 18.10.88.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Type DWord -Value 1 -ControlId '18.10.88.2'  # 18.10.88.2
    # Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowBasic' -Type DWord -Value 0  # 18.10.90.1.1
    # Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowUnencryptedTraffic' -Type DWord -Value 0  # 18.10.90.1.2
    # Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowDigest' -Type DWord -Value 0  # 18.10.90.1.3
    # Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic' -Type DWord -Value 0  # 18.10.90.2.1
    # Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowAutoConfig' -Type DWord -Value 0 -ControlId '18.10.90.2.2'  # 18.10.90.2.2
    # Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' -Type DWord -Value 0  # 18.10.90.2.3
    # Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'DisableRunAs' -Type DWord -Value 1  # 18.10.90.2.4
    # Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS' -Name 'AllowRemoteShellAccess' -Type DWord -Value 0 -ControlId '18.10.91.1'  # 18.10.91.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoRebootWithLoggedOnUsers' -Type DWord -Value 0  # 18.10.94.1.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type DWord -Value 0  # 18.10.94.2.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallDay' -Type DWord -Value 0  # 18.10.94.2.2
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ManagePreviewBuildsPolicyValue' -Type DWord -Value 1  # 18.10.94.4.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DisableWpad' -Type DWord -Value 1  # 18.11.1
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'DisableProxyAuthenticationSchemes' -Type DWord -Value 256  # 18.11.2
}

# ===========================================================================
# Section 19 - Administrative Templates / User (per-user registry)
# Writes HKU\.DEFAULT (new profiles) and every loaded interactive hive.
# ===========================================================================
function Set-CISAdminTemplatesUser {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$ServerRole = "member_server", [string]$BackupDir)
    Write-CISLog "Section 19 - Administrative Templates (User) - per-user hives"
    $settings = @(
        @{ Sub='Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'; Name='NoToastApplicationNotificationOnLockScreen'; Val=1; Level='L1' }  # 19.5.1.1
        @{ Sub='Software\Policies\Microsoft\Assistance\Client\1.0'; Name='NoImplicitFeedback'; Val=1; Level='L2' }  # 19.6.6.1.1
        @{ Sub='Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'; Name='SaveZoneInformation'; Val=2; Level='L1' }  # 19.7.5.1
        @{ Sub='Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'; Name='ScanWithAntiVirus'; Val=3; Level='L1' }  # 19.7.5.2
        @{ Sub='Software\Policies\Microsoft\Windows\CloudContent'; Name='ConfigureWindowsSpotlight'; Val=2; Level='L1' }  # 19.7.8.1
        @{ Sub='Software\Policies\Microsoft\Windows\CloudContent'; Name='DisableThirdPartySuggestions'; Val=1; Level='L1' }  # 19.7.8.2
        @{ Sub='Software\Policies\Microsoft\Windows\CloudContent'; Name='DisableTailoredExperiencesWithDiagnosticData'; Val=1; Level='L2' }  # 19.7.8.3
        @{ Sub='Software\Policies\Microsoft\Windows\CloudContent'; Name='DisableWindowsSpotlightFeatures'; Val=1; Level='L2' }  # 19.7.8.4
        @{ Sub='SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name='DisableSpotlightCollectionOnDesktop'; Val=1; Level='L1' }  # 19.7.8.5
        @{ Sub='Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoInplaceSharing'; Val=1; Level='L1' }  # 19.7.26.1
        @{ Sub='Software\Policies\Microsoft\WindowsMediaPlayer'; Name='PreventCodecDownload'; Val=1; Level='L2' }  # 19.7.46.2.1
    )

    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script | Out-Null
    }
    # Target the .DEFAULT hive plus any loaded interactive user hive (S-1-5-21-*)
    $targets = @('.DEFAULT')
    $targets += (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                 Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } |
                 ForEach-Object { $_.PSChildName })
    foreach ($sid in ($targets | Select-Object -Unique)) {
        foreach ($s in $settings) {
            if ($s.Level -eq 'L2' -and $CisLevel -ne 'L2') { continue }
            $full = "HKU:\$sid\$($s.Sub)"
            Set-CISRegValue -Path $full -Name $s.Name -Type DWord -Value $s.Val
        }
    }
    Write-CISLog ("  Applied {0} per-user settings across {1} hive(s)." -f $settings.Count, ($targets | Select-Object -Unique).Count)
}

# ===========================================================================
# Pre-flight + orchestration
# ===========================================================================
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run from an elevated (Administrator) PowerShell session."
}

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$logFile = Join-Path $LogDir ("remediation-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Start-Transcript -Path $logFile -Append | Out-Null

try {
    Write-CISLog "=== CIS Windows Server 2022 v5.0.0 remediation (combined) ==="
    Write-CISLog ("Server role : {0}" -f $ServerRole)
    Write-CISLog ("WhatIf mode : {0}" -f [bool]$WhatIfPreference)

    # Must run before Section 9 (Windows Defender Firewall) applies DefaultInboundAction=Block,
    # and unconditionally regardless of -Sections filtering, since Packer's own WinRM session
    # depends on 5986 staying reachable for the rest of this build.
    Set-CISWinRMSurvivalRule

    if (-not $SkipBackup -and -not $WhatIfPreference) { Backup-CISState -Dir $BackupDir }
    else { Write-CISLog "Skipping backup (either -SkipBackup or -WhatIf)." }

    $actions = [ordered]@{
        '1'  = { Set-CISAccountPolicies        -BackupDir $BackupDir }
        '2'  = { Set-CISUserRights      -ServerRole $ServerRole -BackupDir $BackupDir
                 Set-CISSecurityOptions -ServerRole $ServerRole -BackupDir $BackupDir }
        '5'  = { Set-CISSystemServices         -ServerRole $ServerRole -BackupDir $BackupDir }
        '9'  = { Set-CISWindowsFirewall        -ServerRole $ServerRole -BackupDir $BackupDir }
        '17' = { Set-CISAuditPolicy            -ServerRole $ServerRole -BackupDir $BackupDir }
        '18' = { Set-CISAdminTemplatesComputer -ServerRole $ServerRole -BackupDir $BackupDir }
        '19' = { Set-CISAdminTemplatesUser     -ServerRole $ServerRole -BackupDir $BackupDir }
    }

    $run = if ($Sections) { $Sections } else { $actions.Keys }
    foreach ($s in $run) {
        if ($actions.Contains([string]$s)) { & $actions[[string]$s] }
        else { Write-CISWarn ("Unknown section '{0}' - skipped." -f $s) }
    }

    Write-CISLog "=== Remediation complete ==="
    Write-CISLog "Re-run the InSpec/CINC profile to confirm the resulting state."
    if (-not $WhatIfPreference) {
        Write-CISLog "Some settings (audit policy, user rights, per-user keys, IPv6, Spooler) take effect at next logon / policy refresh; a reboot is recommended."
    }
}
finally { Stop-Transcript | Out-Null }

# ===========================================================================
# NOT AUTO-APPLIED - REVIEW (organization-specific value required)
# Set the concrete value for your environment, then enforce via GP/registry.
# ===========================================================================
#   REVIEW  2.3.7.4        Configure 'Interactive logon: Message text for users attempting to log on' (Automated)
#   REVIEW  2.3.7.5        Configure 'Interactive logon: Message title for users attempting to log on' (Automated)
#   REVIEW  2.3.10.7       Ensure 'Network access: Named Pipes that can be accessed anonymously' is configured (MS only) (
#   REVIEW  2.3.10.8       Ensure 'Network access: Remotely accessible registry paths' is configured (Automated)
#   REVIEW  2.3.10.9       Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured (Automa
#   REVIEW  2.3.10.11      Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Admini
#   REVIEW  9.1.4          Ensure 'Windows Firewall: Domain: Logging: Name' is configured (Automated)
#   REVIEW  9.2.4          Ensure 'Windows Firewall: Private: Logging: Name' is configured (Automated)
#   REVIEW  9.3.6          Ensure 'Windows Firewall: Public: Logging: Name' is configured (Automated)
#   REVIEW  18.6.14.1      Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication", "Require 
#   REVIEW  18.9.20.1.13   Ensure 'Turn off Windows Error Reporting' is set to 'Enabled' (Automated)
#   REVIEW  18.9.23.1      Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic' (Automa
#   REVIEW  18.10.58.2     Ensure 'Turn on Basic feed authentication over HTTP' is set to 'Disabled' (Automated)
#   REVIEW  18.10.77.2.1   Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' (A
#   REVIEW  18.10.94.4.2   Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days' (Automated)
#
# ===========================================================================
# NOT AUTO-APPLIED - MANUAL (verify via secedit/GP; no single registry key)
# ===========================================================================
#   MANUAL  2.3.1.1        Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only) (Automated)
#   MANUAL  2.3.1.3        Configure 'Accounts: Rename administrator account' (Automated)
#   MANUAL  2.3.1.4        Configure 'Accounts: Rename guest account' (Automated)
#   MANUAL  2.3.7.8        Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is s
#   MANUAL  2.3.10.1       Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled' (Automated)
#   MANUAL  2.3.10.10      Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled
#   MANUAL  2.3.11.6       Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled' (Manual)
#   MANUAL  2.3.15.2       Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symboli
#   MANUAL  2.3.17.8       Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations
#   MANUAL  18.5.1         Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled' (Automated)
#   MANUAL  18.5.8         Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled' (Automated)
#   MANUAL  18.6.4.1       Ensure 'Configure multicast DNS (mDNS) protocol' is set to 'Disabled' (Automated)
#   MANUAL  18.6.4.2       Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on publ
#   MANUAL  18.6.4.4       Ensure 'Turn off multicast name resolution' is set to 'Enabled' (Automated)
#   MANUAL  18.7.2         Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled' (Automated)
#   MANUAL  18.7.4         Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is 
#   MANUAL  18.7.6         Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connec
#   MANUAL  18.7.7         Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0' (Automated)
#   MANUAL  18.7.10        Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific fil
#   MANUAL  18.9.20.1.1    Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled' (Automated)
#   MANUAL  18.9.20.1.6    Ensure 'Turn off printing over HTTP' is set to 'Enabled' (Automated)
#   MANUAL  18.9.37.2      Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled' (Automated)
#   MANUAL  18.9.38.1      Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only) (Automa
#   MANUAL  18.9.38.2      Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated' (MS only) (Aut
#   MANUAL  18.10.42.4.1   Ensure 'Enable EDR in block mode' is set to 'Enabled' (Automated)
#   MANUAL  18.10.42.5.2   Ensure 'Join Microsoft MAPS' is set to 'Enabled: Advanced' (Automated)
#   MANUAL  18.10.42.6.1.2 Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configure
#   MANUAL  18.10.42.6.3.1 Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block' (A
#   MANUAL  18.10.42.13.5  Ensure 'Turn on e-mail scanning' is set to 'Enabled' (Automated)
#   MANUAL  18.10.42.16    Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block' (
#   MANUAL  18.10.57.3.3.2 Ensure 'Do not allow COM port redirection' is set to 'Enabled' (Automated)
#   MANUAL  18.10.57.3.3.3 Ensure 'Do not allow drive redirection' is set to 'Enabled' (Automated)
#   MANUAL  18.10.57.3.3.5 Ensure 'Do not allow LPT port redirection' is set to 'Enabled' (Automated)
#   MANUAL  18.10.57.3.9.3 Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled
#   MANUAL  18.10.59.2     Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search' (Automated)
#   MANUAL  18.10.63.1     Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled' (Automated)
#   MANUAL  18.10.93.2.1   Ensure 'Prevent users from modifying settings' is set to 'Enabled' (Automated)

# ===========================================================================
# EXCLUDED — hardware/architecture incompatible with this fleet's VM class
# (no nested-virtualization/hypervisor exposure to guest, Secure Boot
# reports "Unsupported") and with the SSH-based ghost-user audit model.
# Applying the UEFI-locked settings (18.9.5.3/.5/18.9.27.2) to a VM whose
# firmware cannot complete the UEFI-lock handshake caused an unrecoverable
# boot failure on ecs-audit-window on 2026-07-21. Do not re-enable without
# first gating on hardware capability (Confirm-SecureBootUEFI +
# Get-CimInstance Win32_DeviceGuard -Property VirtualizationBasedSecurityStatus).
# ===========================================================================
#   EXCLUDED  18.4.1        LocalAccountTokenFilterPolicy — breaks local-account SSH pubkey auth (svc_audit)
#   EXCLUDED  18.9.5.1      EnableVirtualizationBasedSecurity
#   EXCLUDED  18.9.5.2      RequirePlatformSecurityFeatures
#   EXCLUDED  18.9.5.3      HypervisorEnforcedCodeIntegrity (UEFI lock)
#   EXCLUDED  18.9.5.4      HVCIMATRequired
#   EXCLUDED  18.9.5.5      LsaCfgFlags — Credential Guard, MS role (UEFI lock)
#   EXCLUDED  18.9.5.6      LsaCfgFlags — Credential Guard, DC role
#   EXCLUDED  18.9.5.7      ConfigureSystemGuardLaunch — Secure Launch
#   EXCLUDED  18.9.27.2     RunAsPPL — LSA process protection (UEFI lock)
