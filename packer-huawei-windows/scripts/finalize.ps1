# =============================================================================
# finalize.ps1 - Corrected Registry Access & Restoration
# NOTE: WinRM GPO lockdown (formerly "Part 3" in this script) has been moved
# OUT and into the final Packer provisioner instead. Writing AllowBasic /
# AllowUnencryptedTraffic to the GPO WinRM registry paths appears to force
# an immediate reload of the WinRM listener stack, which drops the live
# session regardless of the transport/auth currently in use -- so it must
# be the very last thing that happens, alongside listener/cert/firewall
# cleanup and the Sysprep trigger, not a mid-pipeline step.
# =============================================================================

function Set-Reg {
    param($Path, $Name, $Value, $Type = 'DWord')
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

# This function is used by the parent finalize script
function Grant-KeyAccess {
    param($Path)
    if (Test-Path $Path) {
        $acl = Get-Acl $Path
        $permission = "NT AUTHORITY\SYSTEM","FullControl","Allow"
        $accessRule = New-Object System.Security.AccessControl.RegistryAccessRule($permission)
        $acl.SetAccessRule($accessRule)
        Set-Acl $Path $acl
    }
}

Write-Output "=== Part 1: Initial Hardening ==="
Unregister-ScheduledTask -TaskName 'RestoreCISPolicies' -Confirm:$false -ErrorAction SilentlyContinue
# NOTE: "RestrictReceivingNTLMTraffic" = 2 ("Deny all") is deliberately NOT set here.
# NTLM's SSP evaluates this registry value in real time on every new auth attempt --
# setting it here denies any *new* WinRM shell Packer tries to open for the rest of
# the build (including this very script's own post-run cleanup upload), even though
# the currently-open shell keeps working. It must be set only in the final
# provisioner, after nothing else needs a live connection.

$scriptsPath = "C:\Windows\Setup\Scripts"
if (!(Test-Path $scriptsPath)) { 
    New-Item -ItemType Directory -Force -Path $scriptsPath | Out-Null 
}

# =============================================================================
# RestoreCIS.ps1 (The Boot-time engine)
# =============================================================================
$restoreScript = "$scriptsPath\RestoreCIS.ps1"
@'
Start-Transcript -Path "C:\Windows\Setup\Scripts\RestoreCIS.log"

function Grant-KeyAccess {
    param($Path)
    if (Test-Path $Path) {
        $acl = Get-Acl $Path
        $permission = "NT AUTHORITY\SYSTEM","FullControl","Allow"
        $accessRule = New-Object System.Security.AccessControl.RegistryAccessRule($permission)
        $acl.SetAccessRule($accessRule)
        Set-Acl $Path $acl
    }
}

Unregister-ScheduledTask -TaskName 'RestoreCISPolicies' -Confirm:$false -ErrorAction SilentlyContinue

$sysPolicy = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Grant-KeyAccess $sysPolicy

# Wait for Cloudbase-Init to provision the local Administrator account before applying CIS policy
Write-Output "Waiting for Cloudbase-Init to provision the Administrator account..."
$accountWait = 0
while ($accountWait -lt 600) {
  if (Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue) {
    Write-Output "Administrator account found after $accountWait seconds. Proceeding with CIS policy."
    break
  }
  Write-Output "Administrator not yet provisioned... ($accountWait s)"
  Start-Sleep -Seconds 15
  $accountWait += 15
  if ($accountWait -ge 600) {
    Write-Output "WARNING: Administrator account never appeared after 600s. Proceeding anyway."
  }
}

# 1. Apply Security Policy
secedit.exe /configure /db $env:windir\security\local.sdb /cfg C:\Windows\Setup\Scripts\CIS-Gold-State.inf /overwrite /quiet

# 2. Apply Audit Policy
auditpol.exe /restore /file:C:\Windows\Setup\Scripts\CIS-Auditpol.csv

# 3. Enforce Registry State
regedit.exe /s C:\Windows\Setup\Scripts\CIS-Policies.reg

# 4. Enforce Policy Refresh
gpupdate /force
if ($LASTEXITCODE -ne 0) { Write-Error "gpupdate failed!" }

Write-Output "Purging corrupted Sysprep SSH keys..."
Remove-Item -Path "$env:ProgramData\ssh\ssh_host_*" -Force -Recurse -ErrorAction SilentlyContinue

Write-Output "Generating fresh SSH Host Keys..."
Start-Process -FilePath "C:\Windows\System32\OpenSSH\ssh-keygen.exe" -ArgumentList "-A" -NoNewWindow -Wait

$aclScript = "C:\Windows\System32\OpenSSH\FixHostFilePermissions.ps1"
if (Test-Path $aclScript) {
    & powershell.exe -ExecutionPolicy Bypass -File $aclScript -Confirm:$false
}

Write-Output "Starting OpenSSH Server..."
Set-Service -Name sshd -StartupType Automatic
Start-Service -Name sshd

# After gpupdate completes, write SSH rule directly into GP registry
# so it cannot be overridden by local policy merge restrictions
Write-Output "Writing SSH firewall rule to GP registry path..."
$gpFwPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules"
if (-not (Test-Path $gpFwPath)) {
    New-Item -Path $gpFwPath -Force | Out-Null
}
Set-ItemProperty -Path $gpFwPath `
    -Name "Allow-SSH-Pipeline" `
    -Value "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=22|Name=Allow-SSH-Pipeline|" `
    -Type String -Force

gpupdate /force /target:computer

# Remove the local store rule since GP path takes precedence
Remove-NetFirewallRule -Name "Allow-SSH-Pipeline" -ErrorAction SilentlyContinue

# Restart sshd after GP rule is in place
Restart-Service sshd -Force
Write-Output "SSH firewall rule written to GP store. sshd restarted."
Stop-Transcript
'@ | Out-File -FilePath $restoreScript -Encoding ASCII -Force

# Register Task
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -File $restoreScript"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'RestoreCISPolicies' -Action $action -Trigger $trigger -Principal $principal -Force

# Delay Cloudbase-Init's own auto-start so RestoreCIS.ps1's AtStartup task
# (which grants cloudbase-init the SeAssignPrimaryTokenPrivilege it needs
# to respawn itself) reliably runs first. Without this, both race to start
# in the same early-boot window with no ordering guarantee, and
# Cloudbase-Init has been consistently losing that race.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\cloudbase-init" -Name "DelayedAutostart" -Value 1 -Type DWord -Force

Write-Output "finalize.ps1 complete. WinRM GPO lockdown and Sysprep are handled by the final provisioner step."