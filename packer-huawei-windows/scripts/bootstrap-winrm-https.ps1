#ps1_sysnative
<#
.SYNOPSIS
    Bootstraps WinRM over HTTPS with a self-signed certificate for Packer provisioning.
#>

Write-Output "Starting WinRM HTTPS Bootstrap..."

# 1. Ensure the WinRM service is running and set to start automatically
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM -ErrorAction SilentlyContinue

# 2. Configure basic WinRM service settings for automated provisioning
winrm quickconfig -q
winrm set winrm/config/service '@{AllowUnencrypted="false"}'
winrm set winrm/config/service/auth '@{Basic="true"}'

# 3. Generate a Self-Signed SSL Certificate for WinRM
$hostName = [System.Net.Dns]::GetHostByName("localhost").HostName
$cert = New-SelfSignedCertificate -DnsName $hostName -CertStoreLocation "Cert:\LocalMachine\My"
$certThumbprint = $cert.Thumbprint

Write-Output "Generated Self-Signed Cert with Thumbprint: $certThumbprint"

# 4. Remove any existing default HTTP/HTTPS listeners to avoid conflicts
Remove-Item -Path "WSMan:\Localhost\Listener\*" -Recurse -Force -ErrorAction SilentlyContinue

# 5. Create the new WinRM HTTPS Listener bound to the generated certificate
New-Item -Path "WSMan:\LocalHost\Listener" -Transport HTTPS -Address * -CertificateThumbPrint $certThumbprint -Force

# 6. Add Windows Firewall rule to allow WinRM over HTTPS (Port 5986)
New-NetFirewallRule -DisplayName "Allow WinRM HTTPS (5986)" `
                    -Name "WinRM-HTTPS-In" `
                    -Direction Inbound `
                    -LocalPort 5986 `
                    -Protocol TCP `
                    -Action Allow `
                    -Profile Any `
                    -Force

# 7. Restart WinRM to apply all configuration changes
Restart-Service -Name WinRM -Force

Write-Output "WinRM HTTPS Bootstrap Completed Successfully."