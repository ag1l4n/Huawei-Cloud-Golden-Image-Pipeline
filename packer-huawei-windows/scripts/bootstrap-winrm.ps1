Write-Output "Bootstrapping WinRM for Packer..."
winrm quickconfig -q
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress Any