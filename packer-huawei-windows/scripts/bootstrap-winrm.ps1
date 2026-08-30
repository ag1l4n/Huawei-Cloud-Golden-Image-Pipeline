Write-Output "Bootstrapping WinRM for Packer..."
winrm quickconfig -q
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress Any