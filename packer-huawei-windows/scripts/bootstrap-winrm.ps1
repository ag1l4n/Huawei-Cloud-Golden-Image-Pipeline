Write-Output "Configuring OS-level WinHTTP Proxy for offline VM..."
# Configure Windows system services (like Windows Update & Add-WindowsCapability) to use the runner's proxy
netsh winhttp set proxy proxy-server="http=172.30.100.5:8888;https=172.30.100.5:8888" bypass-list="localhost;127.0.0.1;172.30.*"

# Set machine-level environment variables for PowerShell web requests
[Environment]::SetEnvironmentVariable("http_proxy", "http://172.30.100.5:8888", "Machine")
[Environment]::SetEnvironmentVariable("https_proxy", "http://172.30.100.5:8888", "Machine")
[Environment]::SetEnvironmentVariable("no_proxy", "localhost,127.0.0.1,172.30.0.0/16", "Machine")

Write-Output "Bootstrapping WinRM for Packer..."
winrm quickconfig -q
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress Any