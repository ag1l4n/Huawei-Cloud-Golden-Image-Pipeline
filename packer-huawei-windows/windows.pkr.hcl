packer {
  required_plugins {
    huaweicloud = {
      version = ">= 1.2.0"
      source  = "github.com/huaweicloud/huaweicloud"
    }
    ansible = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/ansible"
    }
    windows-update = {
      source  = "github.com/rgl/windows-update"
      version = "~> 0.14"
    }
  }
}

source "huaweicloud-ecs" "windows_cis" {
  access_key = var.hw_access_key
  secret_key = var.hw_secret_key
  project_id = var.hw_project_id
  region     = var.hw_region
  auth_url   = "https://iam.my-kualalumpur-1.alphaedge.tmone.com.my/v3"
  insecure   = true

  image_name        = "win2022-cis-v${var.image_version}"
  source_image_name = "Windows Server 2022 Standard 64bit English" # Verify exact Huawei image name
  availability_zone = "my-kualalumpur-1b"
  flavor            = "c7n.large.4"

  vpc_id          = var.hw_vpc_id
  subnets         = [var.hw_subnet_id]
  security_groups = [var.hw_security_group_id]

  floating_ip = var.hw_eip_id

  # Huawei Windows communicator configuration
  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_use_ssl  = true
  winrm_insecure = true
  winrm_use_ntlm = true
  winrm_port     = 5986
  winrm_timeout  = "30m"

  # Huawei requires the password to be set for the Administrator account
  user_data_file = var.user_data_file
}

build {
  sources = ["source.huaweicloud-ecs.windows_cis"]

  # 1. Bootstrap WinRM (and WinHTTP Proxy!)
  provisioner "powershell" {
    script = "${path.root}/../packer-huawei-windows/scripts/bootstrap-winrm.ps1"
  }

  # 2. Install OpenSSH Server
  provisioner "powershell" {
    inline = [
      "Write-Output 'Installing OpenSSH Server...'",
      "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0",
      "Write-Output 'Initializing sshd to generate sshd_config...'",
      "Start-Service sshd",
      "Stop-Service sshd"
    ]
  }

  # 3. Main CIS Hardening (Replaces Ansible)
  provisioner "powershell" {
    elevated_user     = "Administrator"
    elevated_password = build.WinRMPassword
    script            = "${path.root}/../packer-huawei-windows/scripts/Invoke-CISRemediation-Combined.ps1"
  }
  

  # 4. Flush GPO/Registry
  provisioner "windows-restart" {
    restart_timeout = "15m"
  }

  # 5. Create sysadmin user (since Cloudbase-init won't do it like Azure agent does)
  provisioner "powershell" {
    inline = [
      "Write-Output 'Creating sysadmin local admin account...'",
      "$pw = ConvertTo-SecureString '${var.windows_admin_pass}' -AsPlainText -Force",
      "New-LocalUser -Name 'sysadmin' -Password $pw -PasswordNeverExpires -AccountNeverExpires -ErrorAction SilentlyContinue | Out-Null",
      "Add-LocalGroupMember -Group 'Administrators' -Member 'sysadmin' -ErrorAction SilentlyContinue",
      "New-Item -ItemType Directory -Force -Path 'C:\\Users\\sysadmin\\.ssh' | Out-Null"
    ]
  }

  # 6. Inject the CIS scripts from your existing directory
  provisioner "file" {
    source      = "${path.root}/../packer-huawei-windows/files/"
    destination = "C:/Windows/Setup/Scripts/"
  }

  provisioner "powershell" {
    script = "${path.root}/../packer-huawei-windows/scripts/finalize.ps1"
  }

  provisioner "powershell" {
    inline = [
      "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name 'RestrictReceivingNTLMTraffic' -Value 2 -Type DWord -Force",
      "$winrmPaths = @('HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client', 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service')",
      "foreach ($path in $winrmPaths) { if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }; Set-ItemProperty -Path $path -Name 'AllowBasic' -Value 0 -Type DWord -Force; Set-ItemProperty -Path $path -Name 'AllowUnencryptedTraffic' -Value 0 -Type DWord -Force }",
      "Remove-Item -Path WSMan:\\Localhost\\Listener\\* -Recurse -Force -ErrorAction SilentlyContinue",
      "Remove-NetFirewallRule -DisplayName 'WinRM-HTTPS' -ErrorAction SilentlyContinue",
      "Get-ChildItem Cert:\\LocalMachine\\My | Where-Object {$_.Subject -eq 'CN=packer-build'} | Remove-Item -Force",
      "C:\\Program` Files\\Cloudbase` Solutions\\Cloudbase-Init\\bin\\Invoke-Sysprep.ps1 -SysprepPath 'C:\\Windows\\System32\\Sysprep\\Sysprep.exe'"
    ]
    skip_clean        = true
  }
}