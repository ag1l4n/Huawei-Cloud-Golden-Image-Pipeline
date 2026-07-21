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
  flavor            = "c6.large.2"

  vpc_id          = var.hw_vpc_id
  subnets         = [var.hw_subnet_id]
  security_groups = [var.hw_security_group_id]

  floating_ip = var.hw_eip_id

  # Huawei Windows communicator configuration
  communicator   = "winrm"
  winrm_username = "Administrator"
  # winrm_password = var.windows_admin_pass
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
  # NOTE: This requires internet access to Microsoft servers! It will succeed
  # because we configure netsh winhttp proxy in bootstrap-winrm.ps1 below.
  provisioner "powershell" {
    elevated_user     = "Administrator"
    elevated_password = build.WinRMPassword
    inline = [
      "Write-Output 'Installing OpenSSH Server...'",
      "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
    ]
  }

  # 3. Main CIS Hardening via Ansible
  provisioner "ansible" {
    playbook_file   = "${path.root}/../ansible/windows-cis-l1.yml"
    user            = "Administrator"
    
    # Keep this FALSE! This tells Ansible on the runner NOT to use a proxy
    # to initiate the WinRM connection to the target VM's private IP.
    use_proxy       = false 
    
    extra_arguments = [
      "-e", "ansible_winrm_scheme=https",
      "-e", "ansible_winrm_transport=ntlm",
      "-e", "ansible_winrm_server_cert_validation=ignore",
      "-e", "ansible_winrm_operation_timeout_sec=300",
      "-e", "ansible_winrm_read_timeout_sec=330",
      "--skip-tags", "winrm_connectivity",
      "-e", "@./../ansible/cis-overrides.yml",
    ]
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

  # 6. Inject the CIS scripts from your existing Azure directory
  provisioner "file" {
    source      = "${path.root}/../packer-huawei-windows/files/"
    destination = "C:/Windows/Setup/Scripts/"
  }

  provisioner "powershell" {
    script = "${path.root}/../packer-huawei-windows/scripts/finalize.ps1"
  }

  provisioner "powershell" {
    inline = [
      "Remove-Item -Path WSMan:\\Localhost\\Listener\\* -Recurse -Force -ErrorAction SilentlyContinue",
      "Remove-NetFirewallRule -DisplayName 'WinRM-HTTPS' -ErrorAction SilentlyContinue",
      "Get-ChildItem Cert:\\LocalMachine\\My | Where-Object {$_.Subject -eq 'CN=packer-build'} | Remove-Item -Force",
      "C:\\Program` Files\\Cloudbase` Solutions\\Cloudbase-Init\\bin\\Invoke-Sysprep.ps1 -SysprepPath 'C:\\Windows\\System32\\Sysprep\\Sysprep.exe'"
    ]
    skip_clean        = true
    expect_disconnect = true
  }
}