# =============================================================================
# huawei-golden-image-factory / packer-windows / windows-server-2022.pkr.hcl
#
# Builds a CIS Level 1 hardened Windows Server 2022 golden image on Huawei Cloud.
#
# Provisioner order — do not reorder:
#   1. bootstrap-winrm.ps1         Keep WinRM alive for Ansible
#   2. windows-update              Patch Tuesday updates before hardening
#   3. ansible (--skip winrm_conn) CIS L1 main pass; WinRM-killers skipped
#   4. windows-restart             Flush GPO/registry writes to disk
#   5. apply-winrm-cis-controls.ps1 Apply WinRM-disabling controls via registry
# =============================================================================

packer {
  required_version = ">= 1.9.0"

  required_plugins {
    huaweicloud = {
      source  = "github.com/huaweicloud/huaweicloud"
      version = ">= 1.2.0"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = "~> 1.1"
    }
    windows-update = {
      source  = "github.com/rgl/windows-update"
      version = "~> 0.14"
    }
  }
}

# =============================================================================
# Variables — Names aligned with Huawei infrastructure pipeline
# =============================================================================
variable "hw_access_key" {
  type      = string
  sensitive = true
}

variable "hw_secret_key" {
  type      = string
  sensitive = true
}

variable "hw_project_id" {
  type      = string
  sensitive = true
}

variable "hw_region" {
  type    = string
  default = "my-kualalumpur-1"
}

variable "hw_vpc_id" {
  type = string
}

variable "hw_subnet_id" {
  type = string
}

variable "hw_security_group_id" {
  type = string
}

variable "image_version" {
  type    = string
  default = "1.0.0"
}

# Equivalent to Azure's D4s_v5 (4 vCPU / 16 GB). Map to your specific Huawei c6/c7 flavor if needed.
variable "flavor" {
  type    = string
  default = "c6.xlarge.4" 
}

variable "os_disk_size_gb" {
  type    = number
  default = 128
}

variable "local_admin_username" {
  type    = string
  default = "sysadmin"
}

variable "local_admin_password" {
  type      = string
  sensitive = true
}

variable "tags" {
  type = map(string)
  default = {
    image_type  = "golden"
    os          = "windows-server-2022"
    cis_level   = "l1"
    build_tool  = "packer"
    managed_by  = "golden-image-factory"
    cloud       = "huawei"
  }
}

# =============================================================================
# Locals
# =============================================================================
locals {
  timestamp  = formatdate("YYYYMMDD-hhmmss", timestamp())
  image_name = "win2022-cis-l1-v${var.image_version}-${local.timestamp}"

  ansible_base_args = [
    "-e", "ansible_connection=winrm",
    "-e", "ansible_winrm_scheme=http", # Notice: HTTP used initially for build time unless Huawei image explicitly embeds an active WinRM HTTPS cert out-of-the-box
    "-e", "ansible_winrm_server_cert_validation=ignore",
    "-e", "ansible_winrm_transport=basic",
    "-e", "ansible_winrm_operation_timeout_sec=120",
    "-e", "ansible_winrm_read_timeout_sec=150",
    "-e", "ansible_user=${var.local_admin_username}"
  ]
}

# =============================================================================
# Source: Huawei Cloud ECS
# =============================================================================
source "huaweicloud-ecs" "win2022_cis_l1" {
  # --- Authentication & Infrastructure setup ---
  access_key = var.hw_access_key
  secret_key = var.hw_secret_key
  project_id = var.hw_project_id
  region     = var.hw_region

  image_name        = local.image_name
  source_image_name = "Windows Server 2022 Standard 64bit"
  flavor            = var.flavor
  volume_size       = var.os_disk_size_gb
  volume_type       = "SSD"

  vpc_id          = var.hw_vpc_id
  subnets         = [var.hw_subnet_id]
  security_groups = [var.hw_security_group_id]

  # --- User Data Injection ---
  # Inject the script to configure SSL/HTTPS before Packer attempts connection
  user_data_file = "${path.root}/scripts/bootstrap-winrm-https.ps1"

  # --- Communicator Setup (HTTPS / Port 5986) ---
  communicator   = "winrm"
  winrm_port     = 5986
  winrm_use_ssl  = true
  winrm_insecure = true   # Required because the generated certificate is self-signed
  winrm_timeout  = "45m"  # Allow extra time for first-boot User Data execution
  winrm_username = var.local_admin_username
  winrm_password = var.local_admin_password

  eip_type           = "5_bgp"
  eip_bandwidth_size = 5

  tags = var.tags
}

# =============================================================================
# Build Pipeline
# =============================================================================
build {
  name    = "win2022-cis-l1"
  sources = ["source.huaweicloud-ecs.win2022_cis_l1"]

  # Error handling debug mechanism inherited from your Huawei template style
  error-cleanup-provisioner "powershell" {
    inline = [
      "Write-Output 'Build failed — VM kept alive for 10 minutes for debugging'",
      "Start-Sleep -Seconds 600"
    ]
  }

  # Step 1 — Re-enforce WinRM configuration
  provisioner "powershell" {
    script = "${path.root}/../packer-windows/scripts/bootstrap-winrm.ps1"
  }

  # Step 2 — Windows Updates before applying hard compliance baselines
  provisioner "windows-update" {
    search_criteria = "IsInstalled=0"
    filters = [
      "ExcludeRebootRequired=0",
      "IncludeX86=0"
    ]
    update_timeout = "30m"
  }

  provisioner "powershell" {
    inline = [
      "Write-Output 'Installing OpenSSH Server...'",
      "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
    ]
  }

  # Step 3 — CIS L1 main hardening pass via Ansible
  provisioner "ansible" {
    playbook_file   = "${path.root}/../ansible/windows-cis-l1.yml"
    user            = var.local_admin_username
    use_proxy       = false
    extra_arguments = concat(local.ansible_base_args, [
      "-e", "ansible_password=${var.local_admin_password}",
      "--skip-tags", "winrm_connectivity",
      "-e", "@${path.root}/../ansible/cis-overrides.yml"
    ])
  }

  # Step 4 — Flush registry writes and update policies
  provisioner "windows-restart" {
    restart_timeout       = "15m"
    restart_check_command = "powershell -command \"& {Write-Output 'restarted'}\""
  }

  # Re-assert localized persistent baseline user config
  provisioner "powershell" {
    inline = [
      "Write-Output 'Configuring local admin architecture...'",
      "$pw = ConvertTo-SecureString '${var.local_admin_password}' -AsPlainText -Force",
      "New-LocalUser -Name '${var.local_admin_username}' -Password $pw -PasswordNeverExpires -AccountNeverExpires -ErrorAction SilentlyContinue | Out-Null",
      "Add-LocalGroupMember -Group 'Administrators' -Member '${var.local_admin_username}' -ErrorAction SilentlyContinue",
      
      "New-Item -ItemType Directory -Force -Path 'C:\\Users\\${var.local_admin_username}\\.ssh' | Out-Null",
      "Write-Output 'Profile skeleton established.'"
    ]
  }

  # Step 4.5 — Inject explicit CIS profile configurations
  provisioner "file" {
    source      = "${path.root}/files/"
    destination = "C:/Windows/Setup/Scripts/"
  }

  # Step 5 — Apply final WinRM killing baselines (Registry cuts)
  provisioner "powershell" { 
    script = "${path.root}/../packer-windows/scripts/finalize.ps1"
  }

  # Manifest output tracking
  post-processor "manifest" {
    output     = "${path.root}/manifest.json"
    strip_path = true
    custom_data = {
      image_name    = local.image_name
      image_version = var.image_version
      cis_level     = "L1"
      cloud         = "huawei"
      build_date    = local.timestamp
    }
  }
}