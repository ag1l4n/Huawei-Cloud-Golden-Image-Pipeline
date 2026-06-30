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
  }
}

source "huaweicloud-ecs" "rocky_cis" {
  access_key  = var.hw_access_key
  secret_key  = var.hw_secret_key
  project_id  = var.hw_project_id
  region      = var.hw_region
  auth_url    = "https://iam.my-kualalumpur-1.alphaedge.tmone.com.my/v3"
  insecure    = true

  image_name        = "rocky9-cis-v${var.image_version}"
  source_image_name = "Rocky Linux 9.0 64bit"
  flavor            = "c6.large.2"

  vpc_id          = var.hw_vpc_id
  subnets         = [var.hw_subnet_id]
  security_groups = [var.hw_security_group_id]

  ssh_username                  = "root"
  ssh_timeout                   = "10m"
  ssh_handshake_attempts        = 50

  eip_type           = "5_bgp"
  eip_bandwidth_size = 5

  user_data_file = var.user_data_file
}

build {
  sources = [
    "source.huaweicloud-ecs.rocky_cis"
    ]
  
  error-cleanup-provisioner "shell" {
    inline = ["echo 'Build failed — VM kept alive for 10 minutes for debugging'", "sleep 600"]
  }

  provisioner "shell" {
    inline = [
      "echo '--- Cleaning up temporary Packer SSH rules ---'",
      "sudo rm -f /etc/ssh/sshd_config.d/00-packer-temp.conf",
      
      "echo '--- Creating sysadmin user for the Pipeline Scanner ---'",
      "sudo useradd -m -s /bin/bash sysadmin || true",
      "sudo echo 'sysadmin ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sysadmin",
      
      "echo '--- Fixing Cloud-Init to inject future keys into sysadmin ---'",
      "sudo mkdir -p /etc/cloud/cloud.cfg.d",
      "sudo echo -e 'system_info:\\n  default_user:\\n    name: sysadmin' > /etc/cloud/cloud.cfg.d/99-sysadmin.cfg"
    ]
  }

  provisioner "ansible" {
    playbook_file   = "../ansible/rhel-hardening-playbook.yml"
    user            = "root"
    use_proxy       = false
    extra_arguments = [
      "--extra-vars", "cloud_platform=huawei",
      "--extra-vars", "ansible_python_interpreter=/usr/bin/python3"
    ]
  }

  provisioner "ansible" {
    playbook_file = "../ansible/rhel-remediations-l1-VM_adjusted.yml"
    user          = "root"
    use_proxy     = false
    extra_arguments = [
      "--extra-vars", "ansible_python_interpreter=/usr/bin/python3"
    ]
  }

  provisioner "shell" {
    inline = [
      "sudo cloud-init clean --logs",
      "sudo truncate -s 0 /etc/machine-id",
      "sudo mkdir -p /var/lib/dbus",
      "sudo rm -f /var/lib/dbus/machine-id",
      "sudo ln -s /etc/machine-id /var/lib/dbus/machine-id",
      "sudo rm -f /root/.ssh/authorized_keys",
      "sudo rm -f /home/*/.ssh/authorized_keys",
      "cat /dev/null > ~/.bash_history && history -c",
      "sync"
    ]
  }

  post-processor "manifest" {
    output     = "${path.root}/manifest.json"
    strip_path = true
    custom_data = {
      image_version = var.image_version
      cis_level     = "L1"
      cloud         = "huawei"
    }
  }
}
