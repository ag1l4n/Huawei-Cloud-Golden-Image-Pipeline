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
  default = "my-kualalumpur-1" # Change to your target region
}

variable "hw_vpc_id" {
  type    = string
}

variable "hw_subnet_id" {
  type    = string
}

variable "hw_security_group_id" {
  type    = string
}

variable "image_version" {
  type        = string
  description = "The dynamic version of the image injected by GitHub Actions"
  default     = "1.0.0"
}

variable "local_admin_password" {
  type        = string
  description = "Temporary Administrator password for WinRM connection"
  sensitive   = true
  # You can provide a default fallback here, or rely strictly on the pipeline secret
  default     = "HwCloud!WinBuild2026#" 
}