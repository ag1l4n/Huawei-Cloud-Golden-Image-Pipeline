variable "hw_access_key" {
  type      = string
  sensitive = true
}

variable "hw_secret_key" {
  type = string
  sensitive = true
}

variable "hw_project_id" {
  type = string
  sensitive = true
}

variable "hw_region" {
  type = string
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
  type = string
  default = "1.0.0"
}

variable "user_data_file" {
  type = string
  default = ""
}

variable "windows_admin_pass" {
  type = string
  sensitive = true
}