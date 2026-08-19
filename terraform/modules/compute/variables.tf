variable "environment" {
  type        = string
  description = "Deployment environment name"
  default     = "lab-development"
}

variable "ad_dc_ip" {
  type        = string
  description = "IP address for Active Directory Domain Controller"
  default     = "172.28.20.10"
}

variable "linux_srv_ip" {
  type        = string
  description = "IP address for Enterprise Linux Server"
  default     = "172.28.20.15"
}

variable "win_wkstn_ip" {
  type        = string
  description = "IP address for Windows Workstation"
  default     = "172.28.20.25"
}

variable "app_portal_ip" {
  type        = string
  description = "IP address for Enterprise Web Portal"
  default     = "172.28.30.10"
}

variable "app_db_ip" {
  type        = string
  description = "IP address for Application Database"
  default     = "172.28.30.20"
}
