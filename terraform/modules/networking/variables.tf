variable "environment" {
  type        = string
  description = "Deployment environment name"
  default     = "lab-development"
}

variable "simulation_cidr" {
  type        = string
  description = "CIDR block for Simulation / External DMZ network"
  default     = "172.28.10.0/24"
}

variable "corp_internal_cidr" {
  type        = string
  description = "CIDR block for Corporate Internal network"
  default     = "172.28.20.0/24"
}

variable "app_tier_cidr" {
  type        = string
  description = "CIDR block for Application and Database tier"
  default     = "172.28.30.0/24"
}

variable "secmon_cidr" {
  type        = string
  description = "CIDR block for Security Monitoring and SIEM network"
  default     = "172.28.90.0/24"
}
