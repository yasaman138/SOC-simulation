variable "environment" {
  type        = string
  description = "Deployment environment name"
  default     = "lab-development"
}

variable "siem_ip" {
  type        = string
  description = "IP address for SIEM Central Collector"
  default     = "172.28.90.10"
}

variable "http_ingest_port" {
  type        = number
  description = "HTTP Event Ingestion Port"
  default     = 8088
}

variable "syslog_udp_port" {
  type        = number
  description = "Syslog UDP Ingestion Port"
  default     = 5514
}
