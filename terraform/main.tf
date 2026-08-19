# ==============================================================================
# Enterprise Attack Detection & Response Lab - Root Infrastructure Definition
# ==============================================================================

terraform {
  required_version = ">= 1.0.0"
}

module "networking" {
  source             = "./modules/networking"
  environment        = var.environment
  simulation_cidr    = var.simulation_cidr
  corp_internal_cidr = var.corp_internal_cidr
  app_tier_cidr      = var.app_tier_cidr
  secmon_cidr        = var.secmon_cidr
}

module "compute" {
  source        = "./modules/compute"
  environment   = var.environment
  ad_dc_ip      = "172.28.20.10"
  linux_srv_ip  = "172.28.20.15"
  win_wkstn_ip  = "172.28.20.25"
  app_portal_ip = "172.28.30.10"
  app_db_ip     = "172.28.30.20"
}

module "security_monitoring" {
  source           = "./modules/security_monitoring"
  environment      = var.environment
  siem_ip          = "172.28.90.10"
  http_ingest_port = 8088
  syslog_udp_port  = 5514
}
