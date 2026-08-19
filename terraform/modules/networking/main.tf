# Enterprise Lab Network Tier Definitions and Access Control Lists

locals {
  subnets = {
    simulation = {
      name        = "${var.environment}-simulation-net"
      cidr        = var.simulation_cidr
      trust_level = "untrusted"
    }
    corp_internal = {
      name        = "${var.environment}-corp-internal-net"
      cidr        = var.corp_internal_cidr
      trust_level = "internal_trusted"
    }
    app_tier = {
      name        = "${var.environment}-app-tier-net"
      cidr        = var.app_tier_cidr
      trust_level = "semi_trusted_app"
    }
    secmon = {
      name        = "${var.environment}-secmon-net"
      cidr        = var.secmon_cidr
      trust_level = "security_management"
    }
  }

  security_rules = [
    {
      name        = "allow-simulation-to-edge-proxy"
      source_cidr = var.simulation_cidr
      dest_cidr   = var.app_tier_cidr
      port        = 8000
      protocol    = "tcp"
      action      = "allow"
    },
    {
      name        = "allow-app-to-db"
      source_cidr = var.app_tier_cidr
      dest_cidr   = var.app_tier_cidr
      port        = 5432
      protocol    = "tcp"
      action      = "allow"
    },
    {
      name        = "allow-all-to-siem-http"
      source_cidr = "0.0.0.0/0"
      dest_cidr   = var.secmon_cidr
      port        = 8088
      protocol    = "tcp"
      action      = "allow"
    },
    {
      name        = "allow-corp-to-siem-syslog"
      source_cidr = var.corp_internal_cidr
      dest_cidr   = var.secmon_cidr
      port        = 5514
      protocol    = "udp"
      action      = "allow"
    },
    {
      name        = "deny-simulation-to-corp"
      source_cidr = var.simulation_cidr
      dest_cidr   = var.corp_internal_cidr
      port        = 0
      protocol    = "all"
      action      = "deny"
    }
  ]
}
