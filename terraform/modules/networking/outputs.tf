output "subnets" {
  description = "Configured network subnets and zones"
  value       = local.subnets
}

output "simulation_cidr" {
  description = "Simulation network CIDR"
  value       = var.simulation_cidr
}

output "corp_internal_cidr" {
  description = "Corporate internal network CIDR"
  value       = var.corp_internal_cidr
}

output "app_tier_cidr" {
  description = "Application tier CIDR"
  value       = var.app_tier_cidr
}

output "secmon_cidr" {
  description = "Security monitoring CIDR"
  value       = var.secmon_cidr
}

output "security_rules" {
  description = "Network security and firewall policy rules"
  value       = local.security_rules
}
