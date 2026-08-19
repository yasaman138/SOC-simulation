output "lab_subnets" {
  description = "Enterprise Lab subnets and trust boundaries"
  value       = module.networking.subnets
}

output "lab_instances" {
  description = "Configured compute infrastructure instances"
  value       = module.compute.instances
}

output "siem_collector" {
  description = "SIEM collector configuration"
  value       = module.security_monitoring.siem_collector
}

output "siem_endpoint_url" {
  description = "SIEM HTTP Event Ingestion endpoint URL"
  value       = module.security_monitoring.siem_endpoint_url
}
