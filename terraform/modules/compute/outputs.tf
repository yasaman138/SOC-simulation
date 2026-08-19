output "instances" {
  description = "Configured compute infrastructure instances"
  value       = local.instances
}

output "ad_dc_hostname" {
  description = "Domain Controller hostname"
  value       = local.instances.ad_dc01.hostname
}

output "linux_srv_hostname" {
  description = "Linux Server hostname"
  value       = local.instances.linux_srv01.hostname
}
