output "siem_collector" {
  description = "Configured SIEM Collector instance"
  value       = local.secmon_stack.siem_collector
}

output "monitored_sources" {
  description = "Telemetry sources configured for ingestion"
  value       = local.monitored_sources
}

output "siem_endpoint_url" {
  description = "HTTP telemetry ingestion endpoint"
  value       = "http://${var.siem_ip}:${var.http_ingest_port}/api/v1/events"
}
