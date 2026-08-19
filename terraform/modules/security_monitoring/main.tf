# Security Monitoring and Centralized SIEM Infrastructure

locals {
  secmon_stack = {
    siem_collector = {
      name             = "Centralized SIEM & Telemetry Aggregator"
      hostname         = "siem.secmon.local"
      ip_address       = var.siem_ip
      http_ingest_port = var.http_ingest_port
      syslog_udp_port  = var.syslog_udp_port
      schema_format    = "Elastic Common Schema (ECS)"
      retention_days   = 30
    }
  }

  monitored_sources = [
    {
      source_name = "corp-ad-dc01"
      category    = "active_directory"
      protocol    = "syslog/http"
      data_types  = ["event_log_4624", "event_log_4625", "event_log_4768", "event_log_4769"]
    },
    {
      source_name = "corp-linux-srv01"
      category    = "linux_os"
      protocol    = "syslog_udp"
      data_types  = ["sshd_auth", "auditd_execve", "sudo_commands"]
    },
    {
      source_name = "app-portal"
      category    = "web_application"
      protocol    = "http_json"
      data_types  = ["access_logs", "auth_events", "sql_queries", "command_executions"]
    }
  ]
}
