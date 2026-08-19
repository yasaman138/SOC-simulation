# Enterprise Lab Compute Instances and Virtual Machine Allocations

locals {
  instances = {
    ad_dc01 = {
      hostname    = "dc01.corp.enterprise.local"
      ip_address  = var.ad_dc_ip
      os          = "Windows Server 2022 Datacenter"
      role        = "Primary Active Directory Domain Controller"
      domain      = "CORP.ENTERPRISE.LOCAL"
    }
    linux_srv01 = {
      hostname    = "linux-srv01.corp.enterprise.local"
      ip_address  = var.linux_srv_ip
      os          = "Ubuntu 22.04 LTS"
      role        = "Internal Linux Application & SSH Bastion Server"
      domain      = "CORP.ENTERPRISE.LOCAL"
    }
    win_wkstn10 = {
      hostname    = "wkstn-win10.corp.enterprise.local"
      ip_address  = var.win_wkstn_ip
      os          = "Windows 10 Enterprise"
      role        = "Enterprise Employee Workstation"
      domain      = "CORP.ENTERPRISE.LOCAL"
    }
    app_portal = {
      hostname    = "portal.app.local"
      ip_address  = var.app_portal_ip
      os          = "Linux Container (FastAPI/Python)"
      role        = "Enterprise Web Application & API Portal"
      domain      = "app.local"
    }
    app_db = {
      hostname    = "db01.app.local"
      ip_address  = var.app_db_ip
      os          = "PostgreSQL 15 Container"
      role        = "Backend Relational Database"
      domain      = "app.local"
    }
  }
}
