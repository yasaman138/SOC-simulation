"""Unit tests for Docker Compose and Terraform IaC definitions."""

from pathlib import Path
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


def test_docker_compose_structure():
    compose_path = ROOT_DIR / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist"

    with open(compose_path, "r", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)

    assert "networks" in compose_data
    assert "services" in compose_data

    # Verify 4 networks
    assert "simulation_net" in compose_data["networks"]
    assert "corp_internal_net" in compose_data["networks"]
    assert "app_tier_net" in compose_data["networks"]
    assert "secmon_net" in compose_data["networks"]

    # Verify key services
    services = compose_data["services"]
    assert "siem-collector" in services
    assert "ad-dc01" in services
    assert "linux-srv01" in services
    assert "vulnapp" in services
    assert "app-db" in services
    assert "edge-proxy" in services


def test_terraform_files_exist_and_non_empty():
    tf_dir = ROOT_DIR / "terraform"
    assert (tf_dir / "main.tf").exists()
    assert (tf_dir / "variables.tf").exists()
    assert (tf_dir / "outputs.tf").exists()
    assert (tf_dir / "terraform.tfvars.example").exists()

    modules_dir = tf_dir / "modules"
    assert (modules_dir / "networking" / "main.tf").exists()
    assert (modules_dir / "compute" / "main.tf").exists()
    assert (modules_dir / "security_monitoring" / "main.tf").exists()
