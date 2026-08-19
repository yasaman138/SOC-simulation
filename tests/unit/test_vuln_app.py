"""Unit tests for Application Tier and Intentionally Vulnerable Web App."""


def test_app_health(vuln_app_client):
    res = vuln_app_client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"


def test_app_login_flow(vuln_app_client, event_store):
    initial_count = event_store.count()
    # Success
    res = vuln_app_client.post("/api/v1/auth/login", json={"username": "jdoe", "password": "LabPassword123!"})
    assert res.status_code == 200
    assert res.json()["status"] == "authenticated"

    # Failure
    res_fail = vuln_app_client.post("/api/v1/auth/login", json={"username": "jdoe", "password": "wrong"})
    assert res_fail.status_code == 401
    assert event_store.count() >= initial_count + 2


def test_sqli_endpoint(vuln_app_client, event_store):
    # Standard query
    res = vuln_app_client.get("/api/v1/employees/search?query=John")
    assert res.status_code == 200
    assert res.json()["count"] >= 1

    # SQL Injection payload query
    res_sqli = vuln_app_client.get("/api/v1/employees/search?query=' OR 1=1 --")
    assert res_sqli.status_code == 200
    assert res_sqli.json()["count"] >= 4


def test_command_injection_endpoint(vuln_app_client):
    res = vuln_app_client.post("/api/v1/tools/ping", json={"target": "127.0.0.1; whoami"})
    assert res.status_code == 200
    assert "www-data" in res.json()["output"]


def test_bola_idor_endpoint(vuln_app_client):
    res = vuln_app_client.get("/api/v1/documents/DOC-9001?user_id=1")
    assert res.status_code == 200
    assert res.json()["doc_id"] == "DOC-9001"


def test_ldap_injection_endpoint(vuln_app_client):
    res = vuln_app_client.get("/api/v1/auth/directory-lookup?user=*")
    assert res.status_code == 200
    assert res.json()["results_count"] >= 4


def test_ssrf_endpoint(vuln_app_client):
    res = vuln_app_client.post("/api/v1/integrations/webhook-test", json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert res.status_code == 200
    assert res.json()["ssrf_target_detected"] is True
