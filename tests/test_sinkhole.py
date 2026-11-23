"""Unit and integration tests for the DNS Threat Blocker & Sinkhole Web Application."""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db, get_db


@pytest.fixture(autouse=True)
def setup_database():
    """Ensure database schema is initialized before running tests."""
    init_db()


def test_health_check():
    """Test health check endpoint."""
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "dns_threat_blocker"


def test_sinkhole_catch_all_redirection():
    """Test that any intercepted domain request hits the sinkhole landing page and logs access."""
    with TestClient(app) as client:
        headers = {
            "Host": "malicious-stealer.xyz",
            "User-Agent": "Mozilla/5.0 TestBrowser/1.0",
            "X-Forwarded-For": "10.0.0.42"
        }
        response = client.get("/payload/downloader.exe", headers=headers)
        
        # Verify landing page response
        assert response.status_code == 200
        assert "Acesso Web Bloqueado" in response.text
        assert "malicious-stealer.xyz" in response.text
        assert "10.0.0.42" in response.text
        assert "DNS SINKHOLE ENGINE" in response.text

        # Verify database record in access_logs
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM access_logs WHERE domain_requested = ? ORDER BY id DESC LIMIT 1;",
                ("malicious-stealer.xyz",)
            )
            row = cursor.fetchone()
            assert row is not None
            assert row["domain_requested"] == "malicious-stealer.xyz"
            assert row["client_ip"] == "10.0.0.42"
            assert "TestBrowser" in row["user_agent"]


def test_admin_dashboard_render():
    """Test that the /admin dashboard renders metrics and audit logs correctly."""
    with TestClient(app) as client:
        response = client.get("/admin")
        assert response.status_code == 200
        assert "DNS Threat Blocker" in response.text
        assert "Painel de Telemetria SOC" in response.text
        assert "Top 5 Domínios Mais Acedidos" in response.text
        assert "Últimos 10 Registos de Auditoria" in response.text


def test_api_stats():
    """Test JSON statistics endpoint for live dashboard telemetry."""
    with TestClient(app) as client:
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_blocks" in data
        assert "unique_domains" in data
        assert "unique_clients" in data
        assert "top_domains" in data
        assert "recent_logs" in data
        assert isinstance(data["top_domains"], list)
        assert isinstance(data["recent_logs"], list)


def test_unblock_ioc_endpoint():
    """Test the IoC unblock and rollback endpoint."""
    with TestClient(app) as client:
        # First ensure an IoC is present
        from app.database import add_ioc_entry
        add_ioc_entry("false-positive-domain.com", category="Test")

        # Call unblock
        payload = {"domain": "false-positive-domain.com", "add_to_allowlist": True}
        response = client.post("/api/ioc/unblock", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["domain"] == "false-positive-domain.com"
        assert data["deleted_count"] >= 1


def test_list_iocs_endpoint():
    """Test the IoC listing endpoint with search filter."""
    with TestClient(app) as client:
        response = client.get("/api/iocs?limit=10")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "iocs" in data
        assert isinstance(data["iocs"], list)


def test_ml_analyze_endpoint():
    """Test the ML domain analysis endpoint for DGA detection."""
    with TestClient(app) as client:
        # 1. Benign domain
        res_benign = client.post("/api/ml/analyze", json={"domain": "google.com"})
        assert res_benign.status_code == 200
        data_benign = res_benign.json()
        assert data_benign["verdict"] == "BENIGN"
        assert data_benign["risk_score"] < 0.40

        # 2. DGA random string domain
        res_dga = client.post("/api/ml/analyze", json={"domain": "xzkfplwq987123jfk.xyz"})
        assert res_dga.status_code == 200
        data_dga = res_dga.json()
        assert data_dga["verdict"] in {"HIGH_RISK_DGA", "SUSPICIOUS"}
        assert data_dga["risk_score"] >= 0.40
        assert len(data_dga["signals"]) > 0

