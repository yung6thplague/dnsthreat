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
