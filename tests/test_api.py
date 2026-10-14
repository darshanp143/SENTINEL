import os
import tempfile
from fastapi.testclient import TestClient

# Set test DB before importing the app/database modules.
fd, db_path = tempfile.mkstemp(suffix=".db")
os.close(fd)
os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

from app.main import app  # noqa: E402
from app.database import Base, engine  # noqa: E402

client = TestClient(app)

def setup_function():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

def teardown_module():
    try:
        os.remove(db_path)
    except OSError:
        pass

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_ingest_and_list_event():
    response = client.post("/api/v1/events", json={
        "source": "pytest",
        "event_type": "app_started",
        "severity": "low",
        "source_ip": "192.0.2.5",
        "message": "test event",
        "metadata": {"case": "basic"},
    })
    assert response.status_code == 201
    assert response.json()["source"] == "pytest"
    assert client.get("/api/v1/events").json()[0]["message"] == "test event"

def test_suspicious_path_creates_alert():
    response = client.post("/api/v1/events", json={
        "source": "pytest-web",
        "event_type": "http_request",
        "severity": "low",
        "source_ip": "192.0.2.6",
        "message": "Request to /../../etc/passwd",
        "metadata": {"path": "/../../etc/passwd"},
    })
    assert response.status_code == 201
    alerts = client.get("/api/v1/alerts").json()
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "WEB-001"

def test_five_failed_logins_create_alert():
    for _ in range(5):
        response = client.post("/api/v1/events", json={
            "source": "pytest-auth",
            "event_type": "login_failed",
            "severity": "medium",
            "source_ip": "192.0.2.20",
            "message": "invalid credentials",
            "metadata": {"username": "demo"},
        })
        assert response.status_code == 201
    alerts = client.get("/api/v1/alerts").json()
    assert any(a["rule_id"] == "AUTH-001" for a in alerts)

def test_acknowledge_alert():
    client.post("/api/v1/events", json={
        "source": "pytest-web",
        "event_type": "http_request",
        "severity": "low",
        "source_ip": "192.0.2.8",
        "message": "Request to /.env",
        "metadata": {"path": "/.env"},
    })
    alert = client.get("/api/v1/alerts").json()[0]
    response = client.patch(f"/api/v1/alerts/{alert['id']}/acknowledge")
    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"

def test_invalid_severity_is_rejected():
    response = client.post("/api/v1/events", json={
        "source": "pytest",
        "event_type": "app_started",
        "severity": "super-high",
        "message": "invalid severity",
    })
    assert response.status_code == 422
