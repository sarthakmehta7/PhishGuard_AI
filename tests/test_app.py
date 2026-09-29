import os

os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("SESSION_COOKIE_SECURE", "0")

import pytest

import app as app_module


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "model", object())
    monkeypatch.setattr(app_module, "full_analysis", lambda url: {
        "features": {}, "feature_vector": [0] * len(app_module.FEATURE_COLS),
        "hostname": "example.com", "ssl": {"valid": True},
        "dns": {"resolves": True}, "http": {"status_code": 200},
        "whois": {"age_days": 1000}, "gsb": {}, "reasons": [],
        "scanned_at": "test",
    })
    monkeypatch.setattr(app_module, "is_blacklisted", lambda url: False)
    monkeypatch.setattr(app_module, "save_scan", lambda **kwargs: 1)
    monkeypatch.setattr(app_module, "get_recommendations", lambda label, analysis: [])

    class FakeModel:
        def predict(self, x): return [0]
        def predict_proba(self, x): return [[0.95, 0.04, 0.01]]
    monkeypatch.setattr(app_module, "model", FakeModel())
    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with app_module.app.test_client() as c:
        yield c


def test_scan_rejects_missing_url(client):
    response = client.post("/scan", json={})
    assert response.status_code == 400
    assert response.get_json()["error"] == "No URL provided."


def test_scan_rejects_long_url(client):
    response = client.post("/scan", json={"url": "https://example.com/" + "a" * 2048})
    assert response.status_code == 400


def test_bulk_scan_validates_shape(client):
    response = client.post("/api/bulk-scan", json={"urls": [123]})
    assert response.status_code == 400


def test_security_headers(client):
    response = client.get("/")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "SAMEORIGIN"


def test_private_scan_target_is_blocked(monkeypatch):
    monkeypatch.setattr(app_module, "_public_ips", lambda host: ["192.168.1.10"])
    ok, reason = app_module.is_public_scan_target("internal.example")
    assert ok is False
    assert "private" in reason.lower()
