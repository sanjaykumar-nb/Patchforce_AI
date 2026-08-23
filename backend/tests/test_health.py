"""
PatchForge AI - Phase 2 Health & Observability Unit Tests
========================================================
Validates that FastAPI core routes, observability probes, and middleware
operate correctly with proper status codes and correlation headers.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "PatchForge AI"
    assert data["status"] == "operational"
    assert "documentation" in data
    assert "X-Request-ID" in response.headers
    assert "X-Process-Time-Ms" in response.headers


def test_health_liveness_probe():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "PatchForge AI"
    assert "timestamp" in data


def test_readiness_probe():
    response = client.get("/api/v1/ready")
    assert response.status_code in [200, 503]
    data = response.json()
    assert "components" in data
    assert "database" in data["components"]
    assert "redis_broker" in data["components"]


def test_metrics_endpoint():
    response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "PatchForge AI"
    assert "uptime_seconds" in data
    assert data["uptime_seconds"] >= 0


def test_request_id_propagation():
    custom_req_id = "test-request-id-12345"
    response = client.get("/api/v1/health", headers={"X-Request-ID": custom_req_id})
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == custom_req_id
