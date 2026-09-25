from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from api.dependencies import get_client_ip
from config import config
from main import app


def test_forwarded_for_is_ignored_from_untrusted_client(monkeypatch):
    monkeypatch.setattr(config.api, "trusted_proxy_ips", [])
    request = SimpleNamespace(
        headers={"x-forwarded-for": "203.0.113.10"},
        client=SimpleNamespace(host="198.51.100.20"),
    )

    assert get_client_ip(request) == "198.51.100.20"


def test_forwarded_for_is_used_from_trusted_proxy(monkeypatch):
    monkeypatch.setattr(config.api, "trusted_proxy_ips", ["198.51.100.20"])
    request = SimpleNamespace(
        headers={"x-forwarded-for": "203.0.113.10, 198.51.100.20"},
        client=SimpleNamespace(host="198.51.100.20"),
    )

    assert get_client_ip(request) == "203.0.113.10"


@pytest.mark.asyncio
async def test_health_details_requires_authentication():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        public_health = await client.get("/health")
        detailed_health = await client.get("/health/details")

    assert public_health.status_code == 200
    assert public_health.json() == {"status": "healthy", "service": "SwarmSentinel"}
    assert detailed_health.status_code == 401