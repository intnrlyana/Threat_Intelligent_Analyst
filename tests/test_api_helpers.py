import httpx

from backend.src.providers import api_helpers


def test_get_json_uses_shared_client_and_phase_specific_timeouts(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_get(url: str, **kwargs: object) -> httpx.Response:
        captured["url"] = url
        captured["timeout"] = kwargs["timeout"]
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr(api_helpers._CLIENT, "get", fake_get)

    result = api_helpers.get_json(
        provider="Test",
        url="https://provider.example/data",
        timeout=12,
        connect_timeout=2.5,
        write_timeout=4.0,
        pool_timeout=1.5,
    )

    assert result == {"ok": True}
    assert captured["url"] == "https://provider.example/data"
    timeout = captured["timeout"]
    assert isinstance(timeout, httpx.Timeout)
    assert timeout.connect == 2.5
    assert timeout.read == 12.0
    assert timeout.write == 4.0
    assert timeout.pool == 1.5
