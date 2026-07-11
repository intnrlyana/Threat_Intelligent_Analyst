from backend.src.providers.virustotal_provider import VirusTotalProvider


def test_ip_resolution_relationship_ids_are_normalized_to_domains(monkeypatch) -> None:
    provider = VirusTotalProvider()

    def fake_get(path: str):
        if "resolutions" in path:
            return {"data": [{"type": "resolution", "id": "45.83.122.10nanoset.xyz"}]}
        return {"data": []}

    monkeypatch.setattr(provider, "_get", fake_get)
    result = provider.lookup_relationships("ip", "45.83.122.10")

    assert result is not None
    assert result.related_entities[0].entity_type == "domain"
    assert result.related_entities[0].value == "nanoset.xyz"
