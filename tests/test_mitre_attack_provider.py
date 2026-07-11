from backend.src.providers.mitre_attack_provider import MitreAttackProvider


MINI_STIX_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "intrusion-set",
            "id": "intrusion-set--apt29",
            "name": "APT29",
            "aliases": ["APT 29", "Cozy Bear"],
            "external_references": [{"source_name": "mitre-attack", "external_id": "G0016", "url": "https://attack.mitre.org/groups/G0016/"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--powershell",
            "name": "PowerShell",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001", "url": "https://attack.mitre.org/techniques/T1059/001/"}],
        },
        {
            "type": "relationship",
            "id": "relationship--uses",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--apt29",
            "target_ref": "attack-pattern--powershell",
            "description": "APT29 has used PowerShell for execution.",
        },
    ],
}


def test_mitre_resolves_actor_alias_and_real_technique_id() -> None:
    record = MitreAttackProvider(bundle=MINI_STIX_BUNDLE).lookup_actor("Cozy Bear")

    assert record is not None
    assert record.actor_id == "G0016"
    assert record.known_ttps[0].technique_id == "T1059.001"
    assert record.known_ttps[0].technique_name == "PowerShell"


def test_mitre_does_not_fabricate_unknown_actor() -> None:
    assert MitreAttackProvider(bundle=MINI_STIX_BUNDLE).lookup_actor("Invented Group") is None
