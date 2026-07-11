"""MITRE ATT&CK Enterprise STIX 2.1 actor-to-technique provider."""

from functools import lru_cache

from backend.src.config import Settings, get_settings
from backend.src.providers.api_helpers import get_json
from backend.src.providers.models import ProviderFailure, ProviderRecord, ProviderResult, TechniqueRecord
from backend.src.tools.schemas import SourceReference


class MitreAttackProvider:
    DATA_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

    def __init__(self, settings: Settings | None = None, bundle: dict[str, object] | None = None) -> None:
        self.settings = settings or get_settings()
        self._bundle = bundle

    @staticmethod
    def _reference(item: dict[str, object]) -> tuple[str | None, str | None]:
        for reference in item.get("external_references", []):
            if isinstance(reference, dict) and reference.get("source_name") == "mitre-attack":
                external_id = str(reference["external_id"]) if reference.get("external_id") else None
                url = str(reference["url"]) if reference.get("url") else None
                return external_id, url
        return None, None

    @classmethod
    @lru_cache(maxsize=1)
    def _download(cls, timeout: int) -> dict[str, object] | ProviderFailure | None:
        return get_json(provider="MITRE ATT&CK", url=cls.DATA_URL, timeout=timeout)

    def lookup_actor(self, actor_name: str) -> ProviderResult:
        bundle = self._bundle or self._download(self.settings.api_timeout_seconds)
        if bundle is None or isinstance(bundle, ProviderFailure):
            return bundle
        objects = [item for item in bundle.get("objects", []) if isinstance(item, dict)]
        normalized = actor_name.strip().casefold().replace(" ", "")
        actor = next(
            (
                item for item in objects
                if item.get("type") == "intrusion-set"
                and not item.get("revoked", False)
                and not item.get("x_mitre_deprecated", False)
                and normalized in {str(item.get("name", "")).casefold().replace(" ", ""), *(str(alias).casefold().replace(" ", "") for alias in item.get("aliases", []))}
            ),
            None,
        )
        if actor is None:
            return None
        actor_id, actor_url = self._reference(actor)
        techniques_by_stix_id = {
            str(item.get("id")): item for item in objects
            if item.get("type") == "attack-pattern" and not item.get("revoked", False) and not item.get("x_mitre_deprecated", False)
        }
        relationships = [
            item for item in objects
            if item.get("type") == "relationship"
            and item.get("relationship_type") == "uses"
            and item.get("source_ref") == actor.get("id")
            and item.get("target_ref") in techniques_by_stix_id
            and not item.get("revoked", False)
            and not item.get("x_mitre_deprecated", False)
        ]
        techniques: list[TechniqueRecord] = []
        for relationship in relationships:
            technique = techniques_by_stix_id[str(relationship["target_ref"])]
            technique_id, technique_url = self._reference(technique)
            if technique_id:
                techniques.append(TechniqueRecord(technique_id=technique_id, technique_name=str(technique.get("name", "Unknown technique")), description=str(relationship.get("description") or "MITRE ATT&CK documents this group as using the technique."), url=technique_url))
        techniques.sort(key=lambda item: item.technique_id)
        return ProviderRecord(
            actor=str(actor.get("name", actor_name)),
            actor_id=actor_id,
            aliases=[str(alias) for alias in actor.get("aliases", [])],
            summary=f"MITRE ATT&CK identifies {actor.get('name', actor_name)} as {actor_id or 'an Enterprise ATT&CK group'} and documents {len(techniques)} actor-to-technique relationships.",
            known_ttps=techniques[:15],
            total_known_ttps=len(techniques),
            sources=[SourceReference(name=f"MITRE ATT&CK - {actor.get('name', actor_name)} ({actor_id or 'group'})", url=actor_url, source_type="authoritative_ttp_catalog")],
            attributes={"dataset": "MITRE ATT&CK Enterprise", "format": "STIX 2.1", "source_url": self.DATA_URL},
        )
