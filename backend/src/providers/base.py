"""Base contract for the normalized threat-intelligence facade."""

from abc import ABC, abstractmethod

from backend.src.providers.models import ProviderResult


class ThreatIntelProvider(ABC):
    @abstractmethod
    def lookup_ioc(self, entity_type: str, entity_value: str) -> ProviderResult: ...

    @abstractmethod
    def lookup_actor(self, actor_name: str) -> ProviderResult: ...

    @abstractmethod
    def lookup_exposure(self, product: str, version: str) -> ProviderResult: ...

    @abstractmethod
    def lookup_relationships(self, entity_type: str, entity_value: str) -> ProviderResult: ...

    @abstractmethod
    def lookup_asn(self, ip: str) -> ProviderResult: ...
