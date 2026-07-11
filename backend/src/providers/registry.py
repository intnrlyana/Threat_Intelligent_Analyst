"""Provider construction and selection; contains no merge logic."""

from dataclasses import dataclass

from backend.src.config import Settings
from backend.src.providers.abuseipdb_provider import AbuseIPDBProvider
from backend.src.providers.mitre_attack_provider import MitreAttackProvider
from backend.src.providers.nvd_provider import NVDProvider
from backend.src.providers.otx_provider import OTXProvider
from backend.src.providers.virustotal_provider import VirusTotalProvider


@dataclass(frozen=True)
class ProviderRegistry:
    virustotal: VirusTotalProvider
    otx: OTXProvider
    abuseipdb: AbuseIPDBProvider
    nvd: NVDProvider
    mitre: MitreAttackProvider

    @classmethod
    def from_settings(cls, settings: Settings) -> "ProviderRegistry":
        return cls(
            virustotal=VirusTotalProvider(settings),
            otx=OTXProvider(settings),
            abuseipdb=AbuseIPDBProvider(settings),
            nvd=NVDProvider(settings),
            mitre=MitreAttackProvider(settings),
        )
