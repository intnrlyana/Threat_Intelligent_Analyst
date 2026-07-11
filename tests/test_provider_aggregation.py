from backend.src.providers.aggregator import ProviderAggregator
from backend.src.providers.models import ProviderCall, ProviderFailure, ProviderRecord
from backend.src.tools.schemas import EvidenceItem, SourceReference, ToolError


def _call(provider: str, role: str, result) -> ProviderCall:
    return ProviderCall(provider=provider, role=role, authority=0.9, result=result)


def test_aggregator_preserves_success_when_optional_provider_fails() -> None:
    vt = ProviderRecord(verdict="suspicious", risk_score=20, evidence=[EvidenceItem(claim="VT evidence", source="VirusTotal", source_type="test")], sources=[SourceReference(name="VirusTotal")])
    otx_failure = ProviderFailure(error=ToolError(provider="AlienVault OTX", error_type="rate_limit", message="Quota reached"))

    merged = ProviderAggregator().merge_ioc([_call("VirusTotal", "primary", vt), _call("AlienVault OTX", "supporting", otx_failure)], "ip", "192.0.2.1")

    assert isinstance(merged, ProviderRecord)
    assert merged.verdict == "suspicious"
    assert merged.provider_errors[0].provider == "AlienVault OTX"
    assert [item.success for item in merged.provider_findings] == [True, False]


def test_aggregator_returns_typed_failure_when_every_provider_fails() -> None:
    failure = ProviderFailure(error=ToolError(provider="VirusTotal", error_type="timeout", message="Timed out"))

    merged = ProviderAggregator().merge_ioc([_call("VirusTotal", "primary", failure)], "domain", "example.test")

    assert isinstance(merged, ProviderFailure)
    assert merged.error.error_type == "timeout"
