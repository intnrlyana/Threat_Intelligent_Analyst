"""Pure aggregation logic for normalized provider calls."""

from datetime import datetime, timezone

from backend.src.providers.models import ProviderCall, ProviderFailure, ProviderRecord
from backend.src.tools.schemas import ProviderFinding


class ProviderAggregator:
    VERDICT_ORDER = {"undetected": 0, "unknown": 0, "suspicious": 1, "malicious": 2}

    @staticmethod
    def finding(call: ProviderCall) -> ProviderFinding:
        record = call.result if isinstance(call.result, ProviderRecord) else None
        failure = call.result if isinstance(call.result, ProviderFailure) else None
        return ProviderFinding(
            provider=call.provider,
            role=call.role,
            authority=call.authority,
            verdict=record.verdict if record else None,
            risk_score=record.risk_score if record else None,
            retrieved_at=datetime.now(timezone.utc),
            success=record is not None,
            evidence_count=len(record.evidence) if record else 0,
            error_type=failure.error.error_type if failure else "no_data" if call.result is None else None,
        )

    def merge_ioc(self, calls: list[ProviderCall], entity_type: str, indicator: str) -> ProviderRecord | ProviderFailure | None:
        successes = [call.result for call in calls if isinstance(call.result, ProviderRecord)]
        failures = [call.result.error for call in calls if isinstance(call.result, ProviderFailure)]
        if not successes:
            return ProviderFailure(error=failures[0]) if failures else None
        verdict = max((record.verdict or "unknown" for record in successes), key=lambda value: self.VERDICT_ORDER.get(value, 0))
        scores = [record.risk_score for record in successes if record.risk_score is not None]
        return ProviderRecord(
            entity_type=entity_type,
            indicator=indicator,
            verdict=verdict,
            risk_score=max(scores) if scores else None,
            summary=" ".join(record.summary for record in successes if record.summary),
            evidence=[item for record in successes for item in record.evidence],
            sources=[item for record in successes for item in record.sources],
            related_entities=[item for record in successes for item in record.related_entities],
            provider_errors=failures,
            provider_findings=[self.finding(call) for call in calls],
        )

    def merge_actor(self, calls: list[ProviderCall], actor_name: str) -> ProviderRecord | ProviderFailure | None:
        successes = [call.result for call in calls if isinstance(call.result, ProviderRecord)]
        failures = [call.result.error for call in calls if isinstance(call.result, ProviderFailure)]
        if not successes:
            return ProviderFailure(error=failures[0]) if failures else None
        primary = next((record for record in successes if record.known_ttps), successes[0])
        return ProviderRecord(
            actor=primary.actor or actor_name,
            actor_id=primary.actor_id,
            aliases=primary.aliases,
            summary=" ".join(record.summary for record in successes if record.summary),
            known_ttps=primary.known_ttps,
            total_known_ttps=primary.total_known_ttps or len(primary.known_ttps),
            evidence=[item for record in successes for item in record.evidence],
            sources=[item for record in successes for item in record.sources],
            provider_errors=failures,
            provider_findings=[self.finding(call) for call in calls],
        )

    def annotate_single(self, call: ProviderCall) -> ProviderRecord | ProviderFailure | None:
        if isinstance(call.result, ProviderRecord):
            return call.result.model_copy(update={"provider_findings": [self.finding(call)]}, deep=True)
        return call.result
