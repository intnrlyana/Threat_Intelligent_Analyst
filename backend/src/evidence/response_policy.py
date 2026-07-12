"""Investigation-specific, allowlisted analyst response policy."""

from typing import Final


ACTION_CATALOGUE: Final[dict[str, dict[str, tuple[str, str]]]] = {
    "ioc_reputation_lookup": {
        "IOC-DE-01": ("Detect", "Search DNS, proxy, firewall, and EDR telemetry for the exact indicator."),
        "IOC-RS-01": ("Respond", "Investigate affected assets and contain them only if related malicious activity is corroborated."),
        "IOC-PR-01": ("Protect", "Consider an indicator-level preventive control after validating business impact and legitimate dependencies."),
    },
    "pivot_related_entities": {
        "PIVOT-DE-01": ("Detect", "Search DNS, proxy, and endpoint telemetry for the related entities and validate relationship recency."),
        "PIVOT-RS-01": ("Respond", "Investigate assets that contacted related infrastructure and escalate only when malicious activity is corroborated."),
        "PIVOT-PR-01": ("Protect", "Apply controls only to entities independently confirmed as malicious after validating business impact."),
    },
    "asn_lookup": {
        "ASN-DE-01": ("Detect", "Use the ASN and organization as enrichment when reviewing telemetry involving the exact IP address."),
        "ASN-RS-01": ("Respond", "Correlate the network ownership context with connection, process, and endpoint evidence before escalating."),
        "ASN-PR-01": ("Protect", "Do not block an entire ASN solely from this enrichment result."),
    },
    "actor_ttp_lookup": {
        "ACTOR-DE-01": ("Detect", "Map the documented ATT&CK techniques to existing detections, telemetry, and hunting coverage."),
        "ACTOR-RS-01": ("Respond", "Hunt for the documented behaviors and investigate matches using identity, process, and network context."),
        "ACTOR-PR-01": ("Protect", "Harden the controls associated with the documented techniques according to organizational policy."),
    },
    "exposure_check": {
        "EXPOSURE-DE-01": ("Detect", "Confirm the exact deployed build and inspect relevant logs for indicators associated with applicable vulnerabilities."),
        "EXPOSURE-RS-01": ("Respond", "If an applicable vulnerable build is exposed, investigate for exploitation and follow the incident-response process."),
        "EXPOSURE-PR-01": ("Protect", "Apply the vendor-supported fixed release or documented compensating controls after confirming applicability."),
    },
}


LIMITATION_CATALOGUE: Final[dict[str, dict[str, str]]] = {
    "ioc_reputation_lookup": {
        "IOC-LIM-TIME": "External reputation reflects provider data available at retrieval time and may change.",
        "IOC-LIM-COMPROMISE": "External reputation does not prove internal compromise.",
        "IOC-LIM-UNKNOWN": "An undetected or harmless reputation result is not a clean verdict.",
    },
    "pivot_related_entities": {
        "PIVOT-LIM-RELATIONSHIP": "Relationship records can be historical and do not establish maliciousness or current activity.",
        "PIVOT-LIM-CONTEXT": "Infrastructure relationships require internal telemetry and recency validation before operational action.",
    },
    "asn_lookup": {
        "ASN-LIM-ENRICHMENT": "ASN ownership is enrichment and does not establish malicious intent.",
        "ASN-LIM-LOCATION": "Provider-supplied country context does not prove the infrastructure or operator's physical location.",
    },
    "actor_ttp_lookup": {
        "ACTOR-LIM-HISTORICAL": "Documented actor behavior does not establish current activity in the organization.",
        "ACTOR-LIM-COVERAGE": "The returned techniques may not represent the actor's complete historical capability set.",
    },
    "exposure_check": {
        "EXPOSURE-LIM-CANDIDATE": "NVD matches are candidates until product identity, exact build, affected range, and deployment exposure are verified.",
        "EXPOSURE-LIM-PATCH": "A major or minor version alone may be insufficient to determine vulnerability applicability.",
    },
}


DEFAULT_ACTION_IDS: Final[dict[str, tuple[str, str, str]]] = {
    tool_name: tuple(actions)
    for tool_name, actions in ACTION_CATALOGUE.items()
}

DEFAULT_LIMITATION_IDS: Final[dict[str, tuple[str, ...]]] = {
    tool_name: tuple(limitations)
    for tool_name, limitations in LIMITATION_CATALOGUE.items()
}


UNSUPPORTED_ANALYSIS_TERMS: Final[dict[str, tuple[str, ...]]] = {
    "pivot_related_entities": (
        "data exposure", "unauthorized access", "system compromise",
        "suspicious domain", "malicious domain", "compromised system",
    ),
    "asn_lookup": (
        "unauthorized access", "network disruption", "system compromise",
        "malicious asn", "suspicious asn", "malicious activity",
    ),
    "actor_ttp_lookup": (
        "currently attacking", "current campaign", "active compromise", "organization is compromised",
    ),
}
