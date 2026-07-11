# Design Note - Threat Intelligent Analyst

## Purpose and architecture

Threat Intelligent Analyst is an evidence-first SOC investigation service. It accepts natural-language questions through a web chat interface or MCP, retrieves live intelligence through typed provider adapters, and returns a bounded analyst response with source attribution, confidence, limitations, and a recommended next action.

```text
Web chat (FastAPI / Jinja2 / HTMX) or MCP client
                    |
                LangGraph
 input guard -> semantic guard -> hybrid routing -> context resolution
       -> delegated specialist -> allowlisted typed tool -> evidence ledger
       -> confidence -> grounded response -> session memory + operational trace
                    |
 Composite provider: VirusTotal | AbuseIPDB | AlienVault OTX | NVD | MITRE ATT&CK
```

The provider layer is deliberately separated: adapters normalize vendor payloads into `ProviderRecord` or `ProviderFailure`; the aggregator correlates successful records and preserves partial failures; tools consume the typed contract rather than provider-specific JSON. Independent provider calls execute concurrently through a bounded worker pool, while a bounded TTL cache reduces latency and quota consumption.

## Agentic routing and state

The LangGraph workflow is explicit and observable. Clear, high-confidence entities such as hashes, IP addresses, and product versions are parsed deterministically: this is cheaper, faster, and safer than asking a model to reinterpret an unambiguous indicator. Ambiguous requests use a schema-validated Groq router through LangChain. The coordinator delegates only to an intent-specific specialist with an allowlisted tool.

Conversation state is constrained rather than free-form. A deterministic resolver handles clear follow-ups such as “what is its ASN?”; ambiguous references can use an LLM coreference step that may select only an existing session-memory entity. Compound requests can use a maximum-three-step planner, but every proposed step is validated against allowed intents, entity types, and analyst/session-supplied entities. The model cannot introduce a pivot target or obtain an unapproved tool.

## Grounding, confidence, and safe degradation

Every response follows the same analyst contract: **Finding, Evidence, Sources, Confidence, Limitations, Recommended Next Step**. The response composer may improve the finding, limitations, and next step, but evidence, sources, and confidence are rendered from the typed evidence ledger. A post-generation validator rejects invented indicators, CVEs, ATT&CK IDs, ASNs, numbers, provider names, verdicts, and high-impact security claims, then falls back to the deterministic response.

Confidence measures confidence in the available evidence, not threat severity. It combines source authority (25%), independent coverage (20%), agreement (25%), freshness (15%), completeness (10%), and provider health (5%). Provider contradictions are explicit. Missing data is **Unknown**, never safe; successful provider evidence remains visible when an optional provider times out, is rate-limited, or lacks permissions.

## Security and operational controls

The system applies layered prompt-injection defense. A deterministic policy blocks clear instruction override and protected-prompt disclosure attempts before routing. A locally fine-tuned Prompt Guard checkpoint then provides semantic detection for paraphrased attacks. Retrieved provider text is always untrusted data: deterministic signatures and the same semantic model can flag indirect injection, but retrieved text never controls routing or tool invocation.

Specialist-to-tool allowlists, bounded tool/LLM calls, provider timeouts, typed failures, readiness checks, and secret-free operational traces provide practical guardrails. The deployed local Prompt Guard checkpoint was calibrated on an isolated validation split; on its untouched 200-example English SOC holdout it achieved 89.0% accuracy, 96.43% precision, 81.0% injection recall, and a 3.0% false-positive rate. Because a classifier is probabilistic, deterministic protected-instruction controls remain authoritative.
