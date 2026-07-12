# Design Note — Threat Intelligent Analyst

## Objective

Threat Intelligent Analyst is an evidence-first SOC investigation service exposed through web chat and MCP. It supports IOC reputation, infrastructure pivots, ASN enrichment, actor/TTP research, and software-exposure assessment. External intelligence and LLM output are untrusted: they may inform an analyst but cannot control tools, alter evidence, or authorize operational action.

```text
Web chat / MCP
      |
input validation -> injection defense -> intent routing -> context resolution
      -> specialist delegation -> allowlisted typed tool -> provider aggregation
      -> evidence ledger + confidence -> bounded Groq analysis
      -> response policy + validation -> memory + operational trace
```

## Intent routing and execution

Routing is semantic-first. Deterministic parsing extracts and validates entities but does not assign intent. A managed Qdrant collection retrieves curated, versioned examples using client-side FastEmbed vectors; a route is accepted only when its score and margin over the next entity-compatible intent pass calibrated thresholds. Ambiguous results use Groq through a Pydantic contract restricted to IOC lookup, pivot, ASN lookup, actor/TTP, exposure reasoning, or unknown. Unsupported requests terminate without a tool call. Legacy rule and hybrid modes remain available for comparison and rollback.

Clear and uniquely compatible follow-ups resolve from typed session memory. Ambiguous references request clarification rather than invoking an LLM. Compound planning is capped at three validated steps using analyst- or session-supplied entities.

The coordinator delegates to an intent-specific specialist with a fixed tool allowlist. Tools—not the LLM—select applicable providers. Adapters normalize vendor JSON into typed records; bounded concurrency, connection pooling, caching, and typed partial failures preserve successful evidence during degradation.

## Evidence and response boundary

Deterministic code owns the finding, evidence, sources, evidence-confidence score, NIST action text, limitations, and final structure. Groq receives a structured case file rather than a prewritten answer and returns only investigation-specific analytical statements with evidence IDs plus allowlisted action and limitation selections.

Validation rejects new fact tokens, providers, unknown evidence IDs, and conclusions incompatible with the evidence type. Relationship data cannot prove compromise, ASN data cannot prove malicious intent, and actor history cannot prove current activity. Invalid model output produces a deterministic fallback. Evidence confidence appears once in the summary and is distinct from severity.

## Prompt-injection defense

Defense is layered because no classifier is authoritative by itself:

1. A deterministic pre-routing policy blocks instruction overrides, jailbreak patterns, and protected-prompt disclosure attempts.
2. A local fine-tuned Prompt Guard detects paraphrased attacks; deterministic controls remain authoritative.
3. Retrieved provider text is treated only as evidence. Deterministic and semantic checks flag indirect injection, but retrieved instructions cannot affect routing, planning, or tool execution.
4. Allowlists, call budgets, schema validation, and evidence grounding limit blast radius.
5. Traces expose routes, tools, failures, latency, confidence factors, and safety flags without revealing secrets or hidden reasoning.

Prompt Guard achieved 89.0% accuracy, 96.43% precision, 81.0% injection recall, and a 3.0% false-positive rate on an untouched 200-example English SOC holdout; this is not a production guarantee.

## Trade-offs and production direction

The design favors auditability and safe degradation over unrestricted agent autonomy. Process-local memory and caching keep the implementation simple but require Redis or equivalent coordination for multi-worker deployment. Production hardening would add identity and RBAC, authenticated MCP transport, secret management, OpenTelemetry, circuit breakers and provider-specific retries, deterministic CPE/version evaluation, claim-level entailment checks, external safety benchmarks, and approval-gated SIEM/EDR actions. The core trust boundary should remain unchanged: models interpret evidence; deterministic policy controls facts, capabilities, and authority.
