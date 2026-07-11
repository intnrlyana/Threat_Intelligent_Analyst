"""Deterministic Stage 4 workflow evaluation harness."""

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Evaluations verify the deterministic baseline and must never consume local LLM credentials.
os.environ.setdefault("ROUTER_MODE", "rule_based")
os.environ.setdefault("RESPONSE_MODE", "deterministic")
os.environ.setdefault("PROMPT_GUARD_ENABLED", "false")

from backend.src.graph.state import AgentMemory
from backend.src.graph.workflow import run_agent_workflow
from tests.fake_provider import FakeThreatIntelProvider
import backend.src.agent_harness.execution as execution

# Explicit offline dependency injection: evaluation must never call live providers.
execution.CompositeThreatIntelProvider = FakeThreatIntelProvider

REQUIRED_SECTIONS = ("Finding\n", "Evidence\n", "Sources\n", "Confidence\n", "Limitations\n", "Recommended Next Step\n")


def load_queries() -> list[dict[str, object]]:
    return json.loads(Path(__file__).with_name("eval_queries.json").read_text(encoding="utf-8"))


if __name__ == "__main__":
    cases = load_queries()
    failures: list[str] = []
    report: list[dict[str, object]] = []
    memories: dict[str, AgentMemory] = {}
    for case in cases:
        conversation_id = str(case.get("conversation_id", case["id"]))
        memory = memories.get(conversation_id, AgentMemory(**case.get("initial_memory", {})))
        state = run_agent_workflow(str(case["query"]), memory)
        memories[conversation_id] = state.memory
        actual: dict[str, object] = {
            "expected_intent": state.intent,
            "expected_selected_agent": state.selected_agent,
            "expected_entity_type": state.entity_type,
            "expected_tool": state.tools_called[0] if state.tools_called else None,
            "expected_confidence": state.confidence,
            "expected_degraded": state.degraded,
            "expected_safety_flags": state.safety_flags,
        }
        mismatches = [f"{field}: expected {case[field]!r}, got {actual[field]!r}" for field in actual if field in case and case[field] != actual[field]]
        expected_text = case.get("expected_response_contains")
        if expected_text and str(expected_text) not in state.response:
            mismatches.append(f"response missing {expected_text!r}")
        if state.tool_result:
            for section in REQUIRED_SECTIONS:
                if section not in state.response:
                    mismatches.append(f"grounding: missing response section {section.strip()!r}")
            for evidence in state.tool_result.evidence:
                if evidence.claim not in state.response:
                    mismatches.append(f"grounding: omitted evidence claim {evidence.claim!r}")
            for source in state.tool_result.sources:
                if source.name not in state.response:
                    mismatches.append(f"grounding: omitted source {source.name!r}")
            if state.source_count != len(state.tool_result.sources) or state.evidence_count != len(state.tool_result.evidence):
                mismatches.append("grounding: trace counts differ from typed tool result")
        elif state.tools_called:
            mismatches.append("grounding: tool recorded without a typed result")
        report.append({"id": case["id"], "query": case["query"], "intent": state.intent, "tool": actual["expected_tool"], "confidence": state.confidence, "passed": not mismatches, "mismatches": mismatches})
        if mismatches:
            failures.append(f"{case['id']}: " + "; ".join(mismatches))

    passed = len(cases) - len(failures)
    print(f"Total cases: {len(cases)}")
    print(f"Passed: {passed}")
    print(f"Failed: {len(failures)}")
    print(f"Pass rate: {passed / len(cases):.0%}" if cases else "Pass rate: n/a")
    if failures:
        print("Failure details:")
        print("\n".join(failures))
    Path(__file__).with_name("latest_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    raise SystemExit(1 if failures else 0)
