"""Evaluate Qdrant-first routing without invoking intelligence providers."""

import argparse
from collections import Counter

from backend.src.agent_harness.schemas import EntityType, Intent
from backend.src.agents.coordinator import extract_entities
from backend.src.agents.routing_dataset import load_evaluation_cases
from backend.src.agents.semantic_router import COMPATIBLE_ENTITY_TYPES, route_semantically
from backend.src.config import get_settings
from backend.src.llm.service import classify_with_groq


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=("development", "final"), default="development")
    parser.add_argument("--qdrant-only", action="store_true")
    args = parser.parse_args()
    settings = get_settings()
    rows = []
    for case in load_evaluation_cases(args.split):
        entity = extract_entities(case.text)
        semantic = route_semantically(case.text, entity, settings)
        decision, method = semantic.decision, "qdrant"
        if not semantic.accepted and not args.qdrant_only:
            method = "groq"
            try:
                decision = classify_with_groq(case.text, settings)
                if entity.entity_type != EntityType.UNKNOWN:
                    decision = decision.model_copy(update={"entity_type": entity.entity_type, "entity_value": entity.entity_value, "product": entity.product, "version": entity.version})
                if decision.entity_type not in COMPATIBLE_ENTITY_TYPES.get(decision.intent, set()):
                    decision = decision.model_copy(update={"intent": Intent.UNKNOWN})
            except RuntimeError:
                method, decision = "error", decision.model_copy(update={"intent": Intent.UNKNOWN})
        rows.append((case, decision.intent, method, semantic.score, semantic.margin))
    correct = sum(case.expected_intent == actual for case, actual, *_ in rows)
    methods = Counter(method for _, _, method, _, _ in rows)
    print(f"split={args.split} total={len(rows)} correct={correct} accuracy={correct / len(rows):.1%} methods={dict(methods)}")
    for case, actual, method, score, margin in rows:
        if case.expected_intent != actual:
            print(f"MISS expected={case.expected_intent.value} actual={actual.value} via={method} score={score:.3f} margin={margin:.3f} text={case.text}")


if __name__ == "__main__":
    main()
