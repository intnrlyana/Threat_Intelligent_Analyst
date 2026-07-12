from backend.src.agents.routing_dataset import load_approved_examples, load_evaluation_cases


def test_routing_datasets_are_versioned_balanced_and_family_isolated() -> None:
    approved = load_approved_examples()
    development = load_evaluation_cases("development")
    final = load_evaluation_cases("final")

    assert len(approved) >= 70
    assert len(development) == 30
    assert len(final) == 30
    approved_families = {item.family for item in approved}
    development_families = {item.family for item in development}
    final_families = {item.family for item in final}
    assert approved_families.isdisjoint(development_families)
    assert approved_families.isdisjoint(final_families)
    assert development_families.isdisjoint(final_families)

    approved_counts = {}
    for item in approved:
        approved_counts[item.intent] = approved_counts.get(item.intent, 0) + 1
    assert max(approved_counts.values()) - min(approved_counts.values()) <= 1
