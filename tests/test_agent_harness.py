from backend.src.agents.coordinator import create_agent_task, select_specialist


def test_coordinator_specialist_mapping() -> None:
    assert select_specialist("ioc_lookup") == "ioc_analyst"
    assert select_specialist("exposure_reasoning") == "exposure_analyst"
    assert select_specialist("blocked_prompt_injection") == "none"


def test_delegated_task_preserves_shared_context() -> None:
    task = create_agent_task(intent="ioc_lookup", selected_agent="ioc_analyst", entity_type="ip", entity_value="45.83.122.10", product=None, version=None, shared_context={"last_ip": "45.83.122.10"}, query="Is it malicious?")

    assert task.from_agent == "coordinator"
    assert task.to_agent == "ioc_analyst"
    assert task.shared_context["last_ip"] == "45.83.122.10"
