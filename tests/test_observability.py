from backend.src.graph.workflow import run_agent_workflow


def test_operational_trace_has_required_fields_without_reasoning() -> None:
    trace = run_agent_workflow("Is 45.83.122.10 malicious?").trace
    assert trace is not None
    payload = trace.model_dump()

    assert payload["trace_id"]
    assert payload["workflow_nodes_executed"]
    assert payload["selected_agent"] == "ioc_analyst"
    assert "chain_of_thought" not in payload
    assert "reasoning" not in payload
