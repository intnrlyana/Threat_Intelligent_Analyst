from backend.src.tools.registry import get_tool_for_intent, list_registered_tools


def test_required_tools_have_metadata_and_handlers() -> None:
    metadata = list_registered_tools()
    names = {tool.name for tool in metadata}

    assert {"ioc_reputation_lookup", "actor_ttp_lookup", "exposure_check", "pivot_related_entities", "asn_lookup"} <= names
    assert all(tool.description and tool.input_schema_name and tool.output_schema_name for tool in metadata)
    assert get_tool_for_intent("ioc_lookup") is not None
    assert get_tool_for_intent("exposure_reasoning") is not None
