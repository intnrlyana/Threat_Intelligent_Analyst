"""Validated loaders for versioned semantic-routing datasets."""

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from backend.src.agent_harness.schemas import EntityType, Intent

ROOT = Path(__file__).resolve().parents[3]
DATA_ROOT = ROOT / "routing_data"


class ApprovedRoutingExample(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=8, max_length=300)
    intent: Intent
    family: str
    style: str
    entity_types: list[EntityType] = Field(min_length=1)
    approved: bool
    dataset_version: int = Field(ge=1)


class RoutingEvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=8, max_length=300)
    expected_intent: Intent
    family: str


def _read_jsonl(path: Path, schema):
    return [schema.model_validate(json.loads(line)) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_approved_examples() -> list[ApprovedRoutingExample]:
    examples = _read_jsonl(DATA_ROOT / "approved_examples_v3.jsonl", ApprovedRoutingExample)
    if not examples or not all(item.approved and item.dataset_version == 3 for item in examples):
        raise RuntimeError("Routing dataset contains unapproved or incorrectly versioned examples")
    return examples


def load_evaluation_cases(split: str) -> list[RoutingEvaluationCase]:
    filenames = {"development": "development_queries.jsonl", "final": "final_evaluation.jsonl"}
    if split not in filenames:
        raise ValueError(f"Unsupported routing evaluation split: {split}")
    return _read_jsonl(DATA_ROOT / filenames[split], RoutingEvaluationCase)
