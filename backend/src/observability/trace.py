"""Operational workflow tracing without hidden reasoning content."""

from pydantic import BaseModel


class NodeTrace(BaseModel):
    node_name: str
    status: str
    latency_ms: float
