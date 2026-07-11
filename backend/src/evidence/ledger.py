"""Response-ready ledger built only from tool-returned evidence."""

from backend.src.tools.schemas import EvidenceItem, SourceReference, ToolResult


class EvidenceLedger:
    def __init__(self) -> None:
        self._items: list[EvidenceItem] = []

    def add(self, item: EvidenceItem) -> None:
        self._items.append(item)

    def items(self) -> tuple[EvidenceItem, ...]:
        return tuple(self._items)

    @classmethod
    def from_tool_result(cls, result: ToolResult) -> "EvidenceLedger":
        ledger = cls()
        for item in result.evidence:
            ledger.add(item)
        return ledger

    def sources(self, result: ToolResult) -> tuple[SourceReference, ...]:
        return tuple(result.sources)
