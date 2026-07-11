"""Validate schema, balance, uniqueness, and family-isolated splits."""

import json
from collections import Counter
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
EXPECTED = {"train": 1240, "validation": 180, "test": 180, "final_holdout": 200}
REQUIRED = {"id", "text", "label", "label_name", "category", "source", "family", "difficulty"}


def main() -> None:
    all_ids: set[str] = set()
    all_text: set[str] = set()
    split_families: dict[str, set[str]] = {}
    total_labels: Counter[int] = Counter()
    for split, expected in EXPECTED.items():
        rows = [json.loads(line) for line in (DATA / f"{split}.jsonl").read_text(encoding="utf-8").splitlines() if line]
        assert len(rows) == expected, (split, len(rows), expected)
        assert all(REQUIRED <= row.keys() for row in rows)
        assert all(row["label"] in {0, 1} for row in rows)
        ids, texts = {row["id"] for row in rows}, {row["text"].casefold() for row in rows}
        assert len(ids) == len(rows) and len(texts) == len(rows)
        assert not ids & all_ids and not texts & all_text
        all_ids |= ids
        all_text |= texts
        split_families[split] = {row["family"] for row in rows}
        labels = Counter(row["label"] for row in rows)
        total_labels.update(labels)
        print(split, dict(labels), sorted(split_families[split]))
    splits = list(EXPECTED)
    for index, left in enumerate(splits):
        for right in splits[index + 1:]:
            assert not split_families[left] & split_families[right], f"Family leakage: {left}/{right}"
    assert total_labels == Counter({0: 900, 1: 900}), total_labels
    print("validated: 1,800 unique examples, balanced labels, no family leakage")


if __name__ == "__main__":
    main()
