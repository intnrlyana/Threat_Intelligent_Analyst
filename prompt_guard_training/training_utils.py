"""Dependency-light dataset and metric utilities for Prompt Guard training."""

from __future__ import annotations

import json
from pathlib import Path

import torch
from torch.utils.data import Dataset


class JsonlPromptDataset(Dataset):
    def __init__(self, path: Path, tokenizer, max_length: int = 128) -> None:
        self.rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int) -> dict[str, torch.Tensor]:
        row = self.rows[index]
        encoded = self.tokenizer(row["text"], truncation=True, max_length=self.max_length, padding="max_length", return_tensors="pt")
        return {"input_ids": encoded["input_ids"].squeeze(0), "attention_mask": encoded["attention_mask"].squeeze(0), "labels": torch.tensor(row["label"], dtype=torch.long)}


def classification_metrics(labels: list[int], predictions: list[int]) -> dict[str, float | int]:
    tp = sum(label == 1 and pred == 1 for label, pred in zip(labels, predictions))
    tn = sum(label == 0 and pred == 0 for label, pred in zip(labels, predictions))
    fp = sum(label == 0 and pred == 1 for label, pred in zip(labels, predictions))
    fn = sum(label == 1 and pred == 0 for label, pred in zip(labels, predictions))
    total = max(1, len(labels))
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    return {
        "accuracy": round((tp + tn) / total, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / max(1e-12, precision + recall), 4),
        "false_positive_rate": round(fp / max(1, fp + tn), 4),
        "false_negative_rate": round(fn / max(1, fn + tp), 4),
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "examples": len(labels),
    }


@torch.no_grad()
def evaluate_model(model, loader) -> dict[str, float | int]:
    model.eval()
    labels: list[int] = []
    predictions: list[int] = []
    for batch in loader:
        expected = batch.pop("labels")
        logits = model(**batch).logits
        labels.extend(expected.tolist())
        predictions.extend(logits.argmax(dim=-1).tolist())
    return classification_metrics(labels, predictions)
