"""Evaluate any local or Hugging Face Prompt Guard checkpoint."""

import argparse
import json
from pathlib import Path

import torch
from torch.utils.data import DataLoader
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from backend.src.config import get_settings
from prompt_guard_training.training_utils import JsonlPromptDataset, evaluate_model


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("model")
    parser.add_argument("--split", choices=("validation", "test", "final_holdout"), default="test")
    args = parser.parse_args()
    settings = get_settings()
    token = settings.huggingface_token or None if not Path(args.model).exists() else None
    tokenizer = AutoTokenizer.from_pretrained(args.model, token=token, local_files_only=Path(args.model).exists())
    model = AutoModelForSequenceClassification.from_pretrained(args.model, token=token, local_files_only=Path(args.model).exists())
    data = JsonlPromptDataset(Path(__file__).resolve().parent / f"data/{args.split}.jsonl", tokenizer)
    torch.set_num_threads(max(1, min(4, torch.get_num_threads())))
    print(json.dumps(evaluate_model(model, DataLoader(data, batch_size=4)), indent=2))


if __name__ == "__main__":
    main()
