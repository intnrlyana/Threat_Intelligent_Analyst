"""CPU-safe partial fine-tuning for Llama Prompt Guard 2 86M."""

from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

import torch
from torch.optim import AdamW
from torch.utils.data import DataLoader
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from backend.src.config import get_settings
from prompt_guard_training.training_utils import JsonlPromptDataset, evaluate_model

ROOT = Path(__file__).resolve().parent


def seed_everything(seed: int) -> None:
    random.seed(seed)
    torch.manual_seed(seed)


def trainable_parameters(model, encoder_layers: int) -> tuple[list[torch.nn.Parameter], list[torch.nn.Parameter]]:
    for parameter in model.parameters():
        parameter.requires_grad = False
    encoder_params: list[torch.nn.Parameter] = []
    head_params: list[torch.nn.Parameter] = []
    for name, parameter in model.named_parameters():
        layer_number = None
        if name.startswith("deberta.encoder.layer."):
            layer_number = int(name.split(".")[3])
        if layer_number is not None and layer_number >= 12 - encoder_layers:
            parameter.requires_grad = True
            encoder_params.append(parameter)
        elif name.startswith(("pooler.", "classifier.")):
            parameter.requires_grad = True
            head_params.append(parameter)
    return encoder_params, head_params


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--max-length", type=int, default=128)
    parser.add_argument("--encoder-layers", type=int, default=1, choices=range(0, 13))
    parser.add_argument("--base-model", default="meta-llama/Llama-Prompt-Guard-2-86M")
    parser.add_argument("--seed", type=int, default=20260711)
    parser.add_argument("--output", type=Path, default=Path("models/threat-analyst-prompt-guard"))
    args = parser.parse_args()
    seed_everything(args.seed)
    torch.set_num_threads(max(1, min(4, torch.get_num_threads())))
    settings = get_settings()
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, token=settings.huggingface_token or None)
    model = AutoModelForSequenceClassification.from_pretrained(args.base_model, token=settings.huggingface_token or None)
    encoder_params, head_params = trainable_parameters(model, args.encoder_layers)
    trainable = sum(parameter.numel() for parameter in model.parameters() if parameter.requires_grad)
    total = sum(parameter.numel() for parameter in model.parameters())
    print(f"trainable={trainable:,}/{total:,} ({100 * trainable / total:.2f}%)")
    train_data = JsonlPromptDataset(ROOT / "data/train.jsonl", tokenizer, args.max_length)
    validation_data = JsonlPromptDataset(ROOT / "data/validation.jsonl", tokenizer, args.max_length)
    test_data = JsonlPromptDataset(ROOT / "data/test.jsonl", tokenizer, args.max_length)
    generator = torch.Generator().manual_seed(args.seed)
    train_loader = DataLoader(train_data, batch_size=args.batch_size, shuffle=True, generator=generator)
    validation_loader = DataLoader(validation_data, batch_size=args.batch_size)
    test_loader = DataLoader(test_data, batch_size=args.batch_size)
    baseline = {"validation": evaluate_model(model, validation_loader), "test": evaluate_model(model, test_loader)}
    print("baseline", json.dumps(baseline, indent=2))
    parameter_groups = [{"params": head_params, "lr": 1e-4}]
    if encoder_params:
        parameter_groups.insert(0, {"params": encoder_params, "lr": 2e-5})
    optimizer = AdamW(parameter_groups, weight_decay=0.01)
    best_f1 = -1.0
    best_state: dict[str, torch.Tensor] | None = None
    history: list[dict[str, object]] = []
    started = time.time()
    for epoch in range(1, args.epochs + 1):
        model.train()
        running_loss = 0.0
        for step, batch in enumerate(train_loader, start=1):
            optimizer.zero_grad(set_to_none=True)
            loss = model(**batch).loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_([*encoder_params, *head_params], 1.0)
            optimizer.step()
            running_loss += loss.item()
            if step % 10 == 0 or step == len(train_loader):
                print(f"epoch={epoch} step={step}/{len(train_loader)} loss={running_loss / step:.4f}", flush=True)
        validation = evaluate_model(model, validation_loader)
        history.append({"epoch": epoch, "loss": round(running_loss / len(train_loader), 6), "validation": validation})
        print("validation", json.dumps(validation), flush=True)
        if float(validation["f1"]) > best_f1:
            best_f1 = float(validation["f1"])
            best_state = {name: value.detach().cpu().clone() for name, value in model.state_dict().items()}
    assert best_state is not None
    model.load_state_dict(best_state)
    final = {"validation": evaluate_model(model, validation_loader), "test": evaluate_model(model, test_loader)}
    args.output.mkdir(parents=True, exist_ok=True)
    model.config.id2label = {0: "LABEL_0", 1: "LABEL_1"}
    model.config.label2id = {"LABEL_0": 0, "LABEL_1": 1}
    model.save_pretrained(args.output, safe_serialization=True)
    tokenizer.save_pretrained(args.output)
    report = {"base_model": args.base_model, "method": f"classification head + final {args.encoder_layers} encoder layer(s)", "seed": args.seed, "epochs": args.epochs, "batch_size": args.batch_size, "max_length": args.max_length, "trainable_parameters": trainable, "total_parameters": total, "elapsed_seconds": round(time.time() - started, 2), "baseline": baseline, "history": history, "fine_tuned": final}
    (args.output / "training_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("fine_tuned", json.dumps(final, indent=2))
    print(f"saved={args.output.resolve()}")


if __name__ == "__main__":
    main()
