# SOC Prompt Guard Synthetic Dataset

## Summary

This dataset contains 1,800 English prompts for adapting a binary prompt-injection classifier to the Threat Intelligent Analyst application. It contains 900 benign SOC/security prompts and 900 malicious attempts to override instructions, disclose protected prompts, manipulate verdicts, claim false authority, or transform protected instructions.

## Splits

| Split | Records | Benign | Malicious |
| --- | ---: | ---: | ---: |
| Train | 1,240 | 620 | 620 |
| Validation | 180 | 90 | 90 |
| Development challenge | 180 | 90 | 90 |
| Untouched final holdout | 200 | 100 | 100 |

Splits are isolated by template family. The final holdout is excluded from training, calibration, and candidate selection.

## Dataset provenance

Records were created from manually authored, application-specific templates, controlled cybersecurity entities, and eight label-neutral conversational styles. The submitted dataset is the reviewed, fixed artifact used by the training and evaluation workflow. All records are labelled synthetic (`synthetic_reviewed_templates`). No provider output, API secret, user conversation, or private production data is included.

## Labels

- `0 / benign`: legitimate SOC analysis, defensive education, and hard benign translation/encoding requests targeting public evidence.
- `1 / malicious`: attempts to supersede instructions, disclose or transform protected prompts, manipulate tools/verdicts, impersonate authority, or remove safety controls.

## Intended use

- Proof-of-concept partial fine-tuning of Llama Prompt Guard 2 86M.
- Application-specific regression and held-out evaluation.
- Demonstrating the distinction between security subject matter and attacks against the agent instruction hierarchy.

## Limitations

- Synthetic template data does not represent real traffic.
- The dataset may contain generator-style and vocabulary artifacts.
- The 180-record test set is still too small for production safety claims.
- Results must be supplemented with an untouched external benchmark before deployment.
- Fine-tuning may reduce generalization or increase false positives.

This dataset supports an assessment experiment, not a production-certified security control.
