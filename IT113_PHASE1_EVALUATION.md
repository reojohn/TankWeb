# FortressAuth / IT113 Final Project — Phase 1 Model Evaluation (November 20, 2026)

## Scope and reproducibility

Phase 1 addresses the instructor's dataset understanding, ML model development, and model evaluation criteria. It does not establish that the system is production-ready. All results below come from an intentionally **class-balanced synthetic dataset**. No real users, credentials, IPs, or production incidents are in the public dashboard.

Training command (from `ml-service/`):

```bash
python training/train_models.py
python training/export_evidence.py
python -m unittest discover -s tests -v
```

Use the pinned Python dependencies in `ml-service/requirements.txt`. The data generator has deterministic seeds: training `113`, validation `2113`, shifted test `9113`. The 20 numeric telemetry features and seven class names are unchanged, preserving compatibility with the current inference API.

## Data split and repair

| Set | Rows | Records per class | Role |
|---|---:|---:|---|
| Training | 35,000 | 5,000 | Fit XGBoost and train the normal-only autoencoder |
| Validation | 7,000 | 1,000 | Calibrate the anomaly cutoff on normal records only |
| Test (shifted synthetic) | 10,500 | 1,500 | Final, previously unseen metric calculation |

The generator now enforces: requests in one minute <= requests in five minutes; unique paths <= five-minute requests; authentication requests <= five-minute requests; five-minute failed logins <= five-minute authentication requests; and five-minute failures <= fifteen-minute failures. It also checks counter integer ranges and finite numeric data. **All automatic invariant-violation checks are zero** for the three regenerated sets. These checks do not prove realism and do not cover every possible domain consistency rule.

## XGBoost held-out test performance

- Accuracy: **96.7619%**
- Macro precision: **96.8558%**
- Macro recall: **96.7619%**
- Macro F1: **96.7596%**

| True threat class | Precision | Recall | F1 |
|---|---:|---:|---:|
| Normal | 97.72% | 100.00% | 98.85% |
| Brute force | 91.97% | 99.20% | 95.45% |
| Credential stuffing | 99.13% | 91.33% | 95.07% |
| Reconnaissance | 98.59% | 98.20% | 98.40% |
| Web attack | 93.26% | 95.07% | 94.16% |
| MFA abuse | 99.93% | 99.27% | 99.60% |
| Session abuse | 97.38% | 94.27% | 95.80% |

These numbers are rounded from `ml-service/models/model_metadata.json`. The full confusion matrix and exact values are stored in the metadata and displayed by the login-free assessment page.

## Autoencoder held-out evaluation

- Train on normal-class training records only.
- Calibrate the **99th-percentile** reconstruction-error threshold from normal validation records, without test data.
- Saved threshold: **1.540146** (squared scaled reconstruction error).
- Synthetic test anomaly recall: **100.00%**.
- Synthetic test normal false-positive rate: **1.7333%**.
- Synthetic test anomaly precision: **99.7119%**; F1 **99.8558%**.

These unusually strong figures reflect the artificial separation between the generated normal and suspicious classes; they **must not** be advertised as real-world results.

## Strengths and limitations

**Strengths:** reproducible seeds, explicit class taxonomy, no label leakage from test data into threshold calibration, explainable feature names, per-class metrics, confusion matrices, and example misclassifications.

**Limitations:** generated records do not represent true class prevalence, campaign diversity, changing attacker strategies, or authentic false-positive consequences; the shifted test split is still made by the same family of generators; no independently collected real-world labeled corpus has been evaluated; the autoencoder may treat broadly generated attack cases as trivially separable; rule fusion weights are conceptual and not independently calibrated.

## Ethical statement

The public dashboard uses only precomputed synthetic experiment results. It collects no visitor personal data for the assessment display, does not generate or execute attacks, and does not grant unauthenticated access to privileged security controls. Operational testing must be authorized and isolated from production accounts.

## Deployment / no-login behavior

`/` routes to `/assessment/`. The Vercel static build also ships this assessment. `/assessment/` does not require database access or credentials. The existing `/app/` administration remains protected because logs, user administration, bans, and security configuration should not become public. A unified live assessment portal with appropriately restricted operations is a later Phase 2/3 task.

## Phase checklist

- [x] Phase 1: dataset repairs, three splits, training, metric export, unit checks
- [x] Read-only login-free assessment entry, presented with clearly labeled synthetic results
- [ ] Phase 2: authenticated ML service and durable telemetry/inference evidence
- [ ] Phase 3: live assessment UI, mitigation workflow, enriched academic reporting
- [ ] Phase 4: end-to-end tests, controlled cases, deployed verification
- [ ] Phase 5: final report PDF, presentation, source/package review
