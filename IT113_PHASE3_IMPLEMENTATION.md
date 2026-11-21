# FortressAuth — IT113 Phase 3 implementation

**Scope:** Phase 3, *Improve the interface and reporting*; safely developed during Supabase restoration. The five phases remain unchanged. **This release does not write to, reset, migrate or require a database.** It expects Phase 1 + premium wolf-logo UI + Phase 2 already installed. The existing login-free `/assessment/` is read-only and based entirely on saved synthetic evaluation artifacts. All privileged PHP functions remain protected.

## Improvements delivered

1. **Dataset Assessment:** split rail (35,000 train / 7,000 validation / 10,500 test), feature glossary grouped into request velocity, authentication, application security and context; recorded per-split invariant validation; existing class distribution preserved.
2. **Model Evaluation:** confusion matrix, per-class precision/recall/F1, feature importance, independent split methodology, largest confusion pairs, total error count and autoencoder test results. All numbers are derived from the original Phase 1 `model_summary.json`, not invented.
3. **AI Defense:** new read-only model pipeline diagram, weighted risk-fusion explanation, model fingerprint consistent with the Phase 2 runtime, and an interactive inspector for the 13 original held-out synthetic examples (correct and misclassified). Explanations are limited to transparent numeric threshold indicators, **not** SHAP / causal attributions. No fake live inference or unobserved hybrid risk.
4. **Threat Mitigations:** seven category-specific response recommendations with quick filters, validation steps and mapped response stages. Model categories alone never prove exploitation or attacker identity.
5. **Research Reports:** new offline download area containing a four-page synthetic evaluation PDF, model metrics JSON and precomputed sample evidence JSON. `scripts/export_phase3_eval_pdf.py` regenerates the PDF from versioned source data (install `reportlab` for regeneration). This is a **technical brief**, not the final Phase 5 submission.
6. **Protected admin AI Defense:** additions in `public/ai_threat_intelligence.php` show the latest model version, trace ID, request/event evidence sources, observation window counts and threshold indicator values **only after the original `require_admin_auth()` gate**. The public assessment does not expose those records.
7. **Protected report exporter:** includes fallback copy of safe model evaluation metadata when the PHP deployment image omits `ml-service/`; richer validation fields, trace information, and mitigation matrix in PDF/XLSX/PPTX exports. The existing `report_export.php` admin + CSRF checks are unchanged. **End-to-end database-connected report export still requires restoration.**
8. **Wolf identity:** original `/public/images/wolf1.png` and `.brand-mark`/`.hero-wolf` animations are preserved, never replaced with stock/generative artwork.

## Files in the changed-files ZIP

```text
TankWeb-v3/
├── APPLY_IT113_PHASE3.txt
├── IT113_PHASE3_IMPLEMENTATION.md
├── ml-service/tests/test_phase3_static.py
├── public/ai_threat_intelligence.php
├── public/assessment/index.html
├── public/assessment/site.css
├── public/assessment/site.js
├── public/assessment/phase3.js                (new)
├── public/assessment/phase3_manifest.json      (new)
├── public/assessment/it113_model_evaluation.pdf (new)
├── public/css/ai_threat_intelligence.css
├── scripts/export_phase3_eval_pdf.py           (new)
├── src/model_evaluation_snapshot.json          (new)
└── src/report_exporter.php
```

The package does **not** include `.env`, Supabase credentials, logs, user data, restored DB contents, datasets or model binaries. Model binaries continue to come from Phase 1.

## Verified locally

- All seven public pages navigated correctly in an embedded-data browser test at desktop (1440×900) and mobile (390×844). No browser JavaScript exceptions or horizontal overflow were detected. Navigation, case inspector, filters and report links were checked.
- PHP `-l` syntax validation for the edited PHP modules passed.
- Earlier Phase 1/2 Python tests passed; Phase 3 static regression tests are included.
- Four-page generated PDF inspected at the text and image-render level; its numerical values are computed from the Phase 1 metadata.
- No live Supabase connection, SQL execution, actual hosted deployment or private ML inference test was run for this release.

## After Supabase restoration

1. Verify that the original databases, users, and security tables are healthy before executing **only** the pending Phase 2 SQL migration in `sql/ml_request_telemetry.sql`.
2. Run authenticated local ML inference; confirm the trace ID and fingerprint shown on protected AI Defense correspond to actual private prediction history.
3. Export an authenticated report using a real logged-in administrator and verify the metadata fallback, trace information and mitigation matrix, including all three formats.
4. Test React/PHP deployment parity and access control through hosted Render/Vercel, then carry the results into **Phase 4** validation.

## Limitations

Synthetic class balance does not reflect deployment prevalence. A category prediction is not confirmed compromise. A feature threshold explanation is not a causal account of the model. The read-only public dashboard cannot show actual request/evidence records. Database restoration still prevents checking live telemetry or end-to-end admin report exports in this session.
