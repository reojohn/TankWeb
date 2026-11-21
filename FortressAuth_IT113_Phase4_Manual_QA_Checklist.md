# FortressAuth IT113 — Phase 4 Manual QA Checklist

**Evidence date:** 21 November 2026  
**Scope:** Local academic, synthetic-only assessment workflow.  
**Project source:** Latest uploaded `TankWeb-v3(2).zip` with persistence-diagnostics patch.  
**Important:** Do not upload private `.env` files, passwords, tokens, real logs, or identifiers into the academic demo or share them with reviewers.

## Automated test evidence already completed in the analysis environment

- [x] Seven-category held-out synthetic model test: 10,160 / 10,500 correct, accuracy 96.7619%.
- [x] 13 authenticated example in-process ML requests validated for trace IDs and model versions.
- [x] Private `/predict` endpoint denies requests without valid bearer authentication.
- [x] Offline failure/recovery tests: 18 / 18 passed.
- [x] Python regression suite: 36 / 36 passed.
- [x] PHP threat-guidance checks: 14 assertions passed.
- [x] PHP mitigation-workflow checks: 27 assertions passed.

**Interpretation:** These automated tests do not prove public hosting works, do not evaluate live production intrusion traffic, and do not establish real-world detection accuracy. Supabase and actual browser workflows need separate manual evidence.

## Manual browser test A — Seven categories

Use **AI Defense → Sample to analyze**. For each class below, choose the **correct held-out example**, click **Run model analysis**, and check that (a) the predicted label matches the expected label, (b) model version and unique trace ID are shown, and (c) **STORAGE PRIVATE DATABASE** is shown on your local working setup. Record the result in this checklist. A model mismatch should be documented rather than hidden.

| Behavior category | Expected selection | Run | Prediction matches | DB write | Screenshot |
|---|---|---|---|---|---|
| Normal | Correct held-out example | [ ] | [ ] | [ ] | [ ] |
| Brute Force | Correct held-out example | [ ] | [ ] | [ ] | [ ] |
| Credential Stuffing | Correct held-out example | [ ] | [ ] | [ ] | [ ] |
| Reconnaissance | Correct held-out example | [ ] | [ ] | [ ] | [ ] |
| Web Attack | Correct held-out example | [ ] | [ ] | [ ] | [ ] |
| MFA Abuse | Correct held-out example | [ ] | [ ] | [ ] | [ ] |
| Session Abuse | Correct held-out example | [ ] | [ ] | [ ] | [ ] |

**Rate limit:** The public demo gateway is configured for up to 10 requests in a 60-second window and 100 per day per client identity. If the UI returns HTTP 429, do not bypass the limit; retry after its normal window has elapsed.

**Screenshot evidence:** Capture one example with confidence/risk/indicators/trace. Capture the Threat Findings timeline showing multiple categories. Do not include private credentials or connection settings.

## Manual browser test B — Numeric CSV

- [ ] Click **Download CSV template** in AI Defense.
- [ ] Confirm the CSV contains the 20 official numeric feature headers and one valid synthetic feature row.
- [ ] Choose the downloaded CSV file. Verify **Analyze CSV rows** becomes enabled and the page says the numeric row was validated.
- [ ] Click **Analyze CSV rows**, confirm the synthetic/anonymized-data prompt, and verify one actual prediction.
- [ ] Check **Threat Findings** for a numeric CSV entry and **Research Reports** for the updated report count.
- [ ] Negative test: modify a copy of the template by replacing a numeric cell with `not-a-number` and select that file. Verify it is rejected and sends no assessment request.

**Limits:** Up to eight numeric rows per CSV; at most 16 KB per file. Never use actual personal information, raw application logs, passwords, or live network traffic.

## Manual browser test C — Durability, mitigation, analytics

- [ ] Open **Threat Findings**; confirm the new entries appear.
- [ ] Change one flagged case from `OPEN` to `INVESTIGATING` and click **Save status**.
- [ ] Refresh the browser with **Ctrl + Shift + R**; confirm the new findings and case status persist.
- [ ] Open **Security Analytics**; verify the seven category counts match the current assessment history (not held-out test counts).
- [ ] Open **Research Reports**; verify the assessment summary reflects the same history and the held-out 96.76% accuracy is separately labeled.

## Manual browser test D — Exports and report generation

- [ ] In **Research Reports**, download **Current findings JSON**; confirm it contains a current synthetic finding and excludes passwords, ML tokens and DB configuration.
- [ ] Download **Current findings CSV**; confirm each assessment is represented with expected classification, risk and case status columns.
- [ ] Use **Print current report / PDF** and inspect print preview or save to PDF. Confirm visible text fits page and no content is cropped.
- [ ] Download saved **Model Evaluation PDF** and **Metrics JSON**; confirm these represent the held-out synthetic evaluation, not a live incident.

## Manual browser test E — Failure handling

- [ ] Record normal ML health first: `curl.exe --noproxy "*" http://127.0.0.1:8001/health` returns `{"status":"ok"}`.
- [ ] If you wish to demonstrate resilience, gracefully stop **only the known FortressAuth ML terminal**, not another process.
- [ ] Try one controlled assessment; it should show an error **without inventing a prediction**. Saved findings should still be visible.
- [ ] Restart the ML service from the original project directory and verify `/health` again.
- [ ] Run a new synthetic case to confirm recovery. Keep your Supabase data and .env unchanged.

## Hosted deployment (not yet verified)

- [ ] Confirm the deployed static UI loads on desktop and mobile.
- [ ] Verify the hosted PHP-to-ML bridge uses private environment variables (not exposed to browser JavaScript).
- [ ] Verify rate limiting and misuse protection are appropriate **before enabling public anonymous inference**.
- [ ] Verify the hosted DB/session configuration works without exposing legacy user/administrator records.

## Submission notes

Keep distinct in your report: **(1) held-out model evaluation on synthetic records**, **(2) controlled interactive prediction cases**, and **(3) live deployment or real-world security testing**. The first two are supported by the current project; the third cannot be claimed without separate evidence.
