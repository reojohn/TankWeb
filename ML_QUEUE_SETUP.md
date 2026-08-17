# FortressAuth Deferred ML Analysis Queue

## What changed

When the remote ML service is sleeping or unavailable, FortressAuth now stores a safe telemetry snapshot instead of losing the ML analysis opportunity. Deterministic defenses still handle the original request immediately. After a later live `/predict` succeeds, FortressAuth replays a small number of queued snapshots through XGBoost and the Autoencoder.

Queued replays are **retrospective only** by design. They update AI findings/history but do not retroactively block the request that already finished. This prevents a delayed replay from unexpectedly blocking the administrator who happened to wake the ML service.

## Required production step

Run `sql/ml_analysis_queue.sql` once in Supabase/PostgreSQL using the schema owner/migration account. If the table is absent, FortressAuth automatically falls back to `data/ml/queue`, but the database queue is recommended on Render because it survives restarts/redeploys.

## Render variables

Keep the existing ML settings and add/confirm:

```env
ML_QUEUE_ENABLED=true
ML_QUEUE_REPLAY_LIMIT=2
ML_QUEUE_RETRY_SECONDS=30
ML_QUEUE_MAX_PENDING=100
ML_QUEUE_MAX_AGE_SECONDS=21600
```

No new secret is required.

## Expected behavior

1. An attack/security event arrives while ML is asleep.
2. Rule engine/authentication/session controls act immediately.
3. The final security telemetry snapshot is queued.
4. A later request wakes the ML service and gets a successful live prediction.
5. FortressAuth replays up to `ML_QUEUE_REPLAY_LIMIT` queued snapshots.
6. AI Defense can show `QUEUED REPLAY`, pending count, and replay delay.
