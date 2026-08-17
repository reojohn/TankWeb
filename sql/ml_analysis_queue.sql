-- FortressAuth durable deferred ML-analysis queue (PostgreSQL / Supabase)
-- Run ONCE with the database owner/migration account.
-- The application has a local-file fallback, but this table is recommended on
-- Render so queued analyses survive application restarts/redeploys.

BEGIN;

CREATE TABLE IF NOT EXISTS public.ml_analysis_queue (
    id BIGSERIAL PRIMARY KEY,
    fingerprint VARCHAR(64) UNIQUE NOT NULL,
    source_ip VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'completed', 'discarded')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error_state VARCHAR(64) NULL,
    queued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ NULL,
    result JSONB NULL
);

CREATE INDEX IF NOT EXISTS idx_ml_analysis_queue_pending
    ON public.ml_analysis_queue (status, available_at, queued_at);

CREATE INDEX IF NOT EXISTS idx_ml_analysis_queue_source
    ON public.ml_analysis_queue (source_ip, queued_at DESC);

COMMIT;
