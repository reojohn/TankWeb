-- FortressAuth persistent security + ML history migration (Supabase PostgreSQL)
-- Safe to run more than once.

-- Durable audit/security evidence. The application dual-writes audit.log and
-- this table so Render restarts do not erase Security Analytics/Logs evidence.
CREATE TABLE IF NOT EXISTS public.security_events (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_key VARCHAR(190) NOT NULL,
    source_ip VARCHAR(64) NULL,
    user_id BIGINT NULL,
    username VARCHAR(160) NULL,
    request_path VARCHAR(500) NULL,
    http_method VARCHAR(16) NULL,
    issues TEXT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'INFO',
    outcome VARCHAR(32) NOT NULL DEFAULT 'RECORDED',
    raw_line TEXT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- If an earlier version of security_events already exists, make sure it has
-- every column the current FortressAuth code reads/writes.
ALTER TABLE public.security_events ADD COLUMN IF NOT EXISTS id BIGSERIAL;
ALTER TABLE public.security_events ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE public.security_events ADD COLUMN IF NOT EXISTS event_key VARCHAR(190);
ALTER TABLE public.security_events ADD COLUMN IF NOT EXISTS source_ip VARCHAR(64);
ALTER TABLE public.security_events ADD COLUMN IF NOT EXISTS user_id BIGINT;
ALTER TABLE public.security_events ADD COLUMN IF NOT EXISTS username VARCHAR(160);
ALTER TABLE public.security_events ADD COLUMN IF NOT EXISTS request_path VARCHAR(500);
ALTER TABLE public.security_events ADD COLUMN IF NOT EXISTS http_method VARCHAR(16);
ALTER TABLE public.security_events ADD COLUMN IF NOT EXISTS issues TEXT;
ALTER TABLE public.security_events ADD COLUMN IF NOT EXISTS severity VARCHAR(16) NOT NULL DEFAULT 'INFO';
ALTER TABLE public.security_events ADD COLUMN IF NOT EXISTS outcome VARCHAR(32) NOT NULL DEFAULT 'RECORDED';
ALTER TABLE public.security_events ADD COLUMN IF NOT EXISTS raw_line TEXT;
ALTER TABLE public.security_events ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_security_events_time
    ON public.security_events (occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_key_time
    ON public.security_events (event_key, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_source_time
    ON public.security_events (source_ip, occurred_at DESC)
    WHERE source_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_events_user_time
    ON public.security_events (user_id, occurred_at DESC)
    WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_events_metadata_gin
    ON public.security_events USING GIN (metadata);

-- Permanent model findings. This is intentionally separate from
-- ml_analysis_queue: queue rows are temporary delivery/retry state, while this
-- table is the durable historical result used by AI Defense and reports.
CREATE TABLE IF NOT EXISTS public.ml_predictions (
    id BIGSERIAL PRIMARY KEY,
    record_fingerprint VARCHAR(64) UNIQUE NOT NULL,
    analyzed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip VARCHAR(64) NOT NULL,
    model_name VARCHAR(120) NOT NULL DEFAULT 'FortressAuth Hybrid ML',
    analysis_mode VARCHAR(32) NOT NULL DEFAULT 'LIVE',
    classification VARCHAR(64) NOT NULL DEFAULT 'UNKNOWN',
    confidence DOUBLE PRECISION NULL,
    anomaly_score DOUBLE PRECISION NULL,
    rule_score DOUBLE PRECISION NULL,
    xgboost_risk DOUBLE PRECISION NULL,
    risk_score DOUBLE PRECISION NULL,
    severity VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    enforcement_mode VARCHAR(32) NOT NULL DEFAULT 'ADVISORY',
    enforcement_action VARCHAR(32) NOT NULL DEFAULT 'OBSERVE',
    automatic_block BOOLEAN NOT NULL DEFAULT FALSE,
    queue_delay_seconds INTEGER NOT NULL DEFAULT 0 CHECK (queue_delay_seconds >= 0),
    features JSONB NOT NULL DEFAULT '{}'::jsonb,
    result JSONB NOT NULL DEFAULT '{}'::jsonb,
    queue_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    record JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ml_predictions_analyzed
    ON public.ml_predictions (analyzed_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_ml_predictions_source
    ON public.ml_predictions (source_ip, analyzed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ml_predictions_class
    ON public.ml_predictions (classification, analyzed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ml_predictions_severity
    ON public.ml_predictions (severity, analyzed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ml_predictions_action
    ON public.ml_predictions (enforcement_action, analyzed_at DESC);

-- Quick verification after running this migration.
SELECT
    to_regclass('public.security_events') AS security_events_table,
    to_regclass('public.ml_predictions') AS ml_predictions_table,
    to_regclass('public.ml_analysis_queue') AS ml_analysis_queue_table;
