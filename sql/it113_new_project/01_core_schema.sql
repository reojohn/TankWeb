-- FortressAuth clean-install schema (PostgreSQL)
-- Create the database separately if your hosting provider manages databases.

CREATE TABLE IF NOT EXISTS public.users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    full_name VARCHAR(160),
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    session_version BIGINT NOT NULL DEFAULT 1,
    last_login_at TIMESTAMPTZ NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    school_id_2fa_required BOOLEAN NOT NULL DEFAULT TRUE,
    second_factor_type VARCHAR(32) NOT NULL DEFAULT 'personal_id' CHECK (second_factor_type IN ('personal_id', 'generated_qr')),
    school_id_qr_hash VARCHAR(255) NULL,
    school_id_qr_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    school_id_qr_updated_at TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS public.login_attempts (
    id BIGSERIAL PRIMARY KEY,
    ip_address VARCHAR(64) NOT NULL,
    username VARCHAR(100) NOT NULL,
    success BOOLEAN NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON public.login_attempts (ip_address, attempted_at DESC);

CREATE INDEX IF NOT EXISTS idx_login_attempts_username_time
    ON public.login_attempts (LOWER(username), attempted_at DESC);

CREATE TABLE IF NOT EXISTS public.banned_ips (
    ip VARCHAR(64) PRIMARY KEY,
    banned_until TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_banned_ips_until
    ON public.banned_ips (banned_until);

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

-- Server-persisted Fortress Defense Engine profile. A singleton row keeps
-- Standard / Balanced / Fortress Boost consistent across authorized sessions.
CREATE TABLE IF NOT EXISTS public.security_runtime_settings (
    singleton_id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (singleton_id = 1),
    mode VARCHAR(32) NOT NULL DEFAULT 'balanced'
        CHECK (mode IN ('standard', 'balanced', 'fortress_boost')),
    changed_by BIGINT NULL REFERENCES public.users(id) ON DELETE SET NULL,
    changed_by_username VARCHAR(160) NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO public.security_runtime_settings (
    singleton_id, mode, changed_by, changed_by_username, changed_at
)
VALUES (1, 'balanced', NULL, NULL, NOW())
ON CONFLICT (singleton_id) DO NOTHING;

-- Deferred ML-analysis queue. Deterministic defenses still act immediately;
-- this table preserves telemetry for XGBoost/Autoencoder replay if the remote
-- ML service is temporarily asleep or unavailable.
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

-- Create the first password hash with PHP, preferably using the helper logic in
-- src/auth.php (Argon2id when supported), then insert it manually:
-- INSERT INTO public.users (username, full_name, password_hash)
-- VALUES ('admin', 'Administrator', '<SECURE_PASSWORD_HASH>');
