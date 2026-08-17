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
