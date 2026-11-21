-- IT113 Phase 2: durable, minimal ML request telemetry.
-- Execute once in Supabase SQL Editor as the database owner.
-- Stores NO passwords, request bodies, full user-agent strings, sessions or tokens.
CREATE TABLE IF NOT EXISTS public.ml_request_telemetry (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip VARCHAR(64) NOT NULL,
    request_id VARCHAR(24) NOT NULL,
    http_method VARCHAR(12) NOT NULL,
    request_path VARCHAR(180) NOT NULL,
    ua_hash VARCHAR(16) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ml_request_telemetry_source_time
    ON public.ml_request_telemetry (source_ip, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ml_request_telemetry_time
    ON public.ml_request_telemetry (occurred_at DESC);

-- Grant only the minimum permissions needed to the actual runtime DB role.
-- Replace <runtime_role> below with your role (manual migration SQL, NOT literal SQL).
-- GRANT SELECT, INSERT, DELETE ON public.ml_request_telemetry TO <runtime_role>;
-- GRANT USAGE, SELECT ON SEQUENCE public.ml_request_telemetry_id_seq TO <runtime_role>;
-- Retention: schedule in your database maintenance (do not silently remove audit records):
-- DELETE FROM public.ml_request_telemetry WHERE occurred_at < NOW() - INTERVAL '24 hours';
-- The application also performs bounded best-effort cleanup, no more than once in ~1 hour.
