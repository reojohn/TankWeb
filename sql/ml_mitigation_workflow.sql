-- IT113 protected analyst workflow: persistent mitigation status + append-only notes.
-- DO NOT RUN until Supabase restoration finishes and the project is healthy.
-- Apply in Supabase SQL Editor using the owner role; no original tables are dropped.
BEGIN;
CREATE TABLE IF NOT EXISTS public.ml_mitigation_cases (
    case_id CHAR(64) PRIMARY KEY,
    classification VARCHAR(48) NOT NULL,
    severity VARCHAR(12) NOT NULL,
    trace_id VARCHAR(80) NOT NULL DEFAULT '',
    model_version VARCHAR(80) NOT NULL DEFAULT '',
    status VARCHAR(16) NOT NULL DEFAULT 'OPEN'
        CHECK (status IN ('OPEN','INVESTIGATING','MITIGATED','RESOLVED')),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    updated_by BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS public.ml_mitigation_events (
    event_id BIGSERIAL PRIMARY KEY,
    case_id CHAR(64) NOT NULL REFERENCES public.ml_mitigation_cases(case_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK (revision > 0),
    old_status VARCHAR(16) NOT NULL,
    new_status VARCHAR(16) NOT NULL,
    note VARCHAR(500) NOT NULL,
    actor_uid BIGINT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ml_mitigation_events_revision_unique UNIQUE (case_id, revision)
);
CREATE INDEX IF NOT EXISTS idx_ml_mitigation_cases_recent ON public.ml_mitigation_cases (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ml_mitigation_events_case_recent ON public.ml_mitigation_events (case_id, revision DESC);
-- Restrict direct access through Supabase public clients. PHP's trusted DB role needs
-- SELECT/INSERT/UPDATE on cases, SELECT/INSERT on events, and sequence USAGE.
REVOKE ALL ON public.ml_mitigation_cases, public.ml_mitigation_events FROM PUBLIC;
REVOKE ALL ON SEQUENCE public.ml_mitigation_events_event_id_seq FROM PUBLIC;
-- Supabase may grant default privileges to API roles. Remove those explicit
-- grants where roles exist so the workflow remains server-only.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        REVOKE ALL ON public.ml_mitigation_cases, public.ml_mitigation_events FROM anon;
        REVOKE ALL ON SEQUENCE public.ml_mitigation_events_event_id_seq FROM anon;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        REVOKE ALL ON public.ml_mitigation_cases, public.ml_mitigation_events FROM authenticated;
        REVOKE ALL ON SEQUENCE public.ml_mitigation_events_event_id_seq FROM authenticated;
    END IF;
END;
$$;
COMMIT;
