-- IT113 Phase 4/5 dynamic, login-free ACADEMIC assessment history.
-- Isolated from protected ml_predictions, users, security_events and admin cases.
-- ONLY controlled numeric features / synthetic samples are analyzed; this store
-- holds metadata and threshold indicators, never raw IPs, logs or feature vectors.
-- Run in the NEW FortressAuth-IT113 Supabase SQL Editor, once.
BEGIN;
CREATE TABLE IF NOT EXISTS public.it113_demo_assessments (
    trace_id CHAR(32) PRIMARY KEY CHECK (trace_id ~ '^[a-f0-9]{32}$'),
    session_digest CHAR(64) NOT NULL,
    source_type VARCHAR(24) NOT NULL CHECK (source_type IN ('curated', 'numeric_csv')),
    sample_id VARCHAR(64),
    expected_label VARCHAR(48),
    classification VARCHAR(48) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    anomaly_score DOUBLE PRECISION NOT NULL CHECK (anomaly_score BETWEEN 0 AND 1),
    rule_score DOUBLE PRECISION NOT NULL CHECK (rule_score BETWEEN 0 AND 100),
    risk_score DOUBLE PRECISION NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    severity VARCHAR(16) NOT NULL,
    model_version VARCHAR(40) NOT NULL,
    indicators JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(16) NOT NULL DEFAULT 'OPEN'
        CHECK (status IN ('OPEN','INVESTIGATING','MITIGATED','RESOLVED')),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision BETWEEN 0 AND 15),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_it113_demo_session_time
  ON public.it113_demo_assessments (session_digest, created_at DESC);
CREATE TABLE IF NOT EXISTS public.it113_demo_case_events (
    event_id BIGSERIAL PRIMARY KEY,
    trace_id CHAR(32) NOT NULL REFERENCES public.it113_demo_assessments(trace_id) ON DELETE CASCADE,
    session_digest CHAR(64) NOT NULL,
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 15),
    status VARCHAR(16) NOT NULL CHECK (status IN ('OPEN','INVESTIGATING','MITIGATED','RESOLVED')),
    note VARCHAR(240) NOT NULL DEFAULT '',
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(trace_id, revision)
);
CREATE INDEX IF NOT EXISTS idx_it113_demo_events
  ON public.it113_demo_case_events (session_digest, trace_id, revision);
ALTER TABLE public.it113_demo_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.it113_demo_case_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.it113_demo_assessments, public.it113_demo_case_events FROM PUBLIC;
REVOKE ALL ON SEQUENCE public.it113_demo_case_events_event_id_seq FROM PUBLIC;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='anon') THEN
   REVOKE ALL ON public.it113_demo_assessments, public.it113_demo_case_events FROM anon;
   REVOKE ALL ON SEQUENCE public.it113_demo_case_events_event_id_seq FROM anon;
 END IF;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN
   REVOKE ALL ON public.it113_demo_assessments, public.it113_demo_case_events FROM authenticated;
   REVOKE ALL ON SEQUENCE public.it113_demo_case_events_event_id_seq FROM authenticated;
 END IF;
END $$;
COMMIT;
-- Manual retention after grading (run separately when desired):
-- DELETE FROM public.it113_demo_assessments WHERE created_at < NOW() - INTERVAL '30 days';
-- Historical case events will cascade with their parent assessments.
