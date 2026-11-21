-- Apply in the EXISTING healthy FortressAuth-IT113 Supabase SQL Editor.
-- Idempotent additive migration; does not reset or modify assessments/users.
BEGIN;
CREATE TABLE IF NOT EXISTS public.it113_demo_rate_buckets (
    bucket_key CHAR(64) PRIMARY KEY CHECK (bucket_key ~ '^[a-f0-9]{64}$'),
    hits INTEGER NOT NULL CHECK (hits > 0),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_it113_demo_rate_expiry
    ON public.it113_demo_rate_buckets(expires_at);
ALTER TABLE public.it113_demo_rate_buckets ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.it113_demo_rate_buckets FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        REVOKE ALL ON public.it113_demo_rate_buckets FROM anon;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        REVOKE ALL ON public.it113_demo_rate_buckets FROM authenticated;
    END IF;
END $$;
COMMIT;
-- The PHP backend's privileged server-only PostgreSQL connection manages the
-- counters. No Supabase browser/anon access is necessary or permitted.
-- Optional maintenance (executed by private server or SQL editor):
-- DELETE FROM public.it113_demo_rate_buckets WHERE expires_at < NOW() - INTERVAL '1 day';
