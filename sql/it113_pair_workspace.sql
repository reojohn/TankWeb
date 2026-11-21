-- FortressAuth IT113 | Two-person academic workspace, additive migration.
-- Run AFTER it113_dynamic_assessments.sql and it113_shared_rate_limits.sql.
-- Existing private findings retain NULL workspace_id and remain private.
BEGIN;
CREATE TABLE IF NOT EXISTS public.it113_pair_workspaces (
    workspace_id UUID PRIMARY KEY,
    owner_digest CHAR(64) NOT NULL CHECK (owner_digest ~ '^[a-f0-9]{64}$'),
    invite_digest CHAR(64) UNIQUE,
    invite_expires TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((invite_digest IS NULL AND invite_expires IS NULL)
        OR (invite_digest IS NOT NULL AND invite_expires IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS public.it113_pair_members (
    workspace_id UUID NOT NULL REFERENCES public.it113_pair_workspaces(workspace_id) ON DELETE CASCADE,
    session_digest CHAR(64) NOT NULL UNIQUE CHECK (session_digest ~ '^[a-f0-9]{64}$'),
    role VARCHAR(8) NOT NULL CHECK (role IN ('owner','partner')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (workspace_id, session_digest)
);
CREATE UNIQUE INDEX IF NOT EXISTS it113_pair_one_owner ON public.it113_pair_members(workspace_id) WHERE role='owner';
CREATE UNIQUE INDEX IF NOT EXISTS it113_pair_one_partner ON public.it113_pair_members(workspace_id) WHERE role='partner';
ALTER TABLE public.it113_demo_assessments
  ADD COLUMN IF NOT EXISTS workspace_id UUID REFERENCES public.it113_pair_workspaces(workspace_id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS it113_pair_assessments_time
  ON public.it113_demo_assessments(workspace_id, created_at DESC) WHERE workspace_id IS NOT NULL;
ALTER TABLE public.it113_pair_workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.it113_pair_members ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.it113_pair_workspaces, public.it113_pair_members FROM PUBLIC;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN
    REVOKE ALL ON public.it113_pair_workspaces, public.it113_pair_members FROM anon;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN
    REVOKE ALL ON public.it113_pair_workspaces, public.it113_pair_members FROM authenticated;
  END IF;
END $$;
COMMIT;
-- Do not create permissive RLS policies. Only the privileged server-side PHP DB
-- connection should read/update these tables. Never expose DB_PASS on Vercel.
