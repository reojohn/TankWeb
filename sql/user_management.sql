-- Compatibility migration for older FortressAuth databases.
-- Prefer running sql/hardening.sql, which contains all current hardening fields.
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS full_name VARCHAR(160);
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS session_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ NULL;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS school_id_qr_hash VARCHAR(255) NULL;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS school_id_qr_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS school_id_qr_updated_at TIMESTAMPTZ NULL;

UPDATE public.users
SET full_name = username
WHERE full_name IS NULL OR BTRIM(full_name) = '';
