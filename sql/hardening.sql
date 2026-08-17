-- FortressAuth hardened schema migration
-- Run this ONCE using the database owner/migration account, not the restricted
-- runtime application account. The web app intentionally no longer ALTERs its schema.

BEGIN;

-- Core administrator account hardening fields.
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS full_name VARCHAR(160);
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ NULL;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS session_version BIGINT NOT NULL DEFAULT 1;

-- Personal/School ID possession-factor fields.
-- school_id_2fa_required controls whether this account must complete the QR
-- factor after a successful password login. Existing accounts default to TRUE
-- so the previous mandatory-2FA behavior is preserved until an administrator
-- explicitly disables 2FA for that account.
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS school_id_2fa_required BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS school_id_qr_hash VARCHAR(255) NULL;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS school_id_qr_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS school_id_qr_updated_at TIMESTAMPTZ NULL;

-- Compatibility with older schemas where the QR hash may have been NOT NULL.
-- Password-only accounts require this field to be nullable.
ALTER TABLE public.users ALTER COLUMN school_id_qr_hash DROP NOT NULL;

UPDATE public.users
SET full_name = username
WHERE full_name IS NULL OR BTRIM(full_name) = '';

-- Authentication attempt history used by IP + account throttling.
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

-- Temporary network bans.
CREATE TABLE IF NOT EXISTS public.banned_ips (
    ip VARCHAR(64) PRIMARY KEY,
    banned_until TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_banned_ips_until
    ON public.banned_ips (banned_until);

COMMIT;

-- LEAST-PRIVILEGE NOTE
-- Use a separate runtime DB role for FortressAuth. It should normally receive
-- CONNECT/USAGE plus SELECT/INSERT/UPDATE/DELETE on required application tables,
-- but NOT CREATE, ALTER, DROP, role-management, or database-owner privileges.
-- Apply future schema changes with the owner/migration role only.

-- Administrator-issued QR second-factor type. Existing accounts stay Personal ID based.
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS second_factor_type VARCHAR(32) NOT NULL DEFAULT 'personal_id';
