-- FortressAuth optional per-account School ID 2FA migration
-- Run ONCE with the database owner/migration account.
--
-- Existing accounts remain protected by the previous mandatory-2FA behavior
-- because the new flag defaults to TRUE. An administrator can then explicitly
-- disable 2FA per account from User Management.
--
-- Compatibility note:
-- Older FortressAuth databases may already contain school_id_qr_hash with a
-- NOT NULL constraint. Password-only accounts intentionally store NULL there,
-- so this migration explicitly makes that column nullable.

BEGIN;

ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS school_id_2fa_required BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS school_id_qr_hash VARCHAR(255) NULL;

ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS school_id_qr_enabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS school_id_qr_updated_at TIMESTAMPTZ NULL;

ALTER TABLE public.users
    ALTER COLUMN school_id_qr_hash DROP NOT NULL;

COMMIT;

-- Administrator-issued QR second-factor type. Existing accounts stay Personal ID based.
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS second_factor_type VARCHAR(32) NOT NULL DEFAULT 'personal_id';
