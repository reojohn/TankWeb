-- FortressAuth administrator-issued QR second-factor migration
-- Run once with the Supabase database owner / migration account.
-- Existing accounts remain Personal ID based because the new column defaults
-- to 'personal_id'. Password-only accounts are unaffected.

BEGIN;

ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS second_factor_type VARCHAR(32) NOT NULL DEFAULT 'personal_id';

UPDATE public.users
SET second_factor_type = 'personal_id'
WHERE second_factor_type IS NULL
   OR second_factor_type NOT IN ('personal_id', 'generated_qr');

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'users_second_factor_type_check'
          AND conrelid = 'public.users'::regclass
    ) THEN
        ALTER TABLE public.users
            ADD CONSTRAINT users_second_factor_type_check
            CHECK (second_factor_type IN ('personal_id', 'generated_qr'));
    END IF;
END $$;

COMMIT;
