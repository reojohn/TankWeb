-- FortressAuth role migration
-- Existing privileged accounts become Super Admins.
-- New accounts default to Admin unless a Super Admin explicitly promotes them.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'users'
          AND column_name = 'role'
    ) THEN
        ALTER TABLE public.users ADD COLUMN role TEXT;

        -- Preserve all authority for accounts that existed before role separation.
        UPDATE public.users SET role = 'superadmin';

        -- Safer default for future inserts.
        ALTER TABLE public.users ALTER COLUMN role SET DEFAULT 'admin';
        ALTER TABLE public.users ALTER COLUMN role SET NOT NULL;
    END IF;
END $$;

ALTER TABLE public.users
DROP CONSTRAINT IF EXISTS users_role_check;

ALTER TABLE public.users
ADD CONSTRAINT users_role_check
CHECK (role IN ('superadmin', 'admin'));

CREATE INDEX IF NOT EXISTS idx_users_role
ON public.users (role);
