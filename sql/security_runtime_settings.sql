BEGIN;

CREATE TABLE IF NOT EXISTS public.security_runtime_settings (
    singleton_id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (singleton_id = 1),
    mode VARCHAR(32) NOT NULL DEFAULT 'balanced'
        CHECK (mode IN ('standard', 'balanced', 'fortress_boost')),
    changed_by BIGINT NULL REFERENCES public.users(id) ON DELETE SET NULL,
    changed_by_username VARCHAR(160) NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO public.security_runtime_settings (
    singleton_id,
    mode,
    changed_by,
    changed_by_username,
    changed_at
)
VALUES (1, 'balanced', NULL, NULL, NOW())
ON CONFLICT (singleton_id) DO NOTHING;

COMMIT;
