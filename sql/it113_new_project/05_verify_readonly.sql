-- FortressAuth IT113: READ-ONLY post-install verification.
-- Run AFTER scripts 01, 02, 03, and 04 in the NEW project only.
-- No schema or data changes are made by this script.
SELECT
    expected.table_name,
    CASE WHEN to_regclass('public.' || expected.table_name) IS NULL THEN 'MISSING' ELSE 'PRESENT' END AS status,
    COALESCE(c.relrowsecurity, false) AS rls_enabled
FROM (VALUES
  ('users'), ('login_attempts'), ('banned_ips'), ('security_events'),
  ('ml_predictions'), ('security_runtime_settings'), ('ml_analysis_queue'),
  ('ml_request_telemetry'), ('ml_mitigation_cases'), ('ml_mitigation_events')
) AS expected(table_name)
LEFT JOIN pg_class AS c ON c.oid = to_regclass('public.' || expected.table_name)
ORDER BY expected.table_name;

-- Important fields added by the role migration.
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'users'
  AND column_name IN ('username', 'password_hash', 'role', 'session_version', 'second_factor_type')
ORDER BY column_name;

-- The core schema inserts only one non-sensitive default settings row.
SELECT singleton_id, mode FROM public.security_runtime_settings ORDER BY singleton_id;

-- These numbers should be zero in a new database; no old user data is recovered by this migration.
SELECT 'users' AS source, COUNT(*) AS row_count FROM public.users
UNION ALL SELECT 'security_events', COUNT(*) FROM public.security_events
UNION ALL SELECT 'ml_predictions', COUNT(*) FROM public.ml_predictions
UNION ALL SELECT 'ml_mitigation_cases', COUNT(*) FROM public.ml_mitigation_cases;
