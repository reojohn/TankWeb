"""No-network regression contracts for datastore failures and UI feedback."""
import subprocess
import shutil
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

class StoreFeedbackContracts(unittest.TestCase):
    def test_failure_reason_never_echoes_sensitive_connection_details(self):
        store = (ROOT/'src/it113_public_store.php').read_text(encoding='utf-8')
        gateway = (ROOT/'public/it113_demo_infer.php').read_text(encoding='utf-8')
        history = (ROOT/'public/it113_demo_history.php').read_text(encoding='utf-8')
        for marker in ('database_connection_failed','database_write_failed',
                       'missing_database_config','pgsql_driver_missing',
                       'IT113_DB_CONNECT_TIMEOUT_SECONDS', 'PDO::getAvailableDrivers()',
                       'it113_store_log_error'):
            self.assertIn(marker, store)
        self.assertIn("$record['persistence_status']", gateway)
        self.assertIn('it113_store_diagnostic()', history)
        self.assertNotIn('$error->getMessage()', store)
        self.assertNotIn('$e->getMessage()', store)

    def test_browser_displays_database_failure_separately_from_model_success(self):
        js=(ROOT/'public/assessment/it113-live.js').read_text(encoding='utf-8')
        html=(ROOT/'public/assessment/index.html').read_text(encoding='utf-8')
        self.assertIn('database_write_failed', js)
        self.assertIn('persistence_status', js)
        self.assertIn('Private Supabase history active', js)
        self.assertIn('it113-live.js?v=8', html)
        self.assertIn('it113-premium.css?v=8', html)

    def test_launcher_clears_stale_local_process_overrides_only_with_dotenv(self):
        bat=(ROOT/'Start FortressAuth.bat').read_text(encoding='utf-8')
        self.assertIn('if exist ".env" (', bat)
        self.assertIn('for %%V in (DB_HOST DB_PORT DB_NAME DB_USER DB_PASS', bat)
        self.assertIn('IT113_DEMO_PERSISTENCE_ENABLED',bat)
        self.assertIn('PHP startup skipped',bat)

    @unittest.skipUnless(shutil.which('php'), 'PHP CLI is not installed')
    def test_disabled_and_missing_configuration_have_safe_states(self):
        code = r'''
        require 'src/it113_public_store.php';
        putenv('IT113_DEMO_PERSISTENCE_ENABLED=false');
        if (it113_store_db() !== null || it113_store_diagnostic() !== 'disabled') exit(3);
        putenv('IT113_DEMO_PERSISTENCE_ENABLED=true');
        foreach (['DB_HOST','DB_PORT','DB_NAME','DB_USER','DB_PASS'] as $key) putenv($key);
        if (it113_store_db() !== null || it113_store_diagnostic() !== 'missing_database_config') exit(4);
        echo 'SAFE_OFFLINE_STATES_OK';
        '''
        outcome=subprocess.run(['php','-r',code], cwd=ROOT, capture_output=True,
                               text=True, timeout=10, check=False)
        self.assertEqual(outcome.returncode,0,outcome.stderr)
        self.assertIn('SAFE_OFFLINE_STATES_OK',outcome.stdout)

if __name__ == '__main__': unittest.main()
