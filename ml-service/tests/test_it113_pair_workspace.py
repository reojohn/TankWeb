"""Contract checks for additive, opt-in, two-seat pair workspace (no DB secrets)."""
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

class PairWorkspaceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql=(ROOT/'sql/it113_pair_workspace.sql').read_text('utf-8')
        cls.pair=(ROOT/'src/it113_pair_workspace.php').read_text('utf-8')
        cls.store=(ROOT/'src/it113_public_store.php').read_text('utf-8')
        cls.api=(ROOT/'public/it113_pair_workspace.php').read_text('utf-8')
        cls.history=(ROOT/'public/it113_demo_history.php').read_text('utf-8')
        cls.ui=(ROOT/'public/assessment/index.html').read_text('utf-8')
        cls.js=(ROOT/'public/assessment/it113-live.js').read_text('utf-8')

    def test_migration_is_additive_and_keeps_private_records(self):
        for part in ['CREATE TABLE IF NOT EXISTS public.it113_pair_workspaces',
                     'CREATE TABLE IF NOT EXISTS public.it113_pair_members',
                     'ADD COLUMN IF NOT EXISTS workspace_id UUID','ON DELETE SET NULL']:
            self.assertIn(part,self.sql)
        self.assertNotIn('DROP TABLE',self.sql)
        self.assertNotIn('TRUNCATE',self.sql)

    def test_schema_enforces_two_seats_and_no_public_roles(self):
        for part in ['it113_pair_one_owner','it113_pair_one_partner',
                     'ENABLE ROW LEVEL SECURITY','FROM anon','FROM authenticated',
                     "role IN ('owner','partner')"]:
            self.assertIn(part,self.sql)

    def test_invite_one_use_48_hours_hashed(self):
        for part in ['bin2hex(random_bytes(32))', "hash('sha256',$raw)",
                     "invite_expires>NOW() FOR UPDATE", "INTERVAL '48 hours'",
                     'invite_digest=NULL','SELECT COUNT(*) FROM public.it113_pair_members']:
            self.assertIn(part,self.pair)

    def test_owner_manages_partner_access(self):
        for part in ["$current['role']!=='owner'", "role='partner'", "'owner'",
                     "'remove_partner'", "'leave'", "'not_member'"]:
            self.assertIn(part,self.pair)

    def test_private_is_default_and_scope_fails_closed(self):
        self.assertIn("getenv('IT113_PAIR_WORKSPACE_ENABLED') ?: 'false'",self.pair)
        self.assertIn("'workspace_id'=>null",self.pair)
        self.assertIn('return null; // fail closed',self.pair)
        self.assertIn('workspace_id IS NULL',self.store)

    def test_storage_uses_membership_for_all_sensitive_queries(self):
        for part in ['it113_pair_scope(true)', 'it113_pair_scope(false)',
                     'WHERE workspace_id=? AND session_digest=? FOR SHARE',
                     'public.it113_pair_members m', 'it113_demo_assessments',
                     'shared_clear_blocked']:
            self.assertIn(part,self.store)

    def test_shared_status_events_and_history_still_enforce_revision(self):
        for part in ['FOR UPDATE','revision=revision+1',
                     'it113_demo_case_events',"$transitions",'workspace_id']:
            self.assertIn(part,self.store)
        self.assertIn("'workspace'=>$workspace", self.history)
        self.assertIn('Shared workspace history cannot be cleared',self.history)

    def test_public_api_checks_origin_json_and_rate_limits(self):
        for part in ["IT113_PUBLIC_DEMO_ENABLED", "it113_demo_limit(",
                     "SAFETY_GATE_UNAVAILABLE", "DEMO_LIMIT_REACHED",
                     "'application/json'", "'cross-site'",'Origin not allowed.',
                     "'invite_token'", "'invite'", "'join'"]:
            self.assertIn(part,self.api)
        self.assertNotIn('ML_SERVICE_TOKEN',self.api)
        self.assertNotIn('DB_PASS',self.api)

    def test_public_frontend_requires_no_pair_invitation(self):
        self.assertNotIn("#pair-invite=", self.ui)
        self.assertNotIn('id="pair-workspace-panel"',self.ui)
        self.assertNotIn('postPair(',self.js)
        self.assertNotIn('initializePair()',self.js)
        self.assertIn('Public findings',self.ui)

    def test_private_history_and_legacy_pair_backend_still_exist(self):
        self.assertIn("$scope['workspace_id']!==null",self.store)
        self.assertIn('it113_pair_scope(true)',self.store)
        self.assertIn('IT113_PAIR_WORKSPACE_ENABLED',self.pair)
        self.assertIn("workspace_id IS NULL",self.store)
        self.assertIn("const pair={active:false",self.js)
        self.assertNotIn('ML_SERVICE_TOKEN',self.js)
        self.assertNotIn('DB_PASS',self.js)

    def test_optional_numeric_csv_session_does_not_block_public_dashboard(self):
        self.assertIn('data-project-mode="public"', self.ui)
        self.assertIn('data-project-mode="session"', self.ui)
        self.assertIn("displayMode='public'",self.js)
        self.assertIn("if(ok){setDisplayMode('session');await syncHistory();}",self.js)
        self.assertIn('public-project-overview',self.ui)

if __name__=='__main__':unittest.main()
