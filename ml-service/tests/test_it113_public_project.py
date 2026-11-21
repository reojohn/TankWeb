"""Safety contracts for anonymous READ-ONLY published IT113 synthetic research."""
from pathlib import Path
import re
import unittest
ROOT=Path(__file__).resolve().parents[2]

class PublicProjectContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api=(ROOT/'public/it113_public_project.php').read_text('utf-8')
        cls.store=(ROOT/'src/it113_public_project.php').read_text('utf-8')
        cls.js=(ROOT/'public/assessment/it113-live.js').read_text('utf-8')
        cls.html=(ROOT/'public/assessment/index.html').read_text('utf-8')
        cls.sql=(ROOT/'sql/it113_pair_workspace.sql').read_text('utf-8')

    def test_public_is_opt_in_and_pinned_by_server_environment(self):
        self.assertIn("getenv('IT113_PUBLIC_PROJECT_ENABLED') ?: 'false'",self.store)
        self.assertIn("getenv('IT113_PUBLIC_PROJECT_WORKSPACE_ID')",self.store)
        self.assertIn('it113_public_project_configured()',self.api)
        self.assertIn("'not_published'",self.api)

    def test_anonymous_api_is_get_only_without_any_write_path(self):
        self.assertIn("($_SERVER['REQUEST_METHOD']??'GET')!=='GET'",self.api)
        self.assertIn('project_reply(405',self.api)
        self.assertNotIn('INSERT INTO',self.api+self.store)
        self.assertNotIn('DELETE FROM',self.api+self.store)
        self.assertNotIn('UPDATE public.',self.api+self.store)

    def test_public_response_excludes_visitor_and_member_secrets(self):
        self.assertNotIn("'session_digest'=>",self.store)
        self.assertNotIn("'owner_digest'=>",self.store)
        self.assertNotIn("'invite_digest'=>",self.store)
        self.assertNotIn("'note'=>",self.store)
        self.assertNotIn('it113_demo_case_events',self.store)
        self.assertNotIn('DB_PASS',self.api+self.store)
        self.assertNotIn('ML_SERVICE_TOKEN',self.api+self.store)
        self.assertNotIn('it113_store_session(',self.api+self.store)

    def test_public_data_only_from_pinned_workspace(self):
        self.assertIn('a.workspace_id=CAST(? AS uuid)',self.store)
        self.assertIn('getenv(\'IT113_PUBLIC_PROJECT_WORKSPACE_ID\')',self.store)
        self.assertIn('INNER JOIN public.it113_pair_workspaces',self.store)
        self.assertIn('LIMIT 80',self.store)
        self.assertNotIn('$_GET[',self.store)

    def test_public_api_has_db_backed_rate_limit(self):
        self.assertIn("it113_demo_limit('read')",self.api)
        self.assertIn('SAFETY_GATE_UNAVAILABLE',self.api)
        self.assertIn('DEMO_LIMIT_REACHED',self.api)
        self.assertIn('Cache-Control: no-store',self.api)

    def test_default_dashboard_public_and_has_private_switch(self):
        self.assertIn("displayMode='public'",self.js)
        self.assertIn('data-project-mode="public"',self.html)
        self.assertIn('data-project-mode="session"',self.html)
        self.assertIn('public-project-overview',self.html)
        self.assertIn("fetch('/it113_public_project.php'",self.js)
        self.assertIn('viewEntries()',self.js)

    def test_public_history_never_merged_into_private_local_storage(self):
        self.assertIn('let publicEntries=[]',self.js)
        self.assertIn('publicEntries=publicEnabled&&Array.isArray(data.entries)',self.js)
        self.assertIn("const viewEntries=()=>displayMode==='public'?publicEntries:entries",self.js)
        self.assertIn('if(pair.active)return',self.js)
        self.assertNotIn('mergeHistory(publicEntries)',self.js)

    def test_public_case_ui_read_only_and_private_notes_not_fetched(self):
        self.assertIn('PUBLIC CASE STATUS / READ-ONLY',self.js)
        self.assertIn('if(isPublicView())return;',self.js)
        self.assertIn('if(!isPublicView()&&showStatus',self.js)
        self.assertIn('Private analyst notes',self.js+self.html)

    def test_private_pair_workflow_still_exists(self):
        self.assertIn("postPair({action:'invite'})",self.js)
        self.assertIn("postPair({action:'join',token})",self.js)
        self.assertIn("workspace_id UUID",self.sql)
        self.assertIn('IT113_PAIR_WORKSPACE_ENABLED', (ROOT/'src/it113_pair_workspace.php').read_text('utf-8'))

if __name__=='__main__': unittest.main()
