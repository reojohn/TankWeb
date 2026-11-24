"""No-network contracts for login-free, automatic public curated research."""
from pathlib import Path
import os
import shutil
import subprocess
import unittest
ROOT=Path(__file__).resolve().parents[2]

class PublicProjectContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api=(ROOT/'public/it113_public_project.php').read_text('utf-8')
        cls.store=(ROOT/'src/it113_public_project.php').read_text('utf-8')
        cls.js=(ROOT/'public/assessment/it113-live.js').read_text('utf-8')
        cls.html=(ROOT/'public/assessment/index.html').read_text('utf-8')
        cls.infer=(ROOT/'public/it113_demo_infer.php').read_text('utf-8')

    def test_public_no_workspace_id_invitation_or_publication_flags(self):
        self.assertIn('return it113_store_enabled();',self.store)
        for forbidden in ['IT113_PUBLIC_PROJECT_WORKSPACE_ID','IT113_PUBLIC_PROJECT_ENABLED',
                          'IT113_PAIR_WORKSPACE_ENABLED','it113_pair_members','it113_pair_workspaces',
                          'a.workspace_id=','getenv(\'DB_PASS\')']:
            self.assertNotIn(forbidden,self.store+self.api)

    def test_public_api_is_get_only_and_read_only(self):
        self.assertIn("($_SERVER['REQUEST_METHOD']??'GET')!=='GET'",self.api)
        self.assertIn('project_reply(405',self.api)
        for bad in ['INSERT INTO','DELETE FROM','UPDATE public.']:
            self.assertNotIn(bad,self.api+self.store)

    def test_only_existing_curated_synthetic_samples_are_public(self):
        self.assertIn("WHERE a.source_type = 'curated'",self.store)
        self.assertIn('a.sample_id IS NOT NULL',self.store)
        self.assertIn("$labels[$sampleId] !== (string)$row['expected_label']",self.store)
        self.assertIn("$data['not_live_inference']",self.store)
        self.assertIn("$data['contains_real_personal_data']",self.store)
        self.assertIn('LIMIT 200',self.store)
        self.assertIn('count($entries) === 80',self.store)
        self.assertIn("$sourceType = $isCurated ? 'curated' : 'numeric_csv';",self.infer)

    def test_public_response_excludes_session_and_analyst_notes(self):
        for bad in ["'session_digest'=>","'owner_digest'=>","'invite_digest'=>",
                    "'note'=>",'it113_demo_case_events','DB_PASS','ML_SERVICE_TOKEN',
                    'it113_store_session(', 'SELECT *', '$_GET[']:
            self.assertNotIn(bad,self.api+self.store)
        self.assertIn('public_read_only',self.store)
        self.assertIn("substr(strip_tags($item['description']),0,110)",self.store)
        self.assertIn('is_finite($value)',self.store)

    def test_public_rate_limit_and_no_caching(self):
        for mark in ["it113_demo_limit('public_read')",'SAFETY_GATE_UNAVAILABLE',
                     'DEMO_LIMIT_REACHED','Cache-Control: no-store','public_read_only']:
            self.assertIn(mark,self.api+self.store)

    def test_dashboard_is_public_by_default_without_pair_ui(self):
        self.assertIn("displayMode='public'",self.js)
        self.assertIn('data-project-mode="public"',self.html)
        self.assertIn('data-project-mode="session"',self.html) # optional local numeric CSV tests
        self.assertIn('public-project-overview',self.html)
        self.assertIn("fetch('/it113_public_project.php'",self.js)
        self.assertNotIn('id="pair-workspace-panel"',self.html)
        self.assertNotIn('#pair-invite=',self.html)
        self.assertNotIn('postPair(',self.js)
        self.assertNotIn('initializePair()',self.js)

    def test_public_and_private_local_history_never_merge(self):
        self.assertIn('let publicEntries=[]',self.js)
        self.assertIn('publicEntries=publicEnabled&&Array.isArray(data.entries)',self.js)
        self.assertIn("const viewEntries=()=>displayMode==='public'?publicEntries:entries",self.js)
        self.assertNotIn('mergeHistory(publicEntries)',self.js)
        self.assertIn("credentials:'omit'",self.js)

    def test_public_edit_requires_own_browser_record(self):
        self.assertIn('const mayEditPublic = isPublicView() && persistence && ownedTraces.has(trace)',self.js)
        self.assertIn('if(isPublicView() && !ownedTraces.has(trace))return;',self.js)
        self.assertIn('await syncHistory(trace);if(isPublicView())await syncPublic();',self.js)
        self.assertIn('ownedTraces=new Set(j.entries.filter',self.js)
        self.assertIn('PRIVATE',self.js) # unreviewed CSV session still available
        self.assertIn('PUBLIC CASE STATUS / READ-ONLY',self.js)

    def test_curated_inferences_refresh_public_feed(self):
        self.assertIn('if(data.database_written){await syncHistory();await syncPublic();}',self.js)
        self.assertIn("if(ok){setDisplayMode('session');await syncHistory();}",self.js)
        self.assertIn('it113-live.js?v=10',self.html)
        self.assertIn('it113-premium.css?v=10',self.html)

    @unittest.skipUnless(shutil.which('php'), 'PHP CLI unavailable')
    def test_no_config_public_endpoint_safe_and_post_denied(self):
        env={**os.environ,'IT113_DEMO_PERSISTENCE_ENABLED':'false'}
        get=subprocess.run(['php','public/it113_public_project.php'],cwd=ROOT,env=env,
                           capture_output=True,text=True,timeout=10)
        self.assertEqual(get.returncode,0,get.stderr)
        self.assertIn('"status":"storage_disabled"',get.stdout)
        post=subprocess.run(['php','-r',"$_SERVER['REQUEST_METHOD']='POST';require 'public/it113_public_project.php';"],
                            cwd=ROOT,env=env,capture_output=True,text=True,timeout=10)
        self.assertIn('"ok":false',post.stdout)
        self.assertIn('read-only',post.stdout)

    @unittest.skipUnless(shutil.which('php'), 'PHP CLI unavailable')
    def test_curated_evidence_and_sanitizer_runtime(self):
        code='''
        require 'src/it113_public_project.php';
        $labels=it113_public_curated_labels();
        if(count($labels)<7 || ($labels['brute_force_correct']??'')!=='BRUTE_FORCE') exit(3);
        $row=['trace_id'=>str_repeat('a',32),'created_at'=>'2026-11-21','source_type'=>'curated',
          'sample_id'=>'brute_force_correct','expected_label'=>'BRUTE_FORCE','classification'=>'BRUTE_FORCE',
          'confidence'=>0.99,'anomaly_score'=>0.5,'rule_score'=>70,'risk_score'=>60,
          'severity'=>'HIGH','model_version'=>'24112c5d14aaeac3','indicators'=>'[{"description":"<b>safe</b>","observed":1}]',
          'status'=>'INVESTIGATING','revision'=>1,'session_digest'=>'SECRET','note'=>'SECRET'];
        $e=it113_public_project_entry($row); $j=json_encode($e);
        if(str_contains($j,'SECRET')||str_contains($j,'<b>')||$e['indicator_evidence'][0]['description']!=='safe') exit(4);
        echo 'PUBLIC_SYNTHETIC_PROJECTION_OK';
        '''
        r=subprocess.run(['php','-r',code],cwd=ROOT,capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('PUBLIC_SYNTHETIC_PROJECTION_OK',r.stdout)

if __name__=='__main__': unittest.main()
