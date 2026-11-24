"""Shared curated-only IT113 live analysis, state restoration and alignment contracts."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[2]

class SharedLiveContracts(unittest.TestCase):
    def test_public_polling_is_shared_bounded_and_only_on_visible_tabs(self):
        js=(ROOT/'public/assessment/it113-live.js').read_text('utf-8')
        api=(ROOT/'public/it113_public_project.php').read_text('utf-8')
        limiter=(ROOT/'src/it113_shared_limiter.php').read_text('utf-8')
        for text in ("publicSyncIntervalMs=20000", "if(!document.hidden)syncPublic()",
                     "fetch('/it113_public_project.php'", "credentials:'omit'",
                     "publicSyncInFlight", "nextPublicSyncAt"):
            self.assertIn(text,js)
        self.assertIn("it113_demo_limit('public_read')",api)
        self.assertIn("'public_read' => [12, 6000, 120, 40000]",limiter)

    def test_public_restore_and_private_csv_isolation(self):
        js=(ROOT/'public/assessment/it113-live.js').read_text('utf-8')
        for text in ('publicResultCacheKey','restoreSharedResult()','cacheSharedResult(latest)',
                     "entry.source_type==='curated'", "currentLiveScope='public'",
                     "currentLiveScope=e.source_type==='curated'?'public':'private'", 
                     "renderedPublicSignature", "previousResult"):
            self.assertIn(text,js)
        self.assertNotIn('cacheSharedResult(e);',js)
        self.assertIn("const keys=['trace_id','at','source_type','sample_id'",js)

    def test_css_button_tracks_input_not_help_text(self):
        css=(ROOT/'public/assessment/it113-premium.css').read_text('utf-8')
        html=(ROOT/'public/assessment/index.html').read_text('utf-8')
        self.assertIn('align-items:start;gap:15px;',css)
        self.assertIn('.live-run{align-self:start;margin-top:28px;',css)
        self.assertIn('.live-run{width:100%;margin-top:0}',css)
        self.assertIn('id="live-sync-note"',html)
        self.assertIn('it113-live.js?v=10',html)
        self.assertIn('it113-premium.css?v=10',html)

    @unittest.skipUnless(shutil.which('node'),'Node.js is unavailable')
    def test_live_shared_two_client_simulation(self):
        result=subprocess.run(['node',str(ROOT/'ml-service/tests/it113_live_sync_vm.cjs')],
                              cwd=ROOT,capture_output=True,text=True,timeout=15,check=False)
        self.assertEqual(result.returncode,0,result.stdout+'\n'+result.stderr)
        self.assertIn('PASS: two distinct clients',result.stdout)

if __name__=='__main__':unittest.main()
