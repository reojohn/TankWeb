"""PHP telemetry fallback regression tests, isolated from any real FortressAuth data."""
import json
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

@unittest.skipUnless(shutil.which('php'), 'PHP command-line interpreter is not installed')
class Phase2PhpTests(unittest.TestCase):
    def test_local_request_and_audit_provenance(self):
        with tempfile.TemporaryDirectory(prefix='fortress-php-test-') as temp:
            project = Path(temp)
            shutil.copytree(ROOT/'src', project/'src')
            (project/'data/ml').mkdir(parents=True)
            now = int(time.time())
            ip = '198.51.100.19'
            events = [
                f"[{time.strftime('%Y-%m-%d %H:%M:%S+00:00', time.gmtime(now-20))}] rid=abcdef123456 ip={ip} ua=Mozilla/5.0 (Windows NT 10.0) password_factor_failed username=alice",
                f"[{time.strftime('%Y-%m-%d %H:%M:%S+00:00', time.gmtime(now-100))}] rid=abcdef123457 ip={ip} ua=hash password_factor_failed username=bob",
                f"[{time.strftime('%Y-%m-%d %H:%M:%S+00:00', time.gmtime(now-30))}] rid=abcdef123458 ip={ip} ua=hash sensitive_path_probe",
            ]
            (project/'data/audit.log').write_text('\n'.join(events)+'\n')
            requests = [
                {'ts':now-10,'ip':ip,'rid':'abcdef123456','method':'POST','path':'/login.php','ua':'abcd'},
                {'ts':now-20,'ip':ip,'rid':'abcdef123457','method':'POST','path':'/login.php','ua':'abcd'},
                {'ts':now-110,'ip':ip,'rid':'abcdef123458','method':'GET','path':'/admin','ua':'other'},
                {'ts':now-500,'ip':ip,'rid':'abcdef123459','method':'GET','path':'/older','ua':'other'},
            ]
            (project/'data/ml/request_telemetry.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in requests))
            code = r'''require 'src/ml_threat.php'; $p=[]; $f=fortress_ml_features_for_ip('198.51.100.19', $p); echo json_encode(['features'=>$f,'provenance'=>$p]);'''
            result = subprocess.run(['php','-r',code],cwd=project,text=True,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            values = json.loads(result.stdout)
            f, provenance = values['features'], values['provenance']
            self.assertEqual(f['requests_1m'],2)
            self.assertEqual(f['requests_5m'],3)
            self.assertEqual(f['unique_paths_5m'],2)
            self.assertEqual(f['failed_logins_5m'],2)
            self.assertEqual(f['failed_logins_15m'],2)
            self.assertEqual(f['unique_usernames_15m'],2)
            self.assertEqual(f['sensitive_path_probes_15m'],1)
            self.assertEqual(provenance['request_source'],'local_fallback')
            self.assertEqual(provenance['security_event_source'],'local_fallback')
            self.assertIn('abcdef123456',provenance['sample_request_ids'])
            self.assertNotIn('alice',json.dumps(provenance))

    def test_log_tail_is_bounded_and_has_no_off_by_one(self):
        with tempfile.TemporaryDirectory(prefix='fortress-php-test-') as temp:
            project = Path(temp)
            shutil.copytree(ROOT/'src',project/'src')
            (project/'data').mkdir()
            logfile = project/'data'/'large.log'
            logfile.write_text(''.join(f'{i}\n' for i in range(10000)), encoding='utf-8')
            result = subprocess.run(['php','-r',"require 'src/ml_threat.php'; echo json_encode(fortress_ml_tail_lines('data/large.log',5));"],
                                    cwd=project,text=True,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout),['9995','9996','9997','9998','9999'])


if __name__ == '__main__':
    unittest.main()
