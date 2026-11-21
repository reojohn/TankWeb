"""IT113 Phase 4 / Step 4 -- controlled security failure and recovery evidence.

Run: python ml-service/tests/run_phase4_failure_recovery.py

This script NEVER reads the project .env, visits public hosts, or connects to
Supabase. It creates a disposable copy of src/ and data/, uses a synthetic
payload, and starts a short-lived ML server on 127.0.0.1 only. The private
bearer token is generated for this test run and is never written to evidence.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ML_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ML_ROOT.parent
RESULTS_DIR = ML_ROOT / 'phase4-results'
OUTFILE = RESULTS_DIR / 'phase4_failure_recovery_summary.json'


def check(condition: bool, label: str, results: list[dict], detail: str = '') -> None:
    results.append({'check': label, 'result': 'PASS' if condition else 'FAIL', 'detail': detail})
    print(f"{'PASS' if condition else 'FAIL'}: {label}" + (f' ({detail})' if detail else ''))
    if not condition:
        raise AssertionError(label + ': ' + detail)


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return int(sock.getsockname()[1])


def request_json(url: str, *, payload: dict | None = None, token: str | None = None, timeout: float = 3.0) -> tuple[int, dict]:
    headers = {'Content-Type': 'application/json'}
    if token is not None:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8') if payload is not None else None,
        headers=headers,
        method='POST' if payload is not None else 'GET',
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode('utf-8'))


def php_call(project: Path, env: dict[str, str], code: str, *, payload: dict | None = None) -> dict:
    run_env = env.copy()
    if payload is not None:
        run_env['FORTRESS_PHASE4_PAYLOAD'] = json.dumps(payload, ensure_ascii=True)
    run = subprocess.run(
        ['php', '-r', code], cwd=project, env=run_env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding='utf-8', errors='replace', timeout=15,
    )
    if run.returncode != 0:
        # Never print a private environment variable or full request body.
        raise AssertionError(f'isolated PHP process failed with exit status {run.returncode}: {run.stderr[-500:]}')
    try:
        return json.loads(run.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError('Isolated PHP returned invalid JSON: ' + run.stdout[-300:]) from error


@contextmanager
def fake_api(mode: str):
    """Loopback-only negative-response fixture; never a production service."""
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body_len = int(self.headers.get('Content-Length', '0'))
            self.rfile.read(min(body_len, 65536))
            if mode == 'timeout':
                time.sleep(0.7)
            if mode == 'invalid_response':
                code, body = 200, {'classification': 'BRUTE_FORCE', 'confidence': 0.99,
                                   'risk_score': 90, 'trace_id': 'bad-trace',
                                   'model_version': '0'*16, 'indicator_evidence': []}
            elif mode == 'unavailable':
                code, body = 503, {'detail': 'Temporarily unavailable'}
            else:
                code, body = 200, {}
            data = json.dumps(body).encode('utf-8')
            try:
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Expected during the deliberately simulated timeout.

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def main() -> int:
    if shutil.which('php') is None:
        print('ERROR: PHP executable is not on PATH. Run from a terminal where `php -v` works.')
        return 2
    metadata = json.loads((ML_ROOT / 'models' / 'model_metadata.json').read_text(encoding='utf-8'))
    features = {name: 0 for name in metadata['dataset']['features']}
    features.update({
        'requests_1m': 5, 'requests_5m': 20, 'unique_paths_5m': 5,
        'auth_endpoint_requests_5m': 5, 'failed_logins_5m': 4,
        'failed_logins_15m': 7, 'post_ratio_5m': 0.6,
        'off_hours': 1, 'avg_request_interval_5m': 2,
    })
    trace = 'f4' + secrets.token_hex(10)  # Synthetic request correlation only.
    payload = {'features': features, 'rule_score': 55, 'trace_id': trace}
    token = secrets.token_hex(32)
    blank_env = os.environ.copy()
    blank_env.pop('ML_SERVICE_TOKEN', None)
    env = blank_env.copy()
    env.update({
        'ML_SERVICE_TOKEN': token, 'ML_SERVICE_ENABLED': 'true',
        'ML_ASSISTED_ENFORCEMENT': 'false', 'ML_QUEUE_ENABLED': 'true',
        'ML_QUEUE_RETRY_SECONDS': '10', 'ML_TIMEOUT_MS': '300',
        'TRUST_PROXY_HEADERS': 'false',
    })
    results: list[dict] = []
    print('\nIT113 PHASE 4 / STEP 4 -- FAILURE AND RECOVERY VALIDATION')
    print('Scope: isolated temporary PHP data + loopback-only ML service')
    print('Supabase, remote hosts, and project .env: NOT USED')
    print('-' * 75)

    server: subprocess.Popen | None = None
    try:
        # Startup must fail closed when token is not configured.
        missing = subprocess.run(
            [sys.executable, '-c', 'import app'], cwd=ML_ROOT, env=blank_env,
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=20,
        )
        check(missing.returncode != 0 and 'ML_SERVICE_TOKEN' in missing.stderr,
              'ML API refuses startup with an unset token', results)

        # Every PHP test uses a scratch copy of the actual PHP modules.
        with tempfile.TemporaryDirectory(prefix='fortress-it113-phase4-') as scratch:
            project = Path(scratch)
            shutil.copytree(PROJECT_ROOT / 'src', project / 'src')
            (project / 'data' / 'ml').mkdir(parents=True)
            php_prefix = "require 'src/ml_threat.php'; "
            php_post = php_prefix + (
                "$p=json_decode(getenv('FORTRESS_PHASE4_PAYLOAD'),true); "
                "$r=fortress_ml_post($p); "
                "echo json_encode(['result'=>$r,'status'=>fortress_ml_service_status()]);"
            )

            # No network may be contacted for an insecure remote HTTP destination.
            remote_env = env | {'ML_SERVICE_URL': 'http://example.invalid:4567'}
            remote = php_call(project, remote_env, php_post, payload=payload)
            check(remote['result'] is None and remote['status']['state'] == 'CONFIG_ERROR',
                  'PHP rejects insecure remote HTTP ML URLs', results)

            # Invalid PHP service token is explicitly distinguished from outage.
            invalid_env = env | {'ML_SERVICE_URL': 'http://127.0.0.1:1', 'ML_SERVICE_TOKEN': 'placeholder'}
            invalid = php_call(project, invalid_env, php_post, payload=payload)
            check(invalid['result'] is None and invalid['status']['state'] == 'AUTH_CONFIG_ERROR',
                  'PHP refuses missing/placeholder service credentials', results)

            port = available_port()
            offline_env = env | {'ML_SERVICE_URL': f'http://127.0.0.1:{port}'}
            php_enqueue = php_prefix + (
                "$p=json_decode(getenv('FORTRESS_PHASE4_PAYLOAD'),true); "
                "$r=fortress_ml_post($p); "
                "$one=fortress_ml_queue_enqueue('198.51.100.55',$p['features'],55.0,'phase4_outage',"
                "['request_source'=>'synthetic_test','security_event_source'=>'synthetic_test','sample_request_ids'=>['it113-test']],$p['trace_id']); "
                "$duplicate=fortress_ml_queue_enqueue('198.51.100.55',$p['features'],55.0,'phase4_outage',[], $p['trace_id']); "
                "echo json_encode(['prediction'=>$r,'queued'=>$one,'duplicate'=>$duplicate,"
                "'queue'=>fortress_ml_queue_status(),'status'=>fortress_ml_service_status()]);"
            )
            outage = php_call(project, offline_env, php_enqueue, payload=payload)
            check(outage['prediction'] is None and outage['queued'] is True and outage['duplicate'] is False
                  and outage['queue']['pending'] == 1 and outage['status']['state'] in ('TRANSPORT_ERROR', 'TIMEOUT'),
                  'Offline ML predictions are queued once without blocking PHP', results)
            pending = list((project / 'data' / 'ml' / 'queue').glob('*.json'))
            check(len(pending) == 1, 'Outage queue contains one synthetic pending item', results)

            php_replay = php_prefix + (
                "$n=fortress_ml_process_queue(1); "
                "echo json_encode(['processed'=>$n,'queue'=>fortress_ml_queue_status(),"
                "'status'=>fortress_ml_service_status()]);"
            )
            failed_replay = php_call(project, offline_env, php_replay)
            pending = list((project / 'data' / 'ml' / 'queue').glob('*.json'))
            queued_record = json.loads(pending[0].read_text(encoding='utf-8')) if pending else {}
            check(failed_replay['processed'] == 0 and failed_replay['queue']['pending'] == 1
                  and queued_record.get('attempts') == 1
                  and queued_record.get('available_at', 0) > int(time.time()),
                  'Failed replay retains item with a retry backoff', results)

            # Advance only this disposable test fixture's retry clock.
            queued_record['available_at'] = int(time.time()) - 1
            pending[0].write_text(json.dumps(queued_record), encoding='utf-8')

            # A temporary real ML server tests recovery (not a fake success response).
            server = subprocess.Popen(
                [sys.executable, '-m', 'uvicorn', 'app:app', '--host', '127.0.0.1',
                 '--port', str(port), '--log-level', 'error'],
                cwd=ML_ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            healthy = False
            for _ in range(100):
                if server.poll() is not None:
                    break
                try:
                    status, response = request_json(f'http://127.0.0.1:{port}/health', timeout=0.3)
                    healthy = status == 200 and response == {'status': 'ok'}
                    if healthy:
                        break
                except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                    pass
                time.sleep(0.12)
            check(healthy, 'Recovered real ML server responds on loopback', results)

            base = f'http://127.0.0.1:{port}'
            status, _ = request_json(base + '/model-info')
            status2, _ = request_json(base + '/predict', payload=payload, token='invalid-' + token)
            check(status == 401 and status2 == 401,
                  'Sensitive endpoints reject anonymous/incorrect tokens', results)

            malformed = dict(payload)
            malformed['features'] = {**features, 'requests_1m': 21}
            malformed_status, _ = request_json(base + '/predict', payload=malformed, token=token)
            check(malformed_status == 422,
                  'API rejects inconsistent rolling-window data', results)

            invalid_php = php_call(project, env | {'ML_SERVICE_URL': base, 'ML_SERVICE_TOKEN': secrets.token_hex(32)},
                                   php_post, payload=payload)
            check(invalid_php['result'] is None and invalid_php['status']['state'] == 'UNAUTHORIZED'
                  and invalid_php['status']['http_code'] == 401,
                  'PHP detects ML token disagreement without accepting a prediction', results)

            bad_payload_php = php_call(project, env | {'ML_SERVICE_URL': base}, php_post, payload=malformed)
            check(bad_payload_php['result'] is None and bad_payload_php['status']['state'] == 'INVALID_PAYLOAD',
                  'PHP records 422 invalid-feature response safely', results)

            recovered = php_call(project, env | {'ML_SERVICE_URL': base}, php_replay)
            records_path = project / 'data' / 'ml' / 'predictions.jsonl'
            stored = [json.loads(line) for line in records_path.read_text(encoding='utf-8').splitlines()] if records_path.exists() else []
            latest = stored[-1] if stored else {}
            model_result = latest.get('result', {})
            check(recovered['processed'] == 1 and recovered['queue']['pending'] == 0
                  and recovered['status']['state'] == 'CONNECTED',
                  'Recovered service replays and clears the pending snapshot', results)
            check(model_result.get('trace_id') == trace
                  and isinstance(model_result.get('model_version'), str)
                  and len(model_result['model_version']) == 16
                  and model_result.get('analysis_mode') == 'QUEUED_REPLAY'
                  and model_result.get('enforcement_mode') == 'RETROSPECTIVE'
                  and model_result.get('automatic_block') is False
                  and latest.get('evidence', {}).get('sample_request_ids') == ['it113-test'],
                  'Recovered prediction retains trace, evidence and non-blocking history', results)

            # An adversarial or broken ML response must not be trusted by PHP.
            with fake_api('invalid_response') as fake_port:
                invalid_response = php_call(project, env | {'ML_SERVICE_URL': f'http://127.0.0.1:{fake_port}'},
                                            php_post, payload=payload)
            check(invalid_response['result'] is None
                  and invalid_response['status']['state'] == 'INVALID_RESPONSE',
                  'PHP discards mismatched-trace responses', results)

            with fake_api('unavailable') as fake_port:
                unavailable = php_call(project, env | {'ML_SERVICE_URL': f'http://127.0.0.1:{fake_port}'},
                                       php_post, payload=payload)
            check(unavailable['result'] is None
                  and unavailable['status']['state'] == 'SERVICE_UNAVAILABLE',
                  'PHP handles HTTP 503 without accepting a prediction', results)

            with fake_api('timeout') as fake_port:
                timed = php_call(project, env | {'ML_SERVICE_URL': f'http://127.0.0.1:{fake_port}',
                                                 'ML_TIMEOUT_MS': '250'}, php_post, payload=payload)
            check(timed['result'] is None and timed['status']['state'] in ('TIMEOUT', 'TRANSPORT_ERROR')
                  and timed['status']['latency_ms'] < 4000,
                  'Slow ML response is bounded by the PHP timeout', results)

            # Ensure defense is still configured and optional AI block is disabled.
            policy_code = php_prefix + (
                "$p=fortress_security_policy(); "
                "$f=['failed_logins_5m'=>12,'failed_logins_15m'=>18,'sensitive_path_probes_15m'=>2]; "
                "$r=['classification'=>'BRUTE_FORCE','risk_score'=>100,'confidence'=>1,'rule_score'=>95]; "
                "$d=fortress_ml_enforcement_decision('198.51.100.55',$f,$r); "
                "echo json_encode(['threshold'=>$p['password_ip_failure_limit'],"
                "'enabled'=>$d['enabled'],'block'=>$d['block'],'action'=>$d['action']]);"
            )
            policy = php_call(project, env, policy_code)
            check(policy['threshold'] > 0 and policy['enabled'] is False
                  and policy['block'] is False and policy['action'] == 'ADVISORY_ONLY',
                  'Deterministic policy remains configured; AI enforcement stays advisory', results)

            # Only sanitized diagnostic status is written (no credentials or URLs).
            status_path = project / 'data' / 'ml' / 'service_status.json'
            status_text = status_path.read_text(encoding='utf-8')
            check(token not in status_text and base not in status_text
                  and 'Authorization' not in status_text,
                  'Service status evidence excludes secrets and destination URL', results)

    finally:
        if server is not None:
            server.terminate()
            try:
                server.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.communicate(timeout=3)

    summary = {
        'title': 'FortressAuth IT113 Phase 4 Step 4 - Local Failure and Recovery',
        'tested_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'data_origin': 'synthetic payload, isolated temporary PHP data',
        'network_scope': '127.0.0.1 only; no Supabase or remote hosts',
        'overall': 'PASS',
        'checks_passed': len(results),
        'checks_failed': 0,
        'checks': results,
        'model_version': model_result.get('model_version'),
        'limitations': [
            'Actual Supabase/PostgreSQL queue persistence and recovery were not tested.',
            'A full deployed PHP session, security middleware and administrator UI were not exercised.',
            'Timeouts and malformed responses were exercised with a loopback negative-response fixture.',
            'Results are a controlled local integration test, not a production penetration test.',
        ],
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    OUTFILE.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print('-' * 75)
    print(f"SUMMARY: {len(results)}/{len(results)} local failure/recovery checks PASSED")
    print('Evidence JSON:', OUTFILE)
    print('NOTE: Supabase and deployed application verification remain pending.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (AssertionError, subprocess.TimeoutExpired, OSError, ValueError, KeyError) as exc:
        print('FAILED: ' + str(exc), file=sys.stderr)
        sys.exit(1)
