"""Development-only smoke test: Python service plus PHP client on loopback."""
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[1]
token = '0123456789abcdef' * 4
env = os.environ.copy()
env['ML_SERVICE_TOKEN'] = token
server = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app:app', '--host', '127.0.0.1', '--port', '8001'],
                          cwd=root/'ml-service', env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
try:
    for _ in range(50):
        if server.poll() is not None: raise RuntimeError('ML server exited unexpectedly')
        try:
            with urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=.25) as r:
                if json.load(r)['status'] == 'ok': break
        except Exception: time.sleep(.12)
    else: raise RuntimeError('ML server not healthy')
    features = {f:0 for f in json.loads((root/'ml-service/models/model_metadata.json').read_text())['dataset']['features']}
    features.update({'requests_1m':5, 'requests_5m':20, 'unique_paths_5m':5,
                     'auth_endpoint_requests_5m': 5, 'failed_logins_5m': 4, 'failed_logins_15m': 7,
                     'post_ratio_5m':.6, 'off_hours':1, 'avg_request_interval_5m':2})
    data = json.dumps({'features':features,'rule_score':55,'trace_id':'abcdefabcdef'},separators=(',', ':'))
    code = "require 'src/ml_threat.php'; $r = fortress_ml_post(json_decode(getenv('FA_TEST_PAYLOAD'),true)); echo json_encode($r);"
    env.update({'ML_SERVICE_URL':'http://127.0.0.1:8001', 'FA_TEST_PAYLOAD':data})
    out = subprocess.run(['php','-r',code],cwd=root,env=env,text=True,capture_output=True,timeout=15)
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout)
    assert result is not None, out.stdout
    assert result['trace_id'] == 'abcdefabcdef', result
    assert 'model_version' in result and 'indicator_evidence' in result
    print('PASS: real PHP -> authenticated FastAPI -> XGBoost/autoencoder -> traceable response')
    print('Classification', result['classification'], 'risk',result['risk_score'],'trace',result['trace_id'])
finally:
    server.terminate()
    try: server.communicate(timeout=3)
    except subprocess.TimeoutExpired: server.kill()
