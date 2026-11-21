"""Windows/local ML launcher: load root .env, then bind ML to loopback only."""
from __future__ import annotations

import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for line in (ROOT / '.env').read_text(encoding='utf-8').splitlines() if (ROOT / '.env').is_file() else []:
    line = line.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    key, value = [part.strip() for part in line.split('=', 1)]
    if not key.isidentifier() or not key.isascii():
        continue
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        value = value[1:-1]
    os.environ.setdefault(key, value)

token = os.environ.get('ML_SERVICE_TOKEN', '').strip()
if (len(token) < 24 or token.lower() in {'replace-with-a-random-private-token', 'choose-a-private-token', 'changeme'}
    or token.lower().startswith(('replace_', 'replace-', 'choose-'))
    or not re.fullmatch(r'[A-Za-z0-9._~+/=\-]{24,256}', token)):
    raise SystemExit('ML engine not started: put a private 24+ character ML_SERVICE_TOKEN in root .env')

import uvicorn

if __name__ == '__main__':
    uvicorn.run('app:app', host='127.0.0.1', port=8001, workers=1, log_level='info')
