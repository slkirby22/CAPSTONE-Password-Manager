"""Exercise the actual single-worker start command with a temporary empty DB."""
import base64
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

with tempfile.TemporaryDirectory(prefix='capstone-synthetic-') as directory:
    # Deliberately public fixtures, usable only inside this disposable local process.
    env = dict(os.environ, APP_ENV='synthetic', SYNTHETIC_DATA_ONLY='true',
               DATABASE_URL=f'sqlite:///{directory}/synthetic.db',
               SECRET_KEY='synthetic-wsgi-session-00000000000000',
               JWT_SECRET_KEY='synthetic-wsgi-jwt-000000000000000000',
               ENCRYPTION_KEY=base64.urlsafe_b64encode(b'0' * 32).decode(),
               TRUSTED_HOSTS='127.0.0.1', BIND_HOST='127.0.0.1', PORT='18080')
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(['sh', 'deployment/start.sh'], env=env,
                                   stdout=log, stderr=log, start_new_session=True)
        try:
            for attempt in range(60):
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read().decode())
                try:
                    with urllib.request.urlopen('http://127.0.0.1:18080/healthz', timeout=1) as response:
                        assert response.status == 200
                    break
                except (urllib.error.URLError, TimeoutError):
                    time.sleep(0.25)
            else:
                raise RuntimeError('WSGI readiness timeout')
            with urllib.request.urlopen('http://127.0.0.1:18080/', timeout=3) as response:
                assert response.status == 200
            try:
                urllib.request.urlopen('http://127.0.0.1:18080/get_audit_logs', timeout=3)
            except urllib.error.HTTPError as error:
                assert error.code == 401
            else:
                raise AssertionError('Anonymous audit route must reject access')
            import sqlite3
            with sqlite3.connect(Path(directory) / 'synthetic.db') as db:
                assert db.execute('select count(*) from user').fetchone()[0] == 0
                assert db.execute('select count(*) from password').fetchone()[0] == 0
            sentinel = 'PUBLIC_WSGI_SECRET_TOKEN_SOURCE_SENTINEL'
            request = urllib.request.Request(
                'http://127.0.0.1:18080/healthz?source=' + sentinel,
                headers={'Authorization': 'Bearer ' + sentinel,
                         'Cookie': 'untrusted=' + sentinel,
                         'User-Agent': sentinel, 'Referer': 'https://example.invalid/' + sentinel})
            with urllib.request.urlopen(request, timeout=3) as response:
                assert response.status == 200
                assert sentinel.encode() not in response.read()

        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=10)
        log.seek(0)
        output = log.read().decode()
        assert sentinel not in output, 'Request source leaked into server diagnostics'
        assert 'request_complete status=200 duration=' in output
        print('WSGI smoke passed: readiness, index, audit denial, empty schema, sanitized access logs')
