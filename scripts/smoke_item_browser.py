"""Disposable, public-fixture Chromium smoke. Requires separately installed Playwright.
Run with the application's Python environment; no production data or .env is used.
"""
import base64
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    with tempfile.TemporaryDirectory(prefix='item-browser-synthetic-') as directory:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        os.environ.update(
            APP_ENV='synthetic', SYNTHETIC_DATA_ONLY='true',
            DATABASE_URL=f'sqlite:///{directory}/synthetic.db',
            SECRET_KEY='public-browser-session-fixture-000000000',
            JWT_SECRET_KEY='public-browser-jwt-fixture-0000000000000',
            ENCRYPTION_KEY=base64.urlsafe_b64encode(b'0' * 32).decode(),
            TRUSTED_HOSTS='localhost,127.0.0.1', PYTHON_DOTENV_DISABLED='1',
        )
        os.environ.pop('RENDER', None)
        from app import app
        from models import db, Password, User, audit_log
        from functions import pwd_context
        from cryptography.fernet import Fernet
        with app.app_context():
            db.create_all()
            owner = User('BROWSEROWNER', pwd_context.hash('Public-login-fixture-123!'), 'employee')
            shared = User('BROWSERSHARED', pwd_context.hash('Public-login-fixture-123!'), 'employee')
            admin = User('BROWSERADMIN', pwd_context.hash('Public-login-fixture-123!'), 'admin')
            db.session.add_all([owner, shared, admin])
            db.session.flush()
            cipher = Fernet(app.config['ENCRYPTION_KEY'])
            first = Password('Duplicate service', 'first-login', cipher.encrypt(b'Public-item-one-123!'), 'first notes', owner.id, [shared])
            second = Password('Duplicate service', 'second-login', cipher.encrypt(b'Public-item-two-123!'), 'second notes', owner.id)
            from datetime import datetime
            db.session.add_all([
                audit_log(event_time=datetime(2025, 1, 1, 12), event_message='Synthetic audit first day', event_type='FIXTURE', user_id=None),
                audit_log(event_time=datetime(2025, 1, 2), event_message='Synthetic audit second day midnight', event_type='FIXTURE', user_id=None),
                audit_log(event_time=datetime(2025, 1, 2, 23, 59, 59, 999999), event_message='Synthetic audit second day late', event_type='FIXTURE', user_id=None),
                audit_log(event_time=datetime(2025, 1, 2, 12), event_message='Synthetic excluded message', event_type='OTHER', user_id=None),
            ])
            db.session.add_all([first, second])
            db.session.commit()
            fixture = {'first': first.item_id, 'second': second.item_id, 'ciphertext': first.password.decode(), 'shared_id': shared.id}
        env = dict(os.environ, BROWSER_SMOKE_BASE=f'http://localhost:{port}',
                   BROWSER_SMOKE_FIXTURE=json.dumps(fixture),
                   BROWSER_SMOKE_DB=f'{directory}/synthetic.db', BROWSER_SMOKE_PYTHON=sys.executable)
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen(
                [sys.executable, '-m', 'gunicorn', '--bind', f'127.0.0.1:{port}', '--workers', '1', '--threads', '1', 'app:app'],
                cwd=ROOT, env=env, stdout=log, stderr=log, start_new_session=True)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError('Gunicorn stopped before readiness')
                    try:
                        with urllib.request.urlopen(f'http://localhost:{port}/healthz', timeout=1) as response:
                            assert response.status == 200
                        break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError('Readiness timeout')
                subprocess.run(['node', str(ROOT / 'scripts/smoke_item_browser.js')], env=env, cwd=ROOT, check=True)
            except Exception:
                log.seek(0)
                sys.stderr.write(log.read().decode())
                raise
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)


if __name__ == '__main__':
    main()
