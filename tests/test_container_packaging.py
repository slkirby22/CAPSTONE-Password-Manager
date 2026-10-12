"""Exercise imports using only Python files explicitly shipped by Docker COPY."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_container_python_copy_set_imports_application_in_isolation(tmp_path):
    copied = set()
    for line in (ROOT / 'Dockerfile').read_text().splitlines():
        if not line.startswith('COPY '):
            continue
        fields = shlex.split(line)
        if fields and fields[0] == 'COPY' and fields[-1] == '/app/':
            for name in fields[1:-1]:
                if name.endswith('.py'):
                    shutil.copy2(ROOT / name, tmp_path / Path(name).name)
                    copied.add(name)
    assert 'app.py' in copied
    env = os.environ.copy()
    env.pop('PYTHONPATH', None)
    result = subprocess.run([
        sys.executable, '-I', '-c',
        'import sys; sys.path.insert(0, sys.argv[1]); '
        'from app import app; '
        'assert app.config["SQLALCHEMY_DATABASE_URI"] == "sqlite:///:memory:"',
        str(tmp_path),
    ], cwd=tmp_path, env=env, text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr


def test_container_ships_offline_migration_without_startup_execution(tmp_path):
    dockerfile = (ROOT / 'Dockerfile').read_text()
    assert 'COPY scripts/init_synthetic_db.py scripts/migrate_account_identity.py /app/scripts/' in dockerfile
    assert 'migrate_account_identity' not in (ROOT / 'deployment/start.sh').read_text()
    shutil.copy2(ROOT / 'scripts/migrate_account_identity.py', tmp_path)
    result = subprocess.run([sys.executable, '-I', str(tmp_path / 'migrate_account_identity.py'), '--help'],
                            cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert '--synthetic-only' in result.stdout
