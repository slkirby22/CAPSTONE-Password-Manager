"""Self-created fixtures only; the recovery command never accepts a target DB."""
from pathlib import Path
import os
import sqlite3
import subprocess
import sys

import pytest
from scripts.smoke_recovery import run_drill

ROOT = Path(__file__).resolve().parents[1]


def test_round_trip(tmp_path):
    restored = run_drill(tmp_path)
    with sqlite3.connect(restored) as connection:
        assert connection.execute('SELECT notes FROM password').fetchone() == ('synthetic notes',)
        assert connection.execute('SELECT count(*) FROM user').fetchone() == (2,)
        assert connection.execute('SELECT count(*) FROM token_blacklist').fetchone() == (1,)


def test_existing_directory_is_untouched(tmp_path):
    sentinel = tmp_path / 'source.db'
    sentinel.write_bytes(b'do not touch')
    with pytest.raises(RuntimeError, match='empty directory'):
        run_drill(tmp_path)
    assert sentinel.read_bytes() == b'do not touch'
    assert list(tmp_path.iterdir()) == [sentinel]


def test_cli_rejects_existing_target_even_optimized(tmp_path):
    sentinel = tmp_path / 'existing.db'
    sentinel.write_bytes(b'do not touch')
    result = subprocess.run([sys.executable, '-O', 'scripts/smoke_recovery.py', str(sentinel)],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0
    assert 'accepts no arguments' in result.stderr
    assert sentinel.read_bytes() == b'do not touch'


def test_full_drill_ignores_external_database_environment(tmp_path):
    sentinel = tmp_path / 'external.db'
    sentinel.write_bytes(b'do not touch')
    result = subprocess.run([sys.executable, '-O', 'scripts/smoke_recovery.py'], cwd=ROOT,
                            env=dict(os.environ, DATABASE_URL=f'sqlite:///{sentinel}',
                                     APP_ENV='production', ENCRYPTION_KEY='invalid'),
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'Synthetic recovery passed' in result.stdout
    assert sentinel.read_bytes() == b'do not touch'


def test_upgrade_payload_loss_is_detected(tmp_path, monkeypatch):
    from scripts import smoke_recovery
    original = smoke_recovery.migrate_accounts

    def lossy_upgrade(connection):
        changed = original(connection)
        connection.execute('DELETE FROM audit_log')
        connection.commit()
        return changed

    monkeypatch.setattr(smoke_recovery, 'migrate_accounts', lossy_upgrade)
    with pytest.raises(RuntimeError, match='existing fixture payload'):
        run_drill(tmp_path)
