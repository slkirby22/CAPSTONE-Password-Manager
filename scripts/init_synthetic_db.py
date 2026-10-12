"""Create empty disposable test tables. Never imports legacy SQL seeds."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import app
from models import db

if app.config['APP_ENV'] != 'synthetic':
    raise SystemExit('Empty schema initialization is restricted to synthetic mode')
with app.app_context():
    db.create_all()
