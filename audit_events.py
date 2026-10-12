"""Shared legacy audit writer for routes and authorization policies."""
from datetime import datetime

import pytz
from models import db, audit_log
from diagnostics import report_failure, rollback_safely

est = pytz.timezone('US/Eastern')


def stage_event(message, event_type, user_id=None):
    """Add an audit row to the caller's transaction without committing it.

    Errors propagate so the caller can roll back both its mutation and audit.
    This helper must never commit or swallow failures.
    """
    new_log = audit_log(
        event_time=datetime.now(est),
        user_id=user_id,
        event_message=message,
        event_type=event_type,
    )
    db.session.add(new_log)
    return new_log


def log_event(message, event_type, user_id=None):
    """Legacy best-effort writer; do not use for atomic audited mutations."""
    try:
        stage_event(message, event_type, user_id)
        db.session.commit()
    except Exception:
        rollback_safely()
        report_failure('audit_write_failed')
