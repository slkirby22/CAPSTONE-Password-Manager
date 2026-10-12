"""Shared legacy audit writer for routes and authorization policies."""
from datetime import datetime

import pytz
from models import db, audit_log

est = pytz.timezone('US/Eastern')


def log_event(message, event_type, user_id=None):
    try:
        new_log = audit_log(
            event_time = datetime.now(est),
            user_id = user_id,
            event_message = message,
            event_type = event_type
        )
        db.session.add(new_log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error logging event: {e}")
