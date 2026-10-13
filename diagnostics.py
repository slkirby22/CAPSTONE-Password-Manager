"""Bounded operational events: never pass exceptions or request data to logging."""
import logging
import re

from flask import current_app, has_request_context, request

from models import db

_LOG = logging.getLogger('password_manager.diagnostics')
_EVENTS = frozenset({
    'request_failed', 'rollback_failed', 'web_login_failed', 'audit_write_failed',
    'database_reset_failed',
})


def report_failure(event):
    # Unknown callers cannot turn this helper into a secret-bearing log sink.
    if event not in _EVENTS:
        event = 'request_failed'
    endpoint = 'none'
    method = 'none'
    if has_request_context():
        candidate = request.endpoint
        if (isinstance(candidate, str) and candidate in current_app.view_functions
                and re.fullmatch(r'[A-Za-z_.]{1,64}', candidate)):
            endpoint = candidate
        if request.method in {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'}:
            method = request.method
    _LOG.error('operation_failed event=%s endpoint=%s method=%s', event, endpoint, method)


def rollback_safely():
    try:
        db.session.rollback()
    except Exception:
        report_failure('rollback_failed')
