"""Same-origin asset and actual response policy regressions."""
from hashlib import sha256
from html.parser import HTMLParser
import json
from pathlib import Path

from app import app

ROOT = Path(__file__).resolve().parents[1]


class TemplateAssets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        assert not any(name.lower().startswith('on') for name in values), 'Inline event handler'
        assert 'style' not in values, 'Inline style attribute'
        if tag == 'script':
            assert 'src' in values, 'Inline script'
            self.in_script = True
        for attr in ('src', 'href', 'action'):
            value = values.get(attr, '').strip()
            assert not value.lower().startswith(('http:', 'https:', '//', 'javascript:')), 'External or executable resource'

    def handle_endtag(self, tag):
        if tag == 'script':
            self.in_script = False

    def handle_data(self, data):
        if self.in_script:
            assert not data.strip(), 'Script body must be empty'


def test_templates_use_no_external_or_inline_executable_content():
    for path in (ROOT / 'templates').glob('*.html'):
        TemplateAssets().feed(path.read_text())


def test_real_responses_enforce_csp():
    client = app.test_client()
    for path in ('/', '/login', '/missing-route', '/static/js/functions.js'):
        response = client.get(path)
        policy = dict((chunk.strip().split(' ', 1) + [''])[:2]
                      for chunk in response.headers['Content-Security-Policy'].split(';') if chunk.strip())
        assert policy['script-src'] == "'self'"
        assert policy['script-src-attr'] == "'none'"
        assert policy['style-src'] == "'self'"
        assert policy['style-src-attr'] == "'none'"
        assert policy['connect-src'] == "'self'"
        assert policy['form-action'] == "'self'"
        assert policy['object-src'] == policy['base-uri'] == policy['frame-ancestors'] == "'none'"
        assert 'unsafe-inline' not in response.headers['Content-Security-Policy']
        assert 'unsafe-eval' not in response.headers['Content-Security-Policy']


def test_existing_vendor_assets_match_reviewed_manifest():
    manifest = json.loads((ROOT / 'static/vendor/bootstrap-5.3.5/asset-manifest.json').read_text())
    for name, expected in manifest['sha256'].items():
        assert sha256((ROOT / 'static/vendor/bootstrap-5.3.5' / name).read_bytes()).hexdigest() == expected


def test_real_vendor_urls_serve_reviewed_bytes_not_extension_assets():
    from models import db
    with app.app_context():
        db.create_all()
        try:
            for name in ('js/bootstrap.min.js', 'css/bootstrap.min.css'):
                response = app.test_client().get('/static/vendor/bootstrap-5.3.5/' + name)
                assert response.status_code == 200
                assert response.data == (ROOT / 'static/vendor/bootstrap-5.3.5' / name).read_bytes()
                assert b'5.3.5' in response.data[:250]
        finally:
            db.session.remove()
            db.drop_all()
