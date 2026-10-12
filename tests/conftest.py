"""All test app imports are isolated from .env and live vault configuration."""
import os
import base64

# Public deterministic fixtures, not deployment credentials.
os.environ.update({
    'APP_ENV': 'testing',
    'DATABASE_URL': 'sqlite:///:memory:',
    'SECRET_KEY': 'synthetic-test-session-secret-000000000',
    'JWT_SECRET_KEY': 'synthetic-test-jwt-secret-000000000000',
    'ENCRYPTION_KEY': base64.urlsafe_b64encode(b'0' * 32).decode(),
})
os.environ.pop('RENDER', None)
