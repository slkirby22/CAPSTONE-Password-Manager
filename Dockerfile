FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements/runtime.txt /app/requirements/runtime.txt
RUN pip install --no-cache-dir -r requirements/runtime.txt \
    && useradd --uid 10001 --create-home appuser \
    && mkdir /data && chown appuser:appuser /data
COPY app.py api_functions.py functions.py models.py config.py authorization.py audit_events.py vault_access.py item_identity.py diagnostics.py account_input.py /app/
COPY templates /app/templates
COPY static /app/static
COPY deployment/start.sh /app/deployment/start.sh
COPY scripts/init_synthetic_db.py scripts/migrate_account_identity.py /app/scripts/
COPY scripts/upgrade_item_identity.py /app/scripts/
COPY scripts/bootstrap_synthetic_admin.py /app/scripts/
USER 10001:10001
EXPOSE 10000
CMD ["sh", "deployment/start.sh"]
