"""Canonical per-incarnation identity and fail-closed SQLite schema validation."""
import re

ITEM_ID_PATTERN = re.compile(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\Z')
ITEM_ID_CHECK = """typeof(item_id) = 'text' AND length(item_id) = 32
    AND item_id NOT GLOB '*[^0-9a-f]*' AND substr(item_id, 13, 1) = '4'
    AND substr(item_id, 17, 1) IN ('8', '9', 'a', 'b')"""
INVALID_NEW = """NEW.item_id IS NULL OR typeof(NEW.item_id) != 'text'
    OR length(NEW.item_id) != 32 OR NEW.item_id GLOB '*[^0-9a-f]*'
    OR substr(NEW.item_id, 13, 1) != '4'
    OR substr(NEW.item_id, 17, 1) NOT IN ('8', '9', 'a', 'b')"""
ITEM_TRIGGERS = {
    'password_item_identity_insert': f"""CREATE TRIGGER password_item_identity_insert
        BEFORE INSERT ON password WHEN {INVALID_NEW}
        BEGIN SELECT RAISE(ABORT, 'Invalid item identity'); END""",
    'password_item_identity_update': f"""CREATE TRIGGER password_item_identity_update
        BEFORE UPDATE ON password WHEN {INVALID_NEW}
        BEGIN SELECT RAISE(ABORT, 'Invalid item identity'); END""",
    'password_item_identity_immutable': """CREATE TRIGGER password_item_identity_immutable
        BEFORE UPDATE OF item_id ON password WHEN NEW.item_id IS NOT OLD.item_id
        BEGIN SELECT RAISE(ABORT, 'Immutable item identity'); END""",
}


def is_item_id(value):
    return isinstance(value, str) and ITEM_ID_PATTERN.fullmatch(value) is not None


def _normalized(sql):
    return ' '.join(sql.split()).rstrip(';').lower()


def validate_item_schema(connection):
    """Require complete guards, unique/non-null schema and valid existing UUID4s.

    Accept sqlite3 or SQLAlchemy Connection. Read only: never repair a schema.
    SQLite is the only supported offline upgrade target.
    """
    if hasattr(connection, 'dialect'):
        if connection.dialect.name != 'sqlite':
            raise ValueError('Item identity schema verification supports SQLite only')
        execute = connection.exec_driver_sql
    else:
        execute = connection.execute
    columns = {row[1]: row for row in execute('PRAGMA table_info(password)')}
    if 'item_id' not in columns or not columns['item_id'][3]:
        raise ValueError('Missing non-null item identity schema')
    unique = any(row[2] and not row[4] and
                 [entry[2] for entry in execute('SELECT * FROM pragma_index_info(?)', (row[1],))] == ['item_id']
                 for row in execute('PRAGMA index_list(password)'))
    if not unique:
        raise ValueError('Missing item identity uniqueness constraint')
    triggers = dict(execute("SELECT name, sql FROM sqlite_master WHERE type='trigger' AND tbl_name='password'").fetchall())
    if any(_normalized(triggers.get(name, '')) != _normalized(sql)
           for name, sql in ITEM_TRIGGERS.items()):
        raise ValueError('Missing or altered item identity guards')
    if execute(f'SELECT 1 FROM password WHERE item_id IS NULL OR NOT ({ITEM_ID_CHECK}) LIMIT 1').fetchone():
        raise ValueError('Invalid existing item identities')
