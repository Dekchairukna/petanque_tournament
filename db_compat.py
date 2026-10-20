import re
import sqlite3


MIGRATION_TABLES = [
    "users", "tournament_batches", "import_drafts", "tournaments",
    "tournament_teams", "tournament_rounds", "round_slots", "round_scores",
    "eliminated_teams", "team_pool", "manual_group_rankings",
]


class PostgresCursor:
    def __init__(self, cursor, lastrowid=None):
        self._cursor = cursor
        self.lastrowid = lastrowid

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    def __iter__(self):
        return iter(self._cursor)


class PostgresConnection:
    is_postgres = True

    def __init__(self, url):
        import psycopg2
        from psycopg2.extras import RealDictCursor

        self._conn = psycopg2.connect(url, cursor_factory=RealDictCursor)

    def execute(self, sql, params=()):
        is_ignore = bool(re.search(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", sql, flags=re.I))
        sql = re.sub(r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT", "BIGSERIAL PRIMARY KEY", sql, flags=re.I)
        sql = re.sub(r"\bBLOB\b", "BYTEA", sql, flags=re.I)
        sql = sql.replace("?", "%s")
        sql = re.sub(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT INTO", sql, flags=re.I)
        if is_ignore and "ON CONFLICT" not in sql.upper():
            sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
        cur = self._conn.cursor()
        cur.execute(sql, params)
        lastrowid = None
        if re.match(r"^\s*INSERT\s+INTO\b", sql, flags=re.I) and not is_ignore:
            probe = self._conn.cursor()
            try:
                probe.execute("SELECT LASTVAL() AS id")
                lastrowid = probe.fetchone()["id"]
            except Exception:
                self._conn.rollback()
                raise
            finally:
                probe.close()
        return PostgresCursor(cur, lastrowid)

    def executescript(self, script):
        script = re.sub(r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT", "BIGSERIAL PRIMARY KEY", script, flags=re.I)
        script = re.sub(r"\bBLOB\b", "BYTEA", script, flags=re.I)
        cur = self._conn.cursor()
        for statement in script.split(";"):
            if statement.strip():
                cur.execute(statement)
        cur.close()

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def connect_database(database_url, sqlite_path):
    if database_url:
        return PostgresConnection(database_url)
    db = sqlite3.connect(sqlite_path)
    db.row_factory = sqlite3.Row
    return db


def migrate_sqlite_data(sqlite_path, target):
    """Seed a new PostgreSQL database from the tracked SQLite snapshot once."""
    if not sqlite_path or not __import__("os").path.exists(sqlite_path):
        return
    source = sqlite3.connect(sqlite_path)
    source.row_factory = sqlite3.Row
    try:
        for table in MIGRATION_TABLES:
            exists = source.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
            if not exists:
                continue
            pg_columns = {
                row["column_name"] for row in target.execute(
                    "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=?",
                    (table,),
                ).fetchall()
            }
            columns = [row[1] for row in source.execute(f"PRAGMA table_info({table})") if row[1] in pg_columns]
            if not columns:
                continue
            column_sql = ",".join(columns)
            placeholders = ",".join("?" for _ in columns)
            updates = ",".join(f"{name}=EXCLUDED.{name}" for name in columns if name != "id")
            conflict = f"DO UPDATE SET {updates}" if updates else "DO NOTHING"
            for row in source.execute(f"SELECT {column_sql} FROM {table} ORDER BY id"):
                target.execute(
                    f"INSERT INTO {table} ({column_sql}) VALUES ({placeholders}) ON CONFLICT (id) {conflict}",
                    tuple(row[name] for name in columns),
                )
            target.commit()
            if "id" in columns:
                target.execute(
                    f"SELECT setval(pg_get_serial_sequence(?, 'id'), COALESCE((SELECT MAX(id) FROM {table}), 1), "
                    f"COALESCE((SELECT MAX(id) FROM {table}), 0) > 0)",
                    (table,),
                )
                target.commit()
    finally:
        source.close()
