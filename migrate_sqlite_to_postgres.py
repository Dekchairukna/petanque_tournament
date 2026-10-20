"""Copy the current SQLite database into an empty PostgreSQL database."""

import argparse
import os
import sqlite3

from db_compat import PostgresConnection
from app import init_db, table_columns, table_exists


TABLES = [
    "users",
    "tournament_batches",
    "import_drafts",
    "tournaments",
    "tournament_teams",
    "tournament_rounds",
    "round_slots",
    "round_scores",
    "eliminated_teams",
    "team_pool",
    "manual_group_rankings",
]


def migrate(sqlite_path, postgres_url):
    source = sqlite3.connect(sqlite_path)
    source.row_factory = sqlite3.Row
    target = PostgresConnection(postgres_url)
    try:
        init_db(target)
        for table in TABLES:
            source_exists = source.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
            if not source_exists or not table_exists(target, table):
                continue
            source_columns = [row[1] for row in source.execute(f"PRAGMA table_info({table})")]
            columns = [name for name in source_columns if name in table_columns(target, table)]
            if not columns:
                continue
            placeholders = ",".join("?" for _ in columns)
            column_sql = ",".join(columns)
            updates = ",".join(f"{name}=EXCLUDED.{name}" for name in columns if name != "id")
            conflict = f"DO UPDATE SET {updates}" if updates else "DO NOTHING"
            rows = source.execute(f"SELECT {column_sql} FROM {table} ORDER BY id").fetchall()
            for row in rows:
                values = tuple(row[name] for name in columns)
                target.execute(
                    f"INSERT INTO {table} ({column_sql}) VALUES ({placeholders}) ON CONFLICT (id) {conflict}",
                    values,
                )
            target.commit()
            if "id" in columns:
                target.execute(
                    "SELECT setval(pg_get_serial_sequence(?, 'id'), COALESCE((SELECT MAX(id) FROM "
                    + table
                    + "), 1), COALESCE((SELECT MAX(id) FROM "
                    + table
                    + "), 0) > 0)",
                    (table,),
                )
                target.commit()
            print(f"{table}: {len(rows)} rows")
    finally:
        source.close()
        target.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sqlite", default=os.path.join(os.path.dirname(__file__), "tournament.db"))
    parser.add_argument("--postgres-url", default=os.environ.get("DATABASE_URL"))
    args = parser.parse_args()
    if not args.postgres_url:
        raise SystemExit("DATABASE_URL or --postgres-url is required")
    migrate(args.sqlite, args.postgres_url)
