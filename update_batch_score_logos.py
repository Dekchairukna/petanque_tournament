"""Store score-sheet logos in a tournament batch without committing image files."""

import argparse
import os
import sqlite3

from db_compat import PostgresConnection


def update_logos(batch_id, left_path, extra_path, database_url=""):
    if database_url:
        db = PostgresConnection(database_url)
    else:
        db = sqlite3.connect(os.path.join(os.path.dirname(__file__), "tournament.db"))
    try:
        columns = {
            row["column_name"] if database_url else row[1]
            for row in (
                db.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema=current_schema() AND table_name='tournament_batches'"
                ).fetchall()
                if database_url
                else db.execute("PRAGMA table_info(tournament_batches)").fetchall()
            )
        }
        if "score_extra_logo" not in columns:
            db.execute("ALTER TABLE tournament_batches ADD COLUMN score_extra_logo BLOB")
        with open(left_path, "rb") as stream:
            left_logo = stream.read()
        with open(extra_path, "rb") as stream:
            extra_logo = stream.read()
        db.execute(
            "UPDATE tournament_batches SET left_logo = ?, score_extra_logo = ? WHERE id = ?",
            (left_logo, extra_logo, batch_id),
        )
        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-id", type=int, required=True)
    parser.add_argument("--left", required=True)
    parser.add_argument("--extra", required=True)
    args = parser.parse_args()
    update_logos(args.batch_id, args.left, args.extra, os.environ.get("DATABASE_URL", ""))
