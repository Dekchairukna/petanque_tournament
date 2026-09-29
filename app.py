import json
import math
import os
import random
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, flash, g, redirect, render_template, request, send_file, session, url_for

import bulk_events
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "tournament.db"))

app = Flask(__name__)
app.secret_key = "change-this-secret-key"
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')


# ------------------------- database -------------------------
def table_exists(db, table_name):
    row = db.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def ensure_runtime_schema(db):
    if not table_exists(db, "manual_group_rankings"):
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS manual_group_rankings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                round_id INTEGER NOT NULL,
                group_no INTEGER NOT NULL,
                winner_slot_no INTEGER,
                second_slot_no INTEGER,
                updated_at TEXT NOT NULL,
                UNIQUE(round_id, group_no),
                FOREIGN KEY(round_id) REFERENCES tournament_rounds(id)
            )
            """
        )
        db.commit()

    # เพิ่มคอลัมน์คลังทีมตกรอบแบบย้อนหลังได้
    # source_tournament_id = อีเว้นต้นทางจริง, source_round_no = ตกรอบที่เท่าไหร่
    if table_exists(db, "team_pool"):
        cols = {row[1] for row in db.execute("PRAGMA table_info(team_pool)").fetchall()}
        changed = False
        if "source_tournament_id" not in cols:
            db.execute("ALTER TABLE team_pool ADD COLUMN source_tournament_id INTEGER")
            changed = True
        if "source_round_no" not in cols:
            db.execute("ALTER TABLE team_pool ADD COLUMN source_round_no INTEGER")
            changed = True
        if "source_group_no" not in cols:
            db.execute("ALTER TABLE team_pool ADD COLUMN source_group_no INTEGER")
            changed = True

        # ข้อมูลเดิมให้ถือว่ามาจากทัวร์นาเมนต์ของตัวเอง และพยายามอ่านเลขรอบ/สายจาก source_text
        rows = db.execute(
            """
            SELECT id, tournament_id, source_text, source_tournament_id, source_round_no, source_group_no
            FROM team_pool
            WHERE source_tournament_id IS NULL OR source_round_no IS NULL OR source_group_no IS NULL
            """
        ).fetchall()
        for row in rows:
            text = row["source_text"] or ""
            round_match = re.search(r"รอบ\s*(\d+)", text)
            group_match = re.search(r"สาย\s*(\d+)", text)
            source_round_no = row["source_round_no"]
            source_group_no = row["source_group_no"]
            if source_round_no is None and round_match:
                source_round_no = int(round_match.group(1))
            if source_group_no is None and group_match:
                source_group_no = int(group_match.group(1))
            db.execute(
                """
                UPDATE team_pool
                SET source_tournament_id = COALESCE(source_tournament_id, ?),
                    source_round_no = ?,
                    source_group_no = ?
                WHERE id = ?
                """,
                (row["tournament_id"], source_round_no, source_group_no, row["id"]),
            )
            changed = True
        if changed:
            db.commit()


    ensure_bulk_schema(db)


def ensure_bulk_schema(db):
    """ตาราง/คอลัมน์สำหรับระบบนำเข้าอีเวนต์จาก Excel (สร้างเพิ่มแบบไม่กระทบข้อมูลเดิม)"""
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS tournament_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            subtitle TEXT,
            owner_id INTEGER NOT NULL,
            left_logo BLOB,
            right_logo BLOB,
            use_default_right_logo INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS import_drafts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            filename TEXT,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    changed = False
    if table_exists(db, "tournaments"):
        cols = {row[1] for row in db.execute("PRAGMA table_info(tournaments)").fetchall()}
        for col, ddl in (
            ("batch_id", "INTEGER"),
            ("event_label", "TEXT"),
            ("event_category", "TEXT"),
            ("event_gender", "TEXT"),
            ("event_age", "INTEGER"),
            ("sort_order", "INTEGER"),
        ):
            if col not in cols:
                db.execute(f"ALTER TABLE tournaments ADD COLUMN {col} {ddl}")
                changed = True
    if table_exists(db, "tournament_teams"):
        cols = {row[1] for row in db.execute("PRAGMA table_info(tournament_teams)").fetchall()}
        for col in ("full_name", "district", "province"):
            if col not in cols:
                db.execute(f"ALTER TABLE tournament_teams ADD COLUMN {col} TEXT")
                changed = True
    db.commit()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        ensure_runtime_schema(g.db)
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def now_dt():
    return datetime.now()


def parse_expiry(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return None


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('super_admin', 'admin')),
            created_by INTEGER,
            is_active INTEGER NOT NULL DEFAULT 1,
            create_quota INTEGER NOT NULL DEFAULT 0,
            created_count INTEGER NOT NULL DEFAULT 0,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS tournaments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            team_count INTEGER NOT NULL,
            group_count INTEGER NOT NULL,
            group_sizes_json TEXT NOT NULL,
            avoid_same INTEGER NOT NULL DEFAULT 1,
            competition_type TEXT NOT NULL DEFAULT 'double_knockout',
            qualify_per_group INTEGER NOT NULL DEFAULT 2,
            status TEXT NOT NULL DEFAULT 'draft',
            created_at TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS tournament_teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tournament_id INTEGER NOT NULL,
            display_name TEXT NOT NULL,
            base_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(tournament_id) REFERENCES tournaments(id)
        );

        CREATE TABLE IF NOT EXISTS tournament_rounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tournament_id INTEGER NOT NULL,
            round_no INTEGER NOT NULL,
            round_name TEXT NOT NULL,
            round_type TEXT NOT NULL,
            group_count INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            UNIQUE(tournament_id, round_no),
            FOREIGN KEY(tournament_id) REFERENCES tournaments(id)
        );

        CREATE TABLE IF NOT EXISTS round_slots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id INTEGER NOT NULL,
            group_no INTEGER NOT NULL,
            slot_no INTEGER NOT NULL,
            display_name TEXT NOT NULL,
            source_type TEXT NOT NULL DEFAULT 'team',
            source_group_no INTEGER,
            source_rank INTEGER,
            team_name TEXT,
            court_name TEXT,
            is_bye INTEGER NOT NULL DEFAULT 0,
            is_resolved INTEGER NOT NULL DEFAULT 0,
            UNIQUE(round_id, group_no, slot_no),
            FOREIGN KEY(round_id) REFERENCES tournament_rounds(id)
        );

        CREATE TABLE IF NOT EXISTS round_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id INTEGER NOT NULL,
            group_no INTEGER NOT NULL,
            slot_no INTEGER NOT NULL,
            stage_no INTEGER NOT NULL,
            score INTEGER,
            updated_at TEXT NOT NULL,
            UNIQUE(round_id, group_no, slot_no, stage_no),
            FOREIGN KEY(round_id) REFERENCES tournament_rounds(id)
        );

        CREATE TABLE IF NOT EXISTS eliminated_teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tournament_id INTEGER NOT NULL,
            team_name TEXT NOT NULL,
            source_round_no INTEGER,
            source_group_no INTEGER,
            source_rank INTEGER,
            status TEXT NOT NULL DEFAULT 'pool',
            created_at TEXT NOT NULL,
            UNIQUE(tournament_id, team_name, source_round_no, source_group_no),
            FOREIGN KEY(tournament_id) REFERENCES tournaments(id)
        );

        CREATE TABLE IF NOT EXISTS team_pool (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tournament_id INTEGER NOT NULL,
            team_name TEXT NOT NULL,
            source_text TEXT,
            source_tournament_id INTEGER,
            source_round_no INTEGER,
            source_group_no INTEGER,
            status TEXT NOT NULL DEFAULT 'pool',
            created_at TEXT NOT NULL,
            UNIQUE(tournament_id, team_name),
            FOREIGN KEY(tournament_id) REFERENCES tournaments(id)
        );

        CREATE TABLE IF NOT EXISTS manual_group_rankings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id INTEGER NOT NULL,
            group_no INTEGER NOT NULL,
            winner_slot_no INTEGER,
            second_slot_no INTEGER,
            updated_at TEXT NOT NULL,
            UNIQUE(round_id, group_no),
            FOREIGN KEY(round_id) REFERENCES tournament_rounds(id)
        );
        """
    )
    db.commit()
    ensure_bulk_schema(db)
    seed_super_admin(db)


def seed_super_admin(db):
    row = db.execute("SELECT id FROM users WHERE role = 'super_admin' LIMIT 1").fetchone()
    if row:
        return
    now = now_str()
    db.execute(
        """
        INSERT INTO users
        (username, password_hash, role, created_by, is_active, create_quota, created_count, expires_at, created_at, updated_at)
        VALUES (?, ?, 'super_admin', NULL, 1, 999999, 0, NULL, ?, ?)
        """,
        ("superadmin", generate_password_hash("admin1234"), now, now),
    )
    db.commit()


# ------------------------- auth helpers -------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("กรุณาเข้าสู่ระบบก่อน", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                flash("กรุณาเข้าสู่ระบบก่อน", "error")
                return redirect(url_for("login"))
            if user["role"] not in roles:
                flash("คุณไม่มีสิทธิ์ใช้งานหน้านี้", "error")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


def check_login_access(user):
    if not user["is_active"]:
        return False, "บัญชีนี้ถูกปิดการใช้งานชั่วคราว"
    if user["expires_at"]:
        expiry = parse_expiry(user["expires_at"])
        if expiry and now_dt().date() > expiry.date():
            return False, "บัญชีนี้หมดอายุแล้ว"
    return True, None


def can_create_tournament(user):
    ok, message = check_login_access(user)
    if not ok:
        return ok, message
    if user["role"] != "super_admin" and user["create_quota"] <= 0:
        return False, "สิทธิ์สร้างทัวร์นาเมนต์หมดแล้ว"
    return True, None


def consume_quota(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or user["role"] == "super_admin":
        return
    db.execute(
        """
        UPDATE users
        SET create_quota = CASE WHEN create_quota > 0 THEN create_quota - 1 ELSE 0 END,
            created_count = created_count + 1,
            updated_at = ?
        WHERE id = ?
        """,
        (now_str(), user_id),
    )
    db.commit()


# ------------------------- general helpers -------------------------
THAI_DIGITS_TRANS = str.maketrans("๐๑๒๓๔๕๖๗๘๙", "0123456789")


def get_base_name(team_name):
    raw = (team_name or "").strip().translate(THAI_DIGITS_TRANS)
    cleaned = re.sub(r"\s+", " ", raw)
    cleaned = re.sub(r"[\(\[\{]?\s*[0-9]+\s*[\)\]\}]?$", "", cleaned)
    cleaned = re.sub(r"(?:\s|[-–_])+(?:[a-zA-Z]|[0-9]+)$", "", cleaned)
    cleaned = re.sub(r"[\-–_]+$", "", cleaned).strip(" -_–")
    normalized = re.sub(r"\s+", " ", cleaned).strip().lower()
    return normalized or raw.lower()


def competition_type_label(value):
    labels = {
        "double_knockout": "Double knockout",
        "double_elimination": "Double knockout",
        "knockout": "Knockout",
    }
    return labels.get(value, value or "-")


def can_manage_tournament(user, tournament):
    if not user or not tournament:
        return False
    return user["role"] == "super_admin" or tournament["owner_id"] == user["id"]


def get_tournament_for_user(tournament_id, user):
    db = get_db()
    if user["role"] == "super_admin":
        return db.execute(
            """
            SELECT t.*, u.username AS owner_name
            FROM tournaments t JOIN users u ON u.id = t.owner_id
            WHERE t.id = ?
            """,
            (tournament_id,),
        ).fetchone()
    return db.execute(
        """
        SELECT t.*, u.username AS owner_name
        FROM tournaments t JOIN users u ON u.id = t.owner_id
        WHERE t.id = ? AND t.owner_id = ?
        """,
        (tournament_id, user["id"]),
    ).fetchone()


def valid_group_count(team_count, group_count):
    return group_count > 0 and (3 * group_count) <= team_count <= (4 * group_count)


def calculate_group_count(team_count):
    for groups in range(math.ceil(team_count / 4), math.floor(team_count / 3) + 1):
        if valid_group_count(team_count, groups):
            return groups
    return None


def calculate_group_sizes(team_count, manual_group_count=None):
    if manual_group_count:
        if not valid_group_count(team_count, manual_group_count):
            raise ValueError("จำนวนสายที่กำหนดทำให้บางสายมีทีมน้อยกว่า 3 หรือมากกว่า 4")
        group_count = manual_group_count
    else:
        group_count = calculate_group_count(team_count)
        if group_count is None:
            raise ValueError("จำนวนทีมนี้ไม่สามารถจัดสายแบบ 3–4 ทีมได้")
    sizes = [3] * group_count
    remaining = team_count - (3 * group_count)
    idx = 0
    while remaining > 0:
        if sizes[idx] < 4:
            sizes[idx] += 1
            remaining -= 1
        idx += 1
    return sizes


def reorder_groups_to_push_byes_last(groups):
    indexed_groups = list(enumerate(groups))
    indexed_groups.sort(
        key=lambda item: (
            sum(1 for name in item[1] if str(name).strip().upper() == "X"),
            item[0],
        )
    )
    return [group for _, group in indexed_groups]


def _first_match_pairs_for_capacity(capacity):
    if capacity >= 4:
        return ((0, 1), (2, 3))
    if capacity == 3:
        return ((0, 1),)
    if capacity == 2:
        return ((0, 1),)
    return tuple()


# วางลำดับทีมในสายเพื่อเลี่ยงชนกันตั้งแต่แมตช์แรกให้มากที่สุด
# โดยเฉพาะกรณีที่จำนวนสายไม่พอและทีมชื่อฐานเดียวกันต้องอยู่สายเดียวกัน
# จะพยายามแยกให้อยู่คนละคู่ก่อน

def arrange_group_for_first_round(group, capacity, key_func=None, secondary_key_func=None):
    key_func = key_func or get_base_name
    secondary_key_func = secondary_key_func or key_func
    n = len(group)
    if n <= 1:
        return list(group)

    preferred_orders = []
    if n >= 4:
        preferred_orders = [
            (0, 2, 1, 3),
            (0, 2, 3, 1),
            (0, 1, 2, 3),
            (0, 3, 1, 2),
            (0, 3, 2, 1),
            (0, 1, 3, 2),
        ]
    elif n == 3:
        preferred_orders = [
            (0, 2, 1),
            (1, 2, 0),
            (2, 0, 1),
            (0, 1, 2),
            (1, 0, 2),
            (2, 1, 0),
        ]
    else:
        preferred_orders = [tuple(range(n))]

    bases = [key_func(name) for name in group]
    secondary_bases = [secondary_key_func(name) for name in group]
    pair_indexes = _first_match_pairs_for_capacity(min(capacity, n))

    def score(order):
        ordered_bases = [bases[i] for i in order]
        ordered_secondary = [secondary_bases[i] for i in order]
        same_pair_penalty = 0
        secondary_pair_penalty = 0
        same_group_penalty = len(ordered_bases) - len(set(ordered_bases))
        secondary_group_penalty = len(ordered_secondary) - len(set(ordered_secondary))
        for a, b in pair_indexes:
            if a < len(ordered_bases) and b < len(ordered_bases) and ordered_bases[a] == ordered_bases[b]:
                same_pair_penalty += 1
            if a < len(ordered_secondary) and b < len(ordered_secondary) and ordered_secondary[a] == ordered_secondary[b]:
                secondary_pair_penalty += 1
        return (same_pair_penalty, secondary_pair_penalty, same_group_penalty, secondary_group_penalty)

    best_order = min(preferred_orders, key=score)
    return [group[i] for i in best_order]


def smart_draw_groups(team_names, group_sizes, avoid_same=True, key_func=None, secondary_key_func=None, trials=80):
    """key_func: ฟังก์ชันคืนค่า 'กลุ่ม' ของทีมที่ไม่อยากให้อยู่สายเดียวกัน (ค่าเริ่มต้น = ชื่อสังกัด)"""
    key_func = key_func or get_base_name
    secondary_key_func = secondary_key_func or key_func
    teams = [t.strip() for t in team_names if t.strip()]

    if not avoid_same:
        random.shuffle(teams)
        groups = [[] for _ in group_sizes]
        capacities = list(group_sizes)
        for team in teams:
            for gi in range(len(groups)):
                if len(groups[gi]) < capacities[gi]:
                    groups[gi].append(team)
                    break
        return [arrange_group_for_first_round(group, capacity) for group, capacity in zip(groups, capacities)]

    team_objects = [{"name": team, "base": key_func(team), "secondary": secondary_key_func(team)} for team in teams]
    base_counts = defaultdict(int)
    for item in team_objects:
        base_counts[item["base"]] += 1

    capacities = list(group_sizes)

    def duplicate_pairs(values):
        counts = Counter(v for v in values if v)
        return sum(n * (n - 1) // 2 for n in counts.values())

    def draw_once():
        ordered = sorted(team_objects, key=lambda item: (base_counts[item["base"]], random.random()), reverse=True)
        groups = [[] for _ in group_sizes]
        for item in ordered:
            available = [gi for gi in range(len(groups)) if len(groups[gi]) < capacities[gi]]
            if not available:
                raise ValueError("ไม่สามารถจัดสายได้ กรุณาลองใหม่")

            def rank_group(gi):
                primary = [member["base"] for member in groups[gi]]
                secondary = [member["secondary"] for member in groups[gi]]
                return (
                    primary.count(item["base"]),
                    secondary.count(item["secondary"]),
                    len(groups[gi]),
                    capacities[gi],
                    random.random(),
                )

            groups[min(available, key=rank_group)].append(item)
        return groups

    def draw_score(groups):
        primary_pairs = sum(duplicate_pairs([m["base"] for m in group]) for group in groups)
        secondary_pairs = sum(duplicate_pairs([m["secondary"] for m in group]) for group in groups)
        primary_groups = sum(len(g) != len({m["base"] for m in g}) for g in groups)
        secondary_groups = sum(len(g) != len({m["secondary"] for m in g}) for g in groups)
        return (primary_pairs, primary_groups, secondary_pairs, secondary_groups)

    best_groups, best_score = None, None
    for _ in range(max(1, trials)):
        candidate = draw_once()
        score = draw_score(candidate)
        if best_score is None or score < best_score:
            best_groups, best_score = candidate, score
            if score == (0, 0, 0, 0):
                break

    arranged_groups = []
    for group, capacity in zip(best_groups, capacities):
        arranged_groups.append(arrange_group_for_first_round(
            [item["name"] for item in group], capacity,
            key_func=key_func, secondary_key_func=secondary_key_func,
        ))
    return arranged_groups


# ------------------------- round helpers -------------------------
def group_label(group_no):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    idx = group_no - 1
    return alphabet[idx] if 0 <= idx < len(alphabet) else f"G{group_no}"


def placeholder_name(rank_no, group_no):
    return f"{rank_no}{group_label(group_no)}"


def get_next_round_no(tournament_id):
    db = get_db()
    row = db.execute(
        "SELECT COALESCE(MAX(round_no), 0) AS max_no FROM tournament_rounds WHERE tournament_id = ?",
        (tournament_id,),
    ).fetchone()
    return (row["max_no"] or 0) + 1


def create_round(tournament_id, round_no, round_name, round_type, grouped_names):
    db = get_db()
    cur = db.execute(
        """
        INSERT INTO tournament_rounds
        (tournament_id, round_no, round_name, round_type, group_count, status, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', ?)
        """,
        (tournament_id, round_no, round_name, round_type, len(grouped_names), now_str()),
    )
    round_id = cur.lastrowid
    fill_value = 4 if round_type == "double_knockout" else 2

    for group_no, names in enumerate(grouped_names, start=1):
        rows = list(names)
        while len(rows) < fill_value:
            rows.append("X")
        for slot_no, name in enumerate(rows, start=1):
            is_bye = 1 if name == "X" else 0
            source_type = "bye" if is_bye else "team"
            db.execute(
                """
                INSERT INTO round_slots
                (round_id, group_no, slot_no, display_name, source_type, source_group_no, source_rank, team_name, court_name, is_bye, is_resolved)
                VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, NULL, ?, ?)
                """,
                (round_id, group_no, slot_no, name, source_type, None if is_bye else name, is_bye, 1),
            )
    return round_id


def upsert_round_score(round_id, group_no, slot_no, stage_no, score):
    db = get_db()
    db.execute(
        """
        INSERT INTO round_scores (round_id, group_no, slot_no, stage_no, score, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(round_id, group_no, slot_no, stage_no)
        DO UPDATE SET score = excluded.score, updated_at = excluded.updated_at
        """,
        (round_id, group_no, slot_no, stage_no, score, now_str()),
    )


def build_round_score_map(rows):
    score_map = {}
    for row in rows:
        score_map[(row["group_no"], row["slot_no"], row["stage_no"])] = row["score"]
    return score_map


def decide_pair(a, b, stage_no, score_map):
    if a is None or b is None:
        return None
    if a["is_bye"] and not b["is_bye"]:
        return {"winner": b, "loser": a, "done": True}
    if b["is_bye"] and not a["is_bye"]:
        return {"winner": a, "loser": b, "done": True}

    sa = score_map.get((a["group_no"], a["slot_no"], stage_no))
    sb = score_map.get((b["group_no"], b["slot_no"], stage_no))

    if sa is None and sb is None:
        return None

    sa = 0 if sa is None else int(sa)
    sb = 0 if sb is None else int(sb)

    if sa == sb:
        return None

    return {
        "winner": a if sa > sb else b,
        "loser": b if sa > sb else a,
        "done": True,
    }


def apply_bye_auto_scores(round_type, slots, score_map):
    slots_by_no = {slot["slot_no"]: slot for slot in slots}

    def put_pair_bye(a, b, stage_no):
        if not a or not b:
            return

        if a["is_bye"] and not b["is_bye"]:
            score_map[(b["group_no"], b["slot_no"], stage_no)] = 1
            score_map[(a["group_no"], a["slot_no"], stage_no)] = 0
        elif b["is_bye"] and not a["is_bye"]:
            score_map[(a["group_no"], a["slot_no"], stage_no)] = 1
            score_map[(b["group_no"], b["slot_no"], stage_no)] = 0

    if round_type == "knockout":
        put_pair_bye(slots_by_no.get(1), slots_by_no.get(2), 1)
        return score_map

    put_pair_bye(slots_by_no.get(1), slots_by_no.get(2), 1)
    put_pair_bye(slots_by_no.get(3), slots_by_no.get(4), 1)

    qf1 = decide_pair(slots_by_no.get(1), slots_by_no.get(2), 1, score_map)
    qf2 = decide_pair(slots_by_no.get(3), slots_by_no.get(4), 1, score_map)

    if qf1 and qf2:
        put_pair_bye(qf1["winner"], qf2["winner"], 2)
        put_pair_bye(qf1["loser"], qf2["loser"], 2)

    wf = decide_pair(qf1["winner"], qf2["winner"], 2, score_map) if qf1 and qf2 else None
    lf = decide_pair(qf1["loser"], qf2["loser"], 2, score_map) if qf1 and qf2 else None

    if wf and lf:
        put_pair_bye(wf["loser"], lf["winner"], 3)

    return score_map


def build_manual_result(round_type, slots, manual_override=None):
    if not manual_override:
        return None

    slots_by_no = {slot["slot_no"]: slot for slot in slots}

    def valid_pick(slot_no):
        slot = slots_by_no.get(slot_no)
        if not slot or slot["is_bye"]:
            return None
        return slot

    winner = valid_pick(manual_override.get("winner_slot_no"))
    second = valid_pick(manual_override.get("second_slot_no")) if round_type == "double_knockout" else None

    if round_type == "knockout":
        if not winner:
            return None
        eliminated = [slot for slot in slots if not slot["is_bye"] and slot["slot_no"] != winner["slot_no"]]
        return {
            "winner": winner,
            "second": None,
            "qualified": [winner],
            "eliminated": eliminated,
            "complete": True,
            "manual_override": True,
        }

    if not winner or not second or winner["slot_no"] == second["slot_no"]:
        return None

    qualified_slots = {winner["slot_no"], second["slot_no"]}
    eliminated = [slot for slot in slots if not slot["is_bye"] and slot["slot_no"] not in qualified_slots]
    return {
        "winner": winner,
        "second": second,
        "qualified": [winner, second],
        "eliminated": eliminated,
        "complete": True,
        "manual_override": True,
    }


def compute_group_results(round_type, slots, score_map, manual_override=None):
    manual_result = build_manual_result(round_type, slots, manual_override)
    if manual_result:
        return manual_result

    slots_by_no = {slot["slot_no"]: slot for slot in slots}
    score_map = apply_bye_auto_scores(round_type, slots, dict(score_map))

    if round_type == "knockout":
        res = decide_pair(slots_by_no.get(1), slots_by_no.get(2), 1, score_map)
        winner = res["winner"] if res else None
        loser = res["loser"] if res else None
        return {
            "winner": winner,
            "second": None,
            "qualified": [winner] if winner and not winner["is_bye"] else [],
            "eliminated": [loser] if loser and not loser["is_bye"] else [],
            "complete": winner is not None,
            "manual_override": False,
        }

    qf1 = decide_pair(slots_by_no.get(1), slots_by_no.get(2), 1, score_map)
    qf2 = decide_pair(slots_by_no.get(3), slots_by_no.get(4), 1, score_map)

    wf = decide_pair(qf1["winner"], qf2["winner"], 2, score_map) if qf1 and qf2 else None
    lf = decide_pair(qf1["loser"], qf2["loser"], 2, score_map) if qf1 and qf2 else None

    top1 = wf["winner"] if wf else None
    top2 = None
    eliminated = []

    dec = decide_pair(wf["loser"], lf["winner"], 3, score_map) if wf and lf else None

    if dec:
        top2 = dec["winner"]
        if lf and lf["loser"] and not lf["loser"]["is_bye"]:
            eliminated.append(lf["loser"])
        if dec["loser"] and not dec["loser"]["is_bye"]:
            eliminated.append(dec["loser"])

    qualified = []
    if top1 and not top1["is_bye"]:
        qualified.append(top1)
    if top2 and not top2["is_bye"]:
        qualified.append(top2)

    return {
        "winner": top1,
        "second": top2,
        "qualified": qualified,
        "eliminated": eliminated,
        "complete": bool(top1 and top2),
        "manual_override": False,
    }


def build_stage_locks(round_type, slots, score_map):
    score_map = apply_bye_auto_scores(round_type, slots, dict(score_map))

    states = {}
    for slot in slots:
        states[slot["slot_no"]] = {
            1: {"locked": False, "color": ""},
            2: {"locked": False, "color": ""},
            3: {"locked": False, "color": ""},
        }

    slots_by_no = {slot["slot_no"]: slot for slot in slots}

    if round_type == "knockout":
        res = decide_pair(slots_by_no.get(1), slots_by_no.get(2), 1, score_map)
        if res:
            w = res["winner"]["slot_no"]
            l = res["loser"]["slot_no"]
            states[w][1] = {"locked": True, "color": "win"}
            states[l][1] = {"locked": True, "color": "loss"}
        return states

    qf1 = decide_pair(slots_by_no.get(1), slots_by_no.get(2), 1, score_map)
    qf2 = decide_pair(slots_by_no.get(3), slots_by_no.get(4), 1, score_map)

    if qf1:
        states[qf1["winner"]["slot_no"]][1] = {"locked": True, "color": "win"}
        states[qf1["loser"]["slot_no"]][1] = {"locked": True, "color": "loss"}
    if qf2:
        states[qf2["winner"]["slot_no"]][1] = {"locked": True, "color": "win"}
        states[qf2["loser"]["slot_no"]][1] = {"locked": True, "color": "loss"}

    wf = decide_pair(qf1["winner"], qf2["winner"], 2, score_map) if qf1 and qf2 else None
    lf = decide_pair(qf1["loser"], qf2["loser"], 2, score_map) if qf1 and qf2 else None

    if wf:
        states[wf["winner"]["slot_no"]][2] = {"locked": True, "color": "win"}
        states[wf["loser"]["slot_no"]][2] = {"locked": True, "color": "loss"}

    if lf:
        states[lf["winner"]["slot_no"]][2] = {"locked": True, "color": "win"}
        states[lf["loser"]["slot_no"]][2] = {"locked": True, "color": "loss"}

    dec = decide_pair(wf["loser"], lf["winner"], 3, score_map) if wf and lf else None
    if dec:
        states[dec["winner"]["slot_no"]][3] = {"locked": True, "color": "win"}
        states[dec["loser"]["slot_no"]][3] = {"locked": True, "color": "loss"}

    return states


def stage_is_editable(round_type, slots, stage_no, slot_no, score_map):
    if stage_no == 1:
        if round_type == "knockout":
            return slot_no in (1, 2)
        return slot_no in (1, 2, 3, 4)

    score_map = apply_bye_auto_scores(round_type, slots, dict(score_map))
    slots_by_no = {slot["slot_no"]: slot for slot in slots}

    qf1 = decide_pair(slots_by_no.get(1), slots_by_no.get(2), 1, score_map)
    qf2 = decide_pair(slots_by_no.get(3), slots_by_no.get(4), 1, score_map)

    if round_type == "knockout":
        return False

    if stage_no == 2:
        if not (qf1 and qf2):
            return False
        stage2_slots = {
            qf1["winner"]["slot_no"], qf2["winner"]["slot_no"],
            qf1["loser"]["slot_no"], qf2["loser"]["slot_no"],
        }
        return slot_no in stage2_slots

    if stage_no == 3:
        if not (qf1 and qf2):
            return False
        wf = decide_pair(qf1["winner"], qf2["winner"], 2, score_map)
        lf = decide_pair(qf1["loser"], qf2["loser"], 2, score_map)
        if not (wf and lf):
            return False
        stage3_slots = {wf["loser"]["slot_no"], lf["winner"]["slot_no"]}
        return slot_no in stage3_slots

    return False




def parse_skip_courts(skip_text):
    skip_set = set()
    for part in (skip_text or "").split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            try:
                start = int(a.strip())
                end = int(b.strip())
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            for n in range(start, end + 1):
                skip_set.add(n)
        else:
            try:
                skip_set.add(int(part))
            except ValueError:
                continue
    return skip_set


def renumber_round_courts(round_id, start_court=1, skip_courts=None):
    db = get_db()
    slots = db.execute(
        "SELECT * FROM round_slots WHERE round_id = ? ORDER BY group_no, slot_no",
        (round_id,),
    ).fetchall()

    skip_courts = set(skip_courts or [])
    next_court = max(1, int(start_court or 1))
    pending = []
    current_group = None

    def allocate_court():
        nonlocal next_court
        while next_court in skip_courts:
            next_court += 1
        court_value = str(next_court)
        next_court += 1
        return court_value

    for slot in slots:
        if current_group != slot["group_no"]:
            pending = []
            current_group = slot["group_no"]

        pending.append(slot)
        if len(pending) == 2:
            has_bye = any(row["is_bye"] for row in pending)
            court_name = None if has_bye else allocate_court()
            for row in pending:
                db.execute(
                    "UPDATE round_slots SET court_name = ? WHERE id = ?",
                    (court_name, row["id"]),
                )
            pending = []

    if pending:
        has_bye = any(row["is_bye"] for row in pending)
        court_name = None if has_bye else allocate_court()
        for row in pending:
            db.execute(
                "UPDATE round_slots SET court_name = ? WHERE id = ?",
                (court_name, row["id"]),
            )


def add_team_into_bye_slot(round_id, slot_id, team_name):
    db = get_db()
    slot = db.execute(
        "SELECT * FROM round_slots WHERE id = ? AND round_id = ?",
        (slot_id, round_id),
    ).fetchone()
    if not slot:
        return False, "ไม่พบช่องที่ต้องการแก้ไข"
    if not slot["is_bye"]:
        return False, "ช่องนี้ไม่ใช่ X"

    name = (team_name or "").strip()
    if not name:
        return False, "กรุณากรอกชื่อทีม"

    dup = db.execute(
        """
        SELECT id FROM round_slots
        WHERE round_id = ? AND group_no = ? AND id != ?
          AND LOWER(TRIM(COALESCE(team_name, display_name))) = LOWER(TRIM(?))
        LIMIT 1
        """,
        (round_id, slot["group_no"], slot_id, name),
    ).fetchone()
    if dup:
        return False, "สายนี้มีทีมชื่อนี้อยู่แล้ว"

    db.execute(
        """
        UPDATE round_slots
        SET display_name = ?, source_type = 'filled_bye', team_name = ?, is_bye = 0, is_resolved = 1
        WHERE id = ?
        """,
        (name, name, slot_id),
    )

    round_row = db.execute("SELECT * FROM tournament_rounds WHERE id = ?", (round_id,)).fetchone()
    if round_row:
        exists = db.execute(
            "SELECT id FROM tournament_teams WHERE tournament_id = ? AND LOWER(TRIM(display_name)) = LOWER(TRIM(?)) LIMIT 1",
            (round_row["tournament_id"], name),
        ).fetchone()
        if not exists:
            db.execute(
                "INSERT INTO tournament_teams (tournament_id, display_name, base_name, created_at) VALUES (?, ?, ?, ?)",
                (round_row["tournament_id"], name, get_base_name(name), now_str()),
            )

    db.execute(
        "DELETE FROM round_scores WHERE round_id = ? AND group_no = ?",
        (round_id, slot["group_no"]),
    )
    return True, "เพิ่มทีมลงแทน X แล้ว กรุณากรอกผลใหม่ของสายนี้"

def get_tournament_sync_version(tournament_id):
    db = get_db()
    row = db.execute(
        """
        SELECT MAX(rs.updated_at) AS latest
        FROM round_scores rs
        JOIN tournament_rounds tr ON tr.id = rs.round_id
        WHERE tr.tournament_id = ?
        """,
        (tournament_id,),
    ).fetchone()
    return row["latest"] if row and row["latest"] else ""


def emit_score_update(tournament_id, payload):
    socketio.emit('score_updated', payload, to=f'tournament_{tournament_id}')


def emit_tournament_reload(tournament_id, reason='reload'):
    socketio.emit('tournament_reload', {'tournament_id': tournament_id, 'reason': reason, 'updated_at': now_str()}, to=f'tournament_{tournament_id}')


@socketio.on('join_tournament')
def on_join_tournament(data):
    tournament_id = (data or {}).get('tournament_id')
    if not tournament_id:
        return
    room = f'tournament_{tournament_id}'
    join_room(room)
    emit('joined_tournament', {'ok': True, 'room': room, 'tournament_id': tournament_id})


def get_manual_group_map(round_id):
    db = get_db()
    try:
        rows = db.execute(
            "SELECT group_no, winner_slot_no, second_slot_no FROM manual_group_rankings WHERE round_id = ?",
            (round_id,),
        ).fetchall()
    except Exception:
        return {}

    result = {}
    for row in rows:
        try:
            result[row["group_no"]] = {
                "winner_slot_no": row["winner_slot_no"],
                "second_slot_no": row["second_slot_no"],
            }
        except Exception:
            continue
    return result


def get_round_views(tournament_id):
    db = get_db()
    rounds = db.execute(
        "SELECT * FROM tournament_rounds WHERE tournament_id = ? ORDER BY round_no ASC",
        (tournament_id,),
    ).fetchall()

    views = []
    for rnd in rounds:
        slots = db.execute(
            "SELECT * FROM round_slots WHERE round_id = ? ORDER BY group_no, slot_no",
            (rnd["id"],),
        ).fetchall()

        grouped = defaultdict(list)
        for slot in slots:
            grouped[slot["group_no"]].append(dict(slot))

        scores = db.execute(
            "SELECT * FROM round_scores WHERE round_id = ?",
            (rnd["id"],),
        ).fetchall()
        base_score_map = build_round_score_map(scores)
        manual_group_map = get_manual_group_map(rnd["id"])

        group_views = []
        merged_score_map = dict(base_score_map)
        display_counter = 1

        for group_no, group_slots in grouped.items():
            for slot in group_slots:
                slot["display_slot_no"] = display_counter
                display_counter += 1
            for idx in range(0, len(group_slots), 2):
                pair_slots = group_slots[idx:idx + 2]
                has_bye = any(slot["is_bye"] for slot in pair_slots)
                for offset, slot in enumerate(pair_slots):
                    slot["pair_has_bye"] = has_bye
                    slot["is_first_in_pair"] = (offset == 0)
                    slot["show_court_input"] = (offset == 0 and not has_bye)
                    slot["court_rowspan"] = len(pair_slots)

            local_score_map = apply_bye_auto_scores(rnd["round_type"], group_slots, dict(base_score_map))
            merged_score_map.update(local_score_map)

            manual_override = manual_group_map.get(group_no)
            res = compute_group_results(rnd["round_type"], group_slots, local_score_map, manual_override=manual_override)
            stage_state = build_stage_locks(rnd["round_type"], group_slots, local_score_map)
            manual_options = [slot for slot in group_slots if not slot["is_bye"]]

            group_views.append({
                "group_no": group_no,
                "slots": group_slots,
                "result": res,
                "stage_state": stage_state,
                "manual_override": manual_override,
                "manual_options": manual_options,
            })

        views.append({
            "round": rnd,
            "group_views": group_views,
            "score_map": merged_score_map,
        })
    return views


def sync_eliminated_for_round(tournament_id, round_no, round_view):
    db = get_db()
    for group in round_view["group_views"]:
        for idx, slot in enumerate(group["result"]["eliminated"], start=1):
            team_name = slot["team_name"] or slot["display_name"]
            db.execute(
                """
                INSERT OR IGNORE INTO eliminated_teams
                (tournament_id, team_name, source_round_no, source_group_no, source_rank, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'pool', ?)
                """,
                (tournament_id, team_name, round_no, group["group_no"], idx, now_str()),
            )
    db.commit()


def collect_eliminated_from_round(tournament_id, round_view):
    db = get_db()
    round_no = round_view["round"]["round_no"]

    for group in round_view["group_views"]:
        group_no = group["group_no"]
        for slot in group["result"]["eliminated"]:
            team_name = (slot["team_name"] or slot["display_name"] or "").strip()
            if not team_name or team_name == "X":
                continue

            source_text = f"ตกรอบ {round_no} / สาย {group_no}"

            exists = db.execute(
                """
                SELECT id
                FROM team_pool
                WHERE tournament_id = ?
                  AND TRIM(team_name) = ?
                LIMIT 1
                """,
                (tournament_id, team_name),
            ).fetchone()

            if exists:
                continue

            db.execute(
                """
                INSERT INTO team_pool
                (tournament_id, team_name, source_text, source_tournament_id, source_round_no, source_group_no, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'pool', ?)
                """,
                (tournament_id, team_name, source_text, tournament_id, round_no, group_no, now_str()),
            )

    db.commit()


def build_source_participants(round_view):
    participants = []
    round_type = round_view["round"]["round_type"]
    qualifier_count = 2 if round_type == "double_knockout" else 1

    for group in round_view["group_views"]:
        qualified = group["result"]["qualified"]
        for rank_no in range(1, qualifier_count + 1):
            if len(qualified) >= rank_no:
                slot = qualified[rank_no - 1]
                participants.append({
                    "display_name": slot["team_name"] or slot["display_name"],
                    "source_type": "team",
                    "source_group_no": group["group_no"],
                    "source_rank": rank_no,
                    "team_name": slot["team_name"] or slot["display_name"],
                    "is_bye": 0,
                    "is_resolved": 1,
                })
            else:
                participants.append({
                    "display_name": placeholder_name(rank_no, group["group_no"]),
                    "source_type": "placeholder",
                    "source_group_no": group["group_no"],
                    "source_rank": rank_no,
                    "team_name": None,
                    "is_bye": 0,
                    "is_resolved": 0,
                })
    return participants


def create_next_round_from_round_view(tournament, round_view, target_round_type, manual_group_count=None, separate_same=True):
    db = get_db()
    tournament_id = tournament["id"]
    participants = build_source_participants(round_view)
    names_for_draw = [p["display_name"] for p in participants]

    if target_round_type == "double_knockout":
        if len(names_for_draw) < 3:
            raise ValueError("Double knockout ต้องมีอย่างน้อย 3 ทีม")
        fill_value = 4
        group_sizes = calculate_group_sizes(len(names_for_draw), manual_group_count)
    else:
        fill_value = 2
        group_count = manual_group_count if manual_group_count and manual_group_count > 0 else max(1, math.ceil(len(names_for_draw) / 2))
        group_sizes = [2] * group_count

    random_groups = smart_draw_groups(names_for_draw, group_sizes, avoid_same=separate_same)
    if target_round_type == "double_knockout":
        for group in random_groups:
            while len(group) < 4:
                group.append("X")
        random_groups = reorder_groups_to_push_byes_last(random_groups)

    round_no = get_next_round_no(tournament_id)
    cur = db.execute(
        """
        INSERT INTO tournament_rounds
        (tournament_id, round_no, round_name, round_type, group_count, status, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', ?)
        """,
        (tournament_id, round_no, f"รอบที่ {round_no}", target_round_type, len(random_groups), now_str()),
    )
    round_id = cur.lastrowid

    pmap = {p["display_name"]: p for p in participants}
    for group_no, names in enumerate(random_groups, start=1):
        rows = list(names)
        while len(rows) < fill_value:
            rows.append("X")
        for slot_no, name in enumerate(rows, start=1):
            if name == "X":
                db.execute(
                    """
                    INSERT INTO round_slots
                    (round_id, group_no, slot_no, display_name, source_type, source_group_no, source_rank, team_name, court_name, is_bye, is_resolved)
                    VALUES (?, ?, ?, 'X', 'bye', NULL, NULL, NULL, NULL, 1, 1)
                    """,
                    (round_id, group_no, slot_no),
                )
            else:
                p = pmap[name]
                db.execute(
                    """
                    INSERT INTO round_slots
                    (round_id, group_no, slot_no, display_name, source_type, source_group_no, source_rank, team_name, court_name, is_bye, is_resolved)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                    """,
                    (
                        round_id,
                        group_no,
                        slot_no,
                        p["display_name"],
                        p["source_type"],
                        p["source_group_no"],
                        p["source_rank"],
                        p["team_name"],
                        p["is_bye"],
                        p["is_resolved"],
                    ),
                )
    db.commit()
    return round_id, round_no


def resolve_placeholders_for_next_round(tournament_id, source_round_no, source_view):
    db = get_db()

    resolved_map = {}
    for group in source_view["group_views"]:
        qualified = group["result"]["qualified"]
        for idx, slot in enumerate(qualified, start=1):
            resolved_map[(group["group_no"], idx)] = slot["team_name"] or slot["display_name"]

    next_round = db.execute(
        """
        SELECT * FROM tournament_rounds
        WHERE tournament_id = ? AND round_no = ?
        LIMIT 1
        """,
        (tournament_id, source_round_no + 1),
    ).fetchone()

    if not next_round:
        return

    next_slots = db.execute(
        """
        SELECT * FROM round_slots
        WHERE round_id = ? AND source_type = 'placeholder'
        """,
        (next_round["id"],),
    ).fetchall()

    for slot in next_slots:
        key = (slot["source_group_no"], slot["source_rank"])
        if key in resolved_map:
            db.execute(
                """
                UPDATE round_slots
                SET team_name = ?, is_resolved = 1
                WHERE id = ?
                """,
                (resolved_map[key], slot["id"]),
            )

    db.commit()




# ------------------------- score sheet helpers -------------------------
def score_sheet_team_name(slot):
    if not slot:
        return "____________________________"
    if slot["is_bye"]:
        return "X / BYE"
    return slot["team_name"] or slot["display_name"] or "____________________________"


def build_score_sheet_matches(round_views, only_round_id=None, only_group_no=None):
    """Build printable paper score sheets in the same style as the tournoi system."""
    sheets = []

    def as_slot_map(slots):
        return {int(slot["slot_no"]): slot for slot in slots}

    def add_sheet(rv, group, stage_no, stage_label, a, b, court_name=None):
        if only_group_no is not None and int(group["group_no"]) != int(only_group_no):
            return
        if a is None and b is None:
            return
        # Do not print an empty BYE-vs-BYE sheet.
        if a is not None and b is not None and a["is_bye"] and b["is_bye"]:
            return
        sheets.append({
            "round": rv["round"],
            "group_no": group["group_no"],
            "stage_no": stage_no,
            "stage_label": stage_label,
            "court_name": court_name or (a["court_name"] if a and a["court_name"] else (b["court_name"] if b and b["court_name"] else "")),
            "team1_name": score_sheet_team_name(a),
            "team2_name": score_sheet_team_name(b),
        })

    for rv in round_views:
        if only_round_id is not None and int(rv["round"]["id"]) != int(only_round_id):
            continue

        round_type = rv["round"]["round_type"]
        for group in rv["group_views"]:
            if only_group_no is not None and int(group["group_no"]) != int(only_group_no):
                continue
            slots = group["slots"]
            by_no = as_slot_map(slots)

            if round_type == "knockout":
                add_sheet(rv, group, 1, "คู่แข่งขัน", by_no.get(1), by_no.get(2))
                continue

            # Double knockout 4-team group:
            # Stage 1: 1-2, 3-4
            add_sheet(rv, group, 1, "คู่ที่ 1", by_no.get(1), by_no.get(2))
            add_sheet(rv, group, 1, "คู่ที่ 2", by_no.get(3), by_no.get(4))

            score_map = dict(rv["score_map"])
            qf1 = decide_pair(by_no.get(1), by_no.get(2), 1, score_map)
            qf2 = decide_pair(by_no.get(3), by_no.get(4), 1, score_map)

            # Stage 2 sheets become real names after stage 1 is scored; otherwise show placeholders.
            if qf1 and qf2:
                add_sheet(rv, group, 2, "ผู้ชนะพบผู้ชนะ", qf1["winner"], qf2["winner"])
                add_sheet(rv, group, 2, "ผู้แพ้พบผู้แพ้", qf1["loser"], qf2["loser"])
            else:
                placeholder_a = {"is_bye": 0, "team_name": "ผู้ชนะคู่ที่ 1", "display_name": "ผู้ชนะคู่ที่ 1", "court_name": ""}
                placeholder_b = {"is_bye": 0, "team_name": "ผู้ชนะคู่ที่ 2", "display_name": "ผู้ชนะคู่ที่ 2", "court_name": ""}
                placeholder_c = {"is_bye": 0, "team_name": "ผู้แพ้คู่ที่ 1", "display_name": "ผู้แพ้คู่ที่ 1", "court_name": ""}
                placeholder_d = {"is_bye": 0, "team_name": "ผู้แพ้คู่ที่ 2", "display_name": "ผู้แพ้คู่ที่ 2", "court_name": ""}
                add_sheet(rv, group, 2, "ผู้ชนะพบผู้ชนะ", placeholder_a, placeholder_b)
                add_sheet(rv, group, 2, "ผู้แพ้พบผู้แพ้", placeholder_c, placeholder_d)

            wf = decide_pair(qf1["winner"], qf2["winner"], 2, score_map) if qf1 and qf2 else None
            lf = decide_pair(qf1["loser"], qf2["loser"], 2, score_map) if qf1 and qf2 else None
            if wf and lf:
                add_sheet(rv, group, 3, "ชิงอันดับ 2", wf["loser"], lf["winner"])
            else:
                placeholder_e = {"is_bye": 0, "team_name": "ผู้แพ้ผู้ชนะพบผู้ชนะ", "display_name": "ผู้แพ้ผู้ชนะพบผู้ชนะ", "court_name": ""}
                placeholder_f = {"is_bye": 0, "team_name": "ผู้ชนะผู้แพ้พบผู้แพ้", "display_name": "ผู้ชนะผู้แพ้พบผู้แพ้", "court_name": ""}
                add_sheet(rv, group, 3, "ชิงอันดับ 2", placeholder_e, placeholder_f)

    return sheets


# ------------------------- template globals -------------------------
@app.context_processor
def inject_user():
    return {
        "current_user": current_user(),
        "competition_type_label": competition_type_label,
        "stage_can_edit": stage_is_editable,
    }


# ------------------------- routes -------------------------
@app.route("/")
def home():
    db = get_db()
    tournaments = db.execute(
        """
        SELECT t.*, u.username AS owner_name
        FROM tournaments t JOIN users u ON u.id = t.owner_id
        ORDER BY t.id DESC
        """
    ).fetchall()
    return render_template("public_home.html", tournaments=tournaments)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง", "error")
            return render_template("login.html")

        ok, message = check_login_access(user)
        if not ok:
            flash(message, "error")
            return render_template("login.html")

        session["user_id"] = user["id"]
        flash("เข้าสู่ระบบสำเร็จ", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("ออกจากระบบแล้ว", "success")
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    db = get_db()

    if user["role"] == "super_admin":
        tournaments = db.execute(
            """
            SELECT t.*, u.username AS owner_name
            FROM tournaments t JOIN users u ON u.id = t.owner_id
            ORDER BY t.id DESC
            """
        ).fetchall()
    else:
        tournaments = db.execute(
            """
            SELECT t.*, u.username AS owner_name
            FROM tournaments t JOIN users u ON u.id = t.owner_id
            WHERE t.owner_id = ?
            ORDER BY t.id DESC
            """,
            (user["id"],),
        ).fetchall()

    create_ok, create_message = can_create_tournament(user)
    batches = db.execute(
        """
        SELECT b.id, b.name, b.subtitle, b.created_at,
               (SELECT COUNT(*) FROM tournaments t WHERE t.batch_id = b.id) AS event_count
        FROM tournament_batches b
        WHERE ? = 'super_admin' OR b.owner_id = ?
        ORDER BY b.id DESC
        """,
        (user["role"], user["id"]),
    ).fetchall()
    batch_names = {b["id"]: b["name"] for b in batches}
    return render_template(
        "dashboard.html",
        tournaments=tournaments,
        create_ok=create_ok,
        create_message=create_message,
        batches=batches,
        batch_names=batch_names,
    )


@app.route("/users", methods=["GET", "POST"])
@role_required("super_admin")
def manage_users():
    db = get_db()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "admin")
        create_quota = int(request.form.get("create_quota", 0) or 0)
        expires_at = request.form.get("expires_at", "").strip() or None

        if not username or not password:
            flash("กรอกชื่อผู้ใช้และรหัสผ่านให้ครบ", "error")
        else:
            try:
                db.execute(
                    """
                    INSERT INTO users
                    (username, password_hash, role, created_by, is_active, create_quota, created_count, expires_at, created_at, updated_at)
                    VALUES (?, ?, ?, ?, 1, ?, 0, ?, ?, ?)
                    """,
                    (
                        username,
                        generate_password_hash(password),
                        role,
                        current_user()["id"],
                        create_quota,
                        expires_at,
                        now_str(),
                        now_str(),
                    ),
                )
                db.commit()
                flash("สร้างผู้ใช้สำเร็จ", "success")
                return redirect(url_for("manage_users"))
            except sqlite3.IntegrityError:
                flash("ชื่อผู้ใช้นี้ถูกใช้แล้ว", "error")

    users = db.execute(
        """
        SELECT u.*, c.username AS creator_name
        FROM users u LEFT JOIN users c ON c.id = u.created_by
        ORDER BY u.id DESC
        """
    ).fetchall()
    return render_template("users.html", users=users)


@app.route("/users/<int:user_id>/toggle", methods=["POST"])
@role_required("super_admin")
def toggle_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash("ไม่พบผู้ใช้", "error")
        return redirect(url_for("manage_users"))
    if user["role"] == "super_admin":
        flash("ไม่อนุญาตให้ปิด super admin", "error")
        return redirect(url_for("manage_users"))

    db.execute(
        "UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?",
        (0 if user["is_active"] else 1, now_str(), user_id),
    )
    db.commit()
    flash("อัปเดตสถานะผู้ใช้แล้ว", "success")
    return redirect(url_for("manage_users"))


@app.route("/users/<int:user_id>/quota", methods=["POST"])
@role_required("super_admin")
def update_user_quota(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash("ไม่พบผู้ใช้", "error")
        return redirect(url_for("manage_users"))

    create_quota = int(request.form.get("create_quota", 0) or 0)
    expires_at = request.form.get("expires_at", "").strip() or None
    db.execute(
        "UPDATE users SET create_quota = ?, expires_at = ?, updated_at = ? WHERE id = ?",
        (create_quota, expires_at, now_str(), user_id),
    )
    db.commit()
    flash("อัปเดตโควตาแล้ว", "success")
    return redirect(url_for("manage_users"))


@app.route("/tournaments/create", methods=["GET", "POST"])
@login_required
def create_tournament():
    user = current_user()
    can_create, message = can_create_tournament(user)
    if not can_create:
        flash(message, "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        teams_text = request.form.get("teams", "")
        avoid_same = 1 if request.form.get("avoid_same") == "on" else 0
        competition_type = request.form.get("competition_type", "double_knockout").strip() or "double_knockout"
        if competition_type not in {"double_knockout", "knockout"}:
            competition_type = "double_knockout"

        manual_group_count_raw = request.form.get("group_count", "").strip()
        try:
            manual_group_count = int(manual_group_count_raw) if manual_group_count_raw else None
        except ValueError:
            flash("จำนวนสายต้องเป็นตัวเลขเท่านั้น", "error")
            return render_template("create_tournament.html")

        if manual_group_count is not None and manual_group_count <= 0:
            flash("จำนวนสายต้องมากกว่า 0", "error")
            return render_template("create_tournament.html")

        teams = [line.strip() for line in teams_text.splitlines() if line.strip()]

        if not name:
            flash("กรุณากรอกชื่อทัวร์นาเมนต์", "error")
            return render_template("create_tournament.html")
        if len(teams) < 2:
            flash("ต้องมีอย่างน้อย 2 ทีม", "error")
            return render_template("create_tournament.html")

        try:
            if competition_type == "double_knockout":
                if len(teams) < 3:
                    flash("Double knockout ต้องมีอย่างน้อย 3 ทีม", "error")
                    return render_template("create_tournament.html")
                group_sizes = calculate_group_sizes(len(teams), manual_group_count)
                groups = smart_draw_groups(teams, group_sizes, avoid_same=bool(avoid_same))
                for g in groups:
                    while len(g) < 4:
                        g.append("X")
                groups = reorder_groups_to_push_byes_last(groups)
                qualify_per_group = 2
            else:
                group_count = manual_group_count if manual_group_count and manual_group_count > 0 else max(1, math.ceil(len(teams) / 2))
                if group_count > len(teams):
                    flash("จำนวนสายมากกว่าจำนวนทีมไม่ได้", "error")
                    return render_template("create_tournament.html")
                groups = smart_draw_groups(teams, [2] * group_count, avoid_same=bool(avoid_same))
                for g in groups:
                    while len(g) < 2:
                        g.append("X")
                qualify_per_group = 1
        except ValueError as e:
            flash(str(e), "error")
            return render_template("create_tournament.html")

        db = get_db()
        cur = db.execute(
            """
            INSERT INTO tournaments
            (name, owner_id, team_count, group_count, group_sizes_json, avoid_same, competition_type, qualify_per_group, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?)
            """,
            (
                name,
                user["id"],
                len(teams),
                len(groups),
                ",".join(str(len(g)) for g in groups),
                avoid_same,
                competition_type,
                qualify_per_group,
                now_str(),
            ),
        )
        tournament_id = cur.lastrowid

        for team in teams:
            db.execute(
                """
                INSERT INTO tournament_teams (tournament_id, display_name, base_name, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (tournament_id, team, get_base_name(team), now_str()),
            )

        create_round(tournament_id, 1, "รอบที่ 1", competition_type, groups)
        db.commit()
        consume_quota(user["id"])
        flash("สร้างทัวร์นาเมนต์สำเร็จแล้ว", "success")
        return redirect(url_for("view_tournament", tournament_id=tournament_id))

    return render_template("create_tournament.html")


@app.route("/tournaments/<int:tournament_id>")
def view_tournament(tournament_id):
    db = get_db()
    tournament = db.execute(
        """
        SELECT t.*, u.username AS owner_name
        FROM tournaments t JOIN users u ON u.id = t.owner_id
        WHERE t.id = ?
        """,
        (tournament_id,),
    ).fetchone()
    if not tournament:
        flash("ไม่พบทัวร์นาเมนต์", "error")
        return redirect(url_for("home"))

    user = current_user()
    can_manage = can_manage_tournament(user, tournament)
    round_views = get_round_views(tournament_id)
    sync_version = get_tournament_sync_version(tournament_id)
    return render_template(
        "tournament_detail.html",
        tournament=tournament,
        round_views=round_views,
        can_manage=can_manage,
        sync_version=sync_version,
    )

@app.route("/tournaments/<int:tournament_id>/print-groups")
def print_groups_sheet(tournament_id):
    db = get_db()
    tournament = db.execute(
        """
        SELECT t.*, u.username AS owner_name
        FROM tournaments t
        JOIN users u ON u.id = t.owner_id
        WHERE t.id = ?
        """,
        (tournament_id,),
    ).fetchone()

    if not tournament:
        flash("ไม่พบทัวร์นาเมนต์", "error")
        return redirect(url_for("home"))

    round_views = get_round_views(tournament_id)

    if not round_views:
        flash("ยังไม่มีข้อมูลรอบแข่งขัน", "error")
        return redirect(url_for("view_tournament", tournament_id=tournament_id))

    return render_template(
        "print_groups_sheet.html",
        tournament=tournament,
        round_views=round_views,
    )




@app.route("/tournaments/<int:tournament_id>/score-sheets")
def tournament_score_sheets(tournament_id):
    db = get_db()
    tournament = db.execute(
        """
        SELECT t.*, u.username AS owner_name
        FROM tournaments t
        JOIN users u ON u.id = t.owner_id
        WHERE t.id = ?
        """,
        (tournament_id,),
    ).fetchone()
    if not tournament:
        flash("ไม่พบทัวร์นาเมนต์", "error")
        return redirect(url_for("home"))

    round_views = get_round_views(tournament_id)
    sheets = build_score_sheet_matches(round_views)
    return render_template(
        "score_sheet_tournoi_style.html",
        tournament=tournament,
        sheets=sheets,
        title_suffix="ทุกสกอร์ชีท",
    )


@app.route("/rounds/<int:round_id>/score-sheet")
def round_score_sheet(round_id):
    db = get_db()
    round_row = db.execute(
        """
        SELECT r.*, t.id AS tournament_id, t.name, t.owner_id, t.team_count, t.group_count,
               t.competition_type, t.status, t.created_at, u.username AS owner_name
        FROM tournament_rounds r
        JOIN tournaments t ON t.id = r.tournament_id
        JOIN users u ON u.id = t.owner_id
        WHERE r.id = ?
        """,
        (round_id,),
    ).fetchone()
    if not round_row:
        flash("ไม่พบรอบแข่งขัน", "error")
        return redirect(url_for("home"))

    tournament = db.execute(
        """
        SELECT t.*, u.username AS owner_name
        FROM tournaments t JOIN users u ON u.id = t.owner_id
        WHERE t.id = ?
        """,
        (round_row["tournament_id"],),
    ).fetchone()
    round_views = get_round_views(round_row["tournament_id"])
    sheets = build_score_sheet_matches(round_views, only_round_id=round_id)
    return render_template(
        "score_sheet_tournoi_style.html",
        tournament=tournament,
        sheets=sheets,
        title_suffix=round_row["round_name"],
    )


@app.route("/rounds/<int:round_id>/groups/<int:group_no>/score-sheet")
def group_score_sheet(round_id, group_no):
    db = get_db()
    round_row = db.execute(
        "SELECT * FROM tournament_rounds WHERE id = ?",
        (round_id,),
    ).fetchone()
    if not round_row:
        flash("ไม่พบรอบแข่งขัน", "error")
        return redirect(url_for("home"))

    tournament = db.execute(
        """
        SELECT t.*, u.username AS owner_name
        FROM tournaments t JOIN users u ON u.id = t.owner_id
        WHERE t.id = ?
        """,
        (round_row["tournament_id"],),
    ).fetchone()
    round_views = get_round_views(round_row["tournament_id"])
    sheets = build_score_sheet_matches(round_views, only_round_id=round_id, only_group_no=group_no)
    return render_template(
        "score_sheet_tournoi_style.html",
        tournament=tournament,
        sheets=sheets,
        title_suffix=f"{round_row['round_name']} / สาย {group_no}",
    )


@app.route("/tournaments/<int:tournament_id>/sync-version")
def tournament_sync_version(tournament_id):
    db = get_db()
    tournament = db.execute(
        "SELECT id FROM tournaments WHERE id = ?",
        (tournament_id,),
    ).fetchone()
    if not tournament:
        return {"ok": False, "message": "ไม่พบทัวร์นาเมนต์"}, 404

    return {"ok": True, "version": get_tournament_sync_version(tournament_id)}



@app.route("/rounds/<int:round_id>/autosave", methods=["POST"])
@login_required
def autosave_round_score(round_id):
    db = get_db()

    round_row = db.execute(
        """
        SELECT r.*, t.id AS tournament_id
        FROM tournament_rounds r
        JOIN tournaments t ON t.id = r.tournament_id
        WHERE r.id = ?
        """,
        (round_id,),
    ).fetchone()

    if not round_row:
        return {"ok": False, "message": "ไม่พบรอบแข่งขัน"}, 404

    tournament = get_tournament_for_user(round_row["tournament_id"], current_user())
    if not tournament:
        return {"ok": False, "message": "ไม่มีสิทธิ์"}, 403

    slot_id = request.form.get("slot_id")
    group_no = request.form.get("group_no")
    stage_no = request.form.get("stage_no")
    score_raw = request.form.get("score", "")
    court_name = request.form.get("court_name", "").strip()
    client_sid = request.form.get("client_sid", "").strip()

    if not slot_id or not group_no:
        return {"ok": False, "message": "ข้อมูลไม่ครบ"}, 400

    slot = db.execute(
        "SELECT * FROM round_slots WHERE id = ? AND round_id = ?",
        (slot_id, round_id),
    ).fetchone()

    if not slot:
        return {"ok": False, "message": "ไม่พบ slot"}, 404

    if slot["is_bye"]:
        return {"ok": False, "message": "ช่อง X ห้ามกรอก"}, 400

    slots = db.execute(
        "SELECT * FROM round_slots WHERE round_id = ? AND group_no = ? ORDER BY slot_no",
        (round_id, int(group_no)),
    ).fetchall()

    pair_start = slot["slot_no"] if slot["slot_no"] % 2 == 1 else slot["slot_no"] - 1

    if stage_no in (None, ""):
        db.execute(
            """
            UPDATE round_slots
            SET court_name = ?
            WHERE round_id = ? AND group_no = ? AND slot_no IN (?, ?)
            """,
            (court_name or None, round_id, int(group_no), pair_start, pair_start + 1),
        )
        db.commit()
        emit_score_update(
            round_row["tournament_id"],
            {
                "tournament_id": round_row["tournament_id"],
                "round_id": round_id,
                "group_no": int(group_no),
                "pair_start": int(pair_start),
                "stage_no": None,
                "slot_id": int(slot_id),
                "court_name": court_name or None,
                "score": None,
                "client_sid": client_sid or None,
                "updated_at": now_str(),
            },
        )
        return {"ok": True, "message": "บันทึกเลขสนามแล้ว"}

    score_rows = db.execute(
        "SELECT * FROM round_scores WHERE round_id = ? AND group_no = ?",
        (round_id, int(group_no)),
    ).fetchall()
    score_map = build_round_score_map(score_rows)

    stage_no_int = int(stage_no)

    if not stage_is_editable(round_row["round_type"], slots, stage_no_int, slot["slot_no"], score_map):
        return {"ok": False, "message": "ยังไม่ถึงรอบของช่องนี้"}, 400

    if score_raw == "":
        db.execute(
            """
            DELETE FROM round_scores
            WHERE round_id = ? AND group_no = ? AND slot_no = ? AND stage_no = ?
            """,
            (round_id, int(group_no), int(slot["slot_no"]), stage_no_int),
        )
    else:
        try:
            score = int(score_raw)
            if score < 0 or score > 13:
                raise ValueError
        except ValueError:
            return {"ok": False, "message": "คะแนนต้องเป็นเลข 0 ถึง 13"}, 400

        upsert_round_score(round_id, int(group_no), int(slot["slot_no"]), stage_no_int, score)

    if stage_no_int < 3:
        db.execute(
            "DELETE FROM round_scores WHERE round_id = ? AND group_no = ? AND stage_no > ?",
            (round_id, int(group_no), stage_no_int),
        )

    db.commit()
    emit_score_update(
        round_row["tournament_id"],
        {
            "tournament_id": round_row["tournament_id"],
            "round_id": round_id,
            "group_no": int(group_no),
            "pair_start": int(pair_start),
            "stage_no": stage_no_int,
            "slot_id": int(slot_id),
            "slot_no": int(slot["slot_no"]),
            "court_name": court_name or None,
            "score": "" if score_raw == "" else int(score_raw),
            "client_sid": client_sid or None,
            "updated_at": now_str(),
        },
    )
    emit_tournament_reload(round_row["tournament_id"], reason='score_saved')
    return {"ok": True, "message": "บันทึกแล้ว"}




@app.route("/rounds/<int:round_id>/renumber-courts", methods=["POST"])
@login_required
def renumber_courts(round_id):
    db = get_db()
    round_row = db.execute(
        """
        SELECT r.*, t.id AS tournament_id
        FROM tournament_rounds r
        JOIN tournaments t ON t.id = r.tournament_id
        WHERE r.id = ?
        """,
        (round_id,),
    ).fetchone()

    if not round_row:
        flash("ไม่พบรอบแข่งขัน", "error")
        return redirect(url_for("dashboard"))

    tournament = get_tournament_for_user(round_row["tournament_id"], current_user())
    if not tournament:
        flash("คุณไม่มีสิทธิ์จัดการ", "error")
        return redirect(url_for("dashboard"))

    start_court = request.form.get("start_court", type=int) or 1
    skip_text = request.form.get("skip_courts", "")
    renumber_round_courts(round_id, start_court=start_court, skip_courts=parse_skip_courts(skip_text))
    db.commit()
    emit_tournament_reload(round_row["tournament_id"], reason='renumber_courts')
    detail = f"เริ่มสนาม {start_court}"
    if skip_text.strip():
        detail += f" · เว้น {skip_text.strip()}"
    flash(f"จัดเลขสนามอัตโนมัติแล้ว ({detail})", "success")
    return redirect(url_for("view_tournament", tournament_id=round_row["tournament_id"]) + f"#saved-round-{round_id}")


@app.route("/rounds/<int:round_id>/fill-bye", methods=["POST"])
@login_required
def fill_bye_slot(round_id):
    db = get_db()
    round_row = db.execute(
        """
        SELECT r.*, t.id AS tournament_id
        FROM tournament_rounds r
        JOIN tournaments t ON t.id = r.tournament_id
        WHERE r.id = ?
        """,
        (round_id,),
    ).fetchone()

    if not round_row:
        flash("ไม่พบรอบแข่งขัน", "error")
        return redirect(url_for("dashboard"))

    tournament = get_tournament_for_user(round_row["tournament_id"], current_user())
    if not tournament:
        flash("คุณไม่มีสิทธิ์จัดการ", "error")
        return redirect(url_for("dashboard"))

    slot_id = request.form.get("slot_id", type=int)
    team_name = request.form.get("team_name", "")
    ok, message = add_team_into_bye_slot(round_id, slot_id, team_name)
    if ok:
        db.commit()
        emit_tournament_reload(round_row["tournament_id"], reason='fill_bye')
        flash(message, "success")
    else:
        db.rollback()
        flash(message, "error")

    group_no = request.form.get("group_no", type=int)
    anchor = f"#round-{round_row['round_no']}-group-{group_no}" if group_no else f"#saved-round-{round_id}"
    return redirect(url_for("view_tournament", tournament_id=round_row["tournament_id"]) + anchor)


@app.route("/rounds/<int:round_id>/groups/<int:group_no>/manual-rankings", methods=["POST"])
@login_required
def save_manual_group_rankings(round_id, group_no):
    db = get_db()
    round_row = db.execute(
        """
        SELECT r.*, t.id AS tournament_id, t.owner_id
        FROM tournament_rounds r JOIN tournaments t ON t.id = r.tournament_id
        WHERE r.id = ?
        """,
        (round_id,),
    ).fetchone()
    if not round_row:
        flash("ไม่พบรอบการแข่งขัน", "error")
        return redirect(url_for("dashboard"))

    tournament = get_tournament_for_user(round_row["tournament_id"], current_user())
    if not tournament:
        flash("คุณไม่มีสิทธิ์จัดการ", "error")
        return redirect(url_for("dashboard"))

    slots = db.execute(
        "SELECT * FROM round_slots WHERE round_id = ? AND group_no = ? ORDER BY slot_no",
        (round_id, group_no),
    ).fetchall()
    valid_slot_nos = {slot["slot_no"] for slot in slots if not slot["is_bye"]}

    winner_raw = (request.form.get("winner_slot_no") or "").strip()
    second_raw = (request.form.get("second_slot_no") or "").strip()

    if not winner_raw:
        flash("กรุณาเลือกอันดับ 1", "error")
        return redirect(url_for("view_tournament", tournament_id=round_row["tournament_id"]) + f"#round-{round_row['round_no']}-group-{group_no}")

    try:
        winner_slot_no = int(winner_raw)
    except ValueError:
        flash("อันดับ 1 ไม่ถูกต้อง", "error")
        return redirect(url_for("view_tournament", tournament_id=round_row["tournament_id"]) + f"#round-{round_row['round_no']}-group-{group_no}")

    if winner_slot_no not in valid_slot_nos:
        flash("อันดับ 1 ต้องเป็นทีมที่มีอยู่จริง", "error")
        return redirect(url_for("view_tournament", tournament_id=round_row["tournament_id"]) + f"#round-{round_row['round_no']}-group-{group_no}")

    second_slot_no = None
    if round_row["round_type"] == "double_knockout":
        if not second_raw:
            flash("กรุณาเลือกอันดับ 2", "error")
            return redirect(url_for("view_tournament", tournament_id=round_row["tournament_id"]) + f"#round-{round_row['round_no']}-group-{group_no}")
        try:
            second_slot_no = int(second_raw)
        except ValueError:
            flash("อันดับ 2 ไม่ถูกต้อง", "error")
            return redirect(url_for("view_tournament", tournament_id=round_row["tournament_id"]) + f"#round-{round_row['round_no']}-group-{group_no}")
        if second_slot_no not in valid_slot_nos:
            flash("อันดับ 2 ต้องเป็นทีมที่มีอยู่จริง", "error")
            return redirect(url_for("view_tournament", tournament_id=round_row["tournament_id"]) + f"#round-{round_row['round_no']}-group-{group_no}")
        if second_slot_no == winner_slot_no:
            flash("อันดับ 1 และอันดับ 2 ต้องไม่เป็นทีมเดียวกัน", "error")
            return redirect(url_for("view_tournament", tournament_id=round_row["tournament_id"]) + f"#round-{round_row['round_no']}-group-{group_no}")

    db.execute(
        """
        INSERT INTO manual_group_rankings (round_id, group_no, winner_slot_no, second_slot_no, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(round_id, group_no)
        DO UPDATE SET winner_slot_no = excluded.winner_slot_no,
                      second_slot_no = excluded.second_slot_no,
                      updated_at = excluded.updated_at
        """,
        (round_id, group_no, winner_slot_no, second_slot_no, now_str()),
    )
    db.commit()
    emit_tournament_reload(round_row["tournament_id"], reason='manual_rankings_saved')
    flash("กำหนดทีมเข้ารอบเองแล้ว", "success")
    return redirect(url_for("view_tournament", tournament_id=round_row["tournament_id"]) + f"#round-{round_row['round_no']}-group-{group_no}")


@app.route("/rounds/<int:round_id>/groups/<int:group_no>/manual-rankings/reset", methods=["POST"])
@login_required
def reset_manual_group_rankings(round_id, group_no):
    db = get_db()
    round_row = db.execute(
        """
        SELECT r.*, t.id AS tournament_id, t.owner_id
        FROM tournament_rounds r JOIN tournaments t ON t.id = r.tournament_id
        WHERE r.id = ?
        """,
        (round_id,),
    ).fetchone()
    if not round_row:
        flash("ไม่พบรอบการแข่งขัน", "error")
        return redirect(url_for("dashboard"))

    tournament = get_tournament_for_user(round_row["tournament_id"], current_user())
    if not tournament:
        flash("คุณไม่มีสิทธิ์จัดการ", "error")
        return redirect(url_for("dashboard"))

    db.execute(
        "DELETE FROM manual_group_rankings WHERE round_id = ? AND group_no = ?",
        (round_id, group_no),
    )
    db.commit()
    emit_tournament_reload(round_row["tournament_id"], reason='manual_rankings_reset')
    flash("ล้างการกำหนดทีมเข้ารอบเองแล้ว", "success")
    return redirect(url_for("view_tournament", tournament_id=round_row["tournament_id"]) + f"#round-{round_row['round_no']}-group-{group_no}")


@app.route("/rounds/<int:round_id>/groups/<int:group_no>/scores", methods=["POST"])
@login_required
def save_round_scores(round_id, group_no):
    db = get_db()
    round_row = db.execute(
        """
        SELECT r.*, t.id AS tournament_id, t.owner_id
        FROM tournament_rounds r JOIN tournaments t ON t.id = r.tournament_id
        WHERE r.id = ?
        """,
        (round_id,),
    ).fetchone()
    if not round_row:
        flash("ไม่พบรอบการแข่งขัน", "error")
        return redirect(url_for("dashboard"))

    tournament = get_tournament_for_user(round_row["tournament_id"], current_user())
    if not tournament:
        flash("คุณไม่มีสิทธิ์จัดการ", "error")
        return redirect(url_for("dashboard"))

    round_views = get_round_views(round_row["tournament_id"])
    source_view = next((rv for rv in round_views if rv["round"]["id"] == round_id), None)
    if source_view:
        resolve_placeholders_for_next_round(
            tournament_id=round_row["tournament_id"],
            source_round_no=round_row["round_no"],
            source_view=source_view,
        )
        sync_eliminated_for_round(round_row["tournament_id"], round_row["round_no"], source_view)
        collect_eliminated_from_round(round_row["tournament_id"], source_view)

    emit_tournament_reload(round_row["tournament_id"], reason='save_round_scores')
    flash("ประมวลผลรอบนี้แล้ว", "success")
    return redirect(url_for("view_tournament", tournament_id=round_row["tournament_id"]) + f"#round-{round_row['round_no']}-group-{group_no}")


@app.route("/tournaments/<int:tournament_id>/next-round", methods=["POST"])
@login_required
def create_next_round(tournament_id):
    tournament = get_tournament_for_user(tournament_id, current_user())
    if not tournament:
        flash("ไม่พบทัวร์นาเมนต์หรือคุณไม่มีสิทธิ์จัดการ", "error")
        return redirect(url_for("dashboard"))

    source_round_id_raw = (request.form.get("source_round_id") or "").strip()
    if not source_round_id_raw:
        flash("กรุณาเลือกรอบต้นทางก่อนสร้างรอบถัดไป", "error")
        return redirect(url_for("view_tournament", tournament_id=tournament_id))

    try:
        source_round_id = int(source_round_id_raw)
    except ValueError:
        flash("รอบต้นทางไม่ถูกต้อง", "error")
        return redirect(url_for("view_tournament", tournament_id=tournament_id))

    target_round_type = request.form.get("round_type", "double_knockout").strip()
    if target_round_type not in {"double_knockout", "knockout"}:
        target_round_type = "double_knockout"

    manual_group_count_raw = request.form.get("next_group_count", "").strip()
    try:
        manual_group_count = int(manual_group_count_raw) if manual_group_count_raw else None
    except ValueError:
        flash("จำนวนสายต้องเป็นตัวเลขเท่านั้น", "error")
        return redirect(url_for("view_tournament", tournament_id=tournament_id))

    if manual_group_count is not None and manual_group_count <= 0:
        flash("จำนวนสายต้องมากกว่า 0", "error")
        return redirect(url_for("view_tournament", tournament_id=tournament_id))

    separate_same = True if request.form.get("separate_same") == "1" else False

    round_views = get_round_views(tournament_id)
    source_view = next((rv for rv in round_views if rv["round"]["id"] == source_round_id), None)
    if not source_view:
        flash("ไม่พบรอบต้นทาง", "error")
        return redirect(url_for("view_tournament", tournament_id=tournament_id))

    sync_eliminated_for_round(tournament_id, source_view["round"]["round_no"], source_view)
    collect_eliminated_from_round(tournament_id, source_view)

    try:
        round_id, round_no = create_next_round_from_round_view(
            tournament=tournament,
            round_view=source_view,
            target_round_type=target_round_type,
            manual_group_count=manual_group_count,
            separate_same=separate_same,
        )
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("view_tournament", tournament_id=tournament_id))

    emit_tournament_reload(tournament_id, reason='create_next_round')
    flash(f"สร้างรอบถัดไปสำเร็จ (รอบที่ {round_no})", "success")
    return redirect(url_for("view_tournament", tournament_id=tournament_id) + f"#saved-round-{round_id}")


@app.route("/tournaments/<int:tournament_id>/eliminated")
@login_required
def eliminated_pool(tournament_id):
    user = current_user()
    tournament = get_tournament_for_user(tournament_id, user)
    if not tournament:
        flash("ไม่พบทัวร์นาเมนต์หรือคุณไม่มีสิทธิ์จัดการ", "error")
        return redirect(url_for("dashboard"))

    db = get_db()

    # รายการที่ผู้ใช้มีสิทธิ์ใช้เป็นต้นทางได้
    if user["role"] == "super_admin":
        available_sources = db.execute(
            """
            SELECT DISTINCT t.id, t.name
            FROM tournaments t
            JOIN team_pool tp ON tp.tournament_id = t.id
            WHERE tp.status IN ('pool', 'used')
            ORDER BY t.created_at DESC, t.id DESC
            """
        ).fetchall()
    else:
        available_sources = db.execute(
            """
            SELECT DISTINCT t.id, t.name
            FROM tournaments t
            JOIN team_pool tp ON tp.tournament_id = t.id
            WHERE t.owner_id = ?
              AND tp.status IN ('pool', 'used')
            ORDER BY t.created_at DESC, t.id DESC
            """,
            (user["id"],),
        ).fetchall()

    selected_source_ids = []
    for raw_id in request.args.getlist("source_ids"):
        try:
            selected_source_ids.append(int(raw_id))
        except (TypeError, ValueError):
            continue

    available_ids = {row["id"] for row in available_sources}
    selected_source_ids = [sid for sid in selected_source_ids if sid in available_ids]
    if not selected_source_ids:
        selected_source_ids = [tournament_id]

    placeholders = ",".join("?" * len(selected_source_ids))
    rows = db.execute(
        f"""
        SELECT
            tp.*,
            COALESCE(src.name, 'ไม่พบชื่ออีเว้น') AS source_tournament_name
        FROM team_pool tp
        LEFT JOIN tournaments src ON src.id = COALESCE(tp.source_tournament_id, tp.tournament_id)
        WHERE tp.tournament_id IN ({placeholders})
          AND tp.status IN ('pool', 'used')
        ORDER BY
          COALESCE(tp.source_tournament_id, tp.tournament_id) DESC,
          COALESCE(tp.source_round_no, 9999) ASC,
          COALESCE(tp.source_group_no, 9999) ASC,
          tp.id DESC
        """,
        selected_source_ids,
    ).fetchall()

    pool_groups_map = {}
    for row in rows:
        source_id = row["source_tournament_id"] or row["tournament_id"]
        round_no = row["source_round_no"]
        if round_no is None:
            round_label = "ไม่ระบุรอบ"
            round_sort = 9999
        elif round_no == 0:
            round_label = "เพิ่มเอง"
            round_sort = 0
        else:
            round_label = f"ตกรอบที่ {round_no}"
            round_sort = int(round_no)

        key = (source_id, round_sort)
        if key not in pool_groups_map:
            pool_groups_map[key] = {
                "source_id": source_id,
                "source_name": row["source_tournament_name"],
                "round_no": round_no,
                "round_label": round_label,
                "rows": [],
            }
        pool_groups_map[key]["rows"].append(row)

    pool_groups = list(pool_groups_map.values())
    pool_groups.sort(key=lambda g: (g["source_name"] or "", 9999 if g["round_no"] is None else int(g["round_no"])))

    return render_template(
        "eliminated_pool.html",
        tournament=tournament,
        available_sources=available_sources,
        selected_source_ids=selected_source_ids,
        pool_groups=pool_groups,
    )


@app.route("/tournaments/<int:tournament_id>/team-pool/add", methods=["POST"])
@login_required
def add_team_to_pool(tournament_id):
    tournament = get_tournament_for_user(tournament_id, current_user())
    if not tournament:
        flash("ไม่พบทัวร์นาเมนต์หรือคุณไม่มีสิทธิ์จัดการ", "error")
        return redirect(url_for("dashboard"))

    team_name = request.form.get("team_name", "").strip()
    if not team_name:
        flash("กรุณากรอกชื่อทีม", "error")
        return redirect(url_for("eliminated_pool", tournament_id=tournament_id))

    db = get_db()

    exists = db.execute(
    """
    SELECT id
    FROM team_pool
    WHERE tournament_id = ?
      AND TRIM(team_name) = ?
    LIMIT 1
    """,
    (tournament_id, team_name.strip()),
).fetchone()
    
    if exists:
        flash("ทีมนี้มีอยู่ในคลังแล้ว", "error")
        return redirect(url_for("eliminated_pool", tournament_id=tournament_id))

    db.execute(
        """
        INSERT INTO team_pool
        (tournament_id, team_name, source_text, source_tournament_id, source_round_no, source_group_no, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'pool', ?)
        """,
        (tournament_id, team_name, "เพิ่มเองโดยผู้ดูแล", tournament_id, 0, None, now_str()),
    )
    db.commit()

    flash("เพิ่มทีมเข้าคลังแล้ว", "success")
    return redirect(url_for("eliminated_pool", tournament_id=tournament_id))

@app.route("/rounds/<int:round_id>/delete", methods=["POST"])
@login_required
def delete_round(round_id):
    db = get_db()
    user = current_user()

    target_round = db.execute(
        """
        SELECT tr.*, t.owner_id
        FROM tournament_rounds tr
        JOIN tournaments t ON t.id = tr.tournament_id
        WHERE tr.id = ?
        """,
        (round_id,),
    ).fetchone()

    if not target_round:
        flash("ไม่พบรอบที่ต้องการลบ", "error")
        return redirect(url_for("home"))

    tournament = db.execute("SELECT * FROM tournaments WHERE id = ?", (target_round["tournament_id"],)).fetchone()
    if not can_manage_tournament(user, tournament):
        flash("คุณไม่มีสิทธิ์ลบรอบนี้", "error")
        return redirect(url_for("view_tournament", tournament_id=target_round["tournament_id"]))

    last_round = db.execute(
        """
        SELECT id, round_no
        FROM tournament_rounds
        WHERE tournament_id = ?
        ORDER BY round_no DESC, id DESC
        LIMIT 1
        """,
        (target_round["tournament_id"],),
    ).fetchone()

    if not last_round or last_round["id"] != round_id:
        flash("ลบได้เฉพาะรอบล่าสุดเท่านั้น", "error")
        return redirect(url_for("view_tournament", tournament_id=target_round["tournament_id"]))

    if table_exists(db, "manual_group_rankings"):
        db.execute("DELETE FROM manual_group_rankings WHERE round_id = ?", (round_id,))
    db.execute("DELETE FROM round_scores WHERE round_id = ?", (round_id,))
    db.execute("DELETE FROM round_slots WHERE round_id = ?", (round_id,))
    db.execute("DELETE FROM tournament_rounds WHERE id = ?", (round_id,))
    db.commit()
    emit_tournament_reload(target_round["tournament_id"], reason='delete_round')

    flash(f"ลบรอบ {target_round['round_name']} เรียบร้อยแล้ว", "success")
    return redirect(url_for("view_tournament", tournament_id=target_round["tournament_id"]))

@app.route("/tournaments/<int:tournament_id>/eliminated/create-new", methods=["POST"])
@login_required
def create_tournament_from_eliminated(tournament_id):
    user = current_user()
    tournament = get_tournament_for_user(tournament_id, user)
    if not tournament:
        flash("ไม่พบทัวร์นาเมนต์หรือคุณไม่มีสิทธิ์จัดการ", "error")
        return redirect(url_for("dashboard"))

    selected_ids = request.form.getlist("team_ids")
    new_name = request.form.get("new_name", "").strip()
    competition_type = request.form.get("competition_type", "double_knockout").strip()
    if competition_type not in {"double_knockout", "knockout"}:
        competition_type = "double_knockout"

    if not selected_ids:
        flash("กรุณาเลือกทีมจากคลังอย่างน้อย 1 ทีม", "error")
        return redirect(url_for("eliminated_pool", tournament_id=tournament_id))
    if not new_name:
        flash("กรุณากรอกชื่อทัวร์นาเมนต์ใหม่", "error")
        return redirect(url_for("eliminated_pool", tournament_id=tournament_id))

    db = get_db()
    placeholders = ",".join("?" * len(selected_ids))
    rows = db.execute(
        f"""
        SELECT tp.*, t.owner_id
        FROM team_pool tp
        JOIN tournaments t ON t.id = tp.tournament_id
        WHERE tp.id IN ({placeholders})
          AND tp.status IN ('pool', 'used')
        ORDER BY tp.source_tournament_id, tp.source_round_no, tp.source_group_no, tp.id
        """,
        selected_ids,
    ).fetchall()

    allowed_rows = []
    for row in rows:
        if user["role"] == "super_admin" or row["owner_id"] == user["id"]:
            allowed_rows.append(row)

    # กันชื่อทีมซ้ำกรณีเลือกข้ามหลายอีเว้น
    teams = []
    seen_names = set()
    for r in allowed_rows:
        team_name = (r["team_name"] or "").strip()
        if not team_name or team_name in seen_names:
            continue
        seen_names.add(team_name)
        teams.append(team_name)
    if len(teams) < 2:
        flash("ต้องมีอย่างน้อย 2 ทีมเพื่อสร้างรายการใหม่", "error")
        return redirect(url_for("eliminated_pool", tournament_id=tournament_id))

    if competition_type == "double_knockout":
        if len(teams) < 3:
            flash("Double knockout ต้องมีอย่างน้อย 3 ทีม", "error")
            return redirect(url_for("eliminated_pool", tournament_id=tournament_id))
        group_sizes = calculate_group_sizes(len(teams), None)
        groups = smart_draw_groups(teams, group_sizes, avoid_same=True)
        for g in groups:
            while len(g) < 4:
                g.append("X")
        groups = reorder_groups_to_push_byes_last(groups)
        qualify_per_group = 2
    else:
        random.shuffle(teams)
        groups = [teams[i:i + 2] for i in range(0, len(teams), 2)]
        for g in groups:
            while len(g) < 2:
                g.append("X")
        qualify_per_group = 1

    cur = db.execute(
        """
        INSERT INTO tournaments
        (name, owner_id, team_count, group_count, group_sizes_json, avoid_same, competition_type, qualify_per_group, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?)
        """,
        (
            new_name,
            user["id"],
            len(teams),
            len(groups),
            ",".join(str(len(g)) for g in groups),
            1,
            competition_type,
            qualify_per_group,
            now_str(),
        ),
    )
    new_tournament_id = cur.lastrowid

    for team in teams:
        db.execute(
            """
            INSERT INTO tournament_teams (tournament_id, display_name, base_name, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (new_tournament_id, team, get_base_name(team), now_str()),
        )

    create_round(new_tournament_id, 1, "รอบที่ 1", competition_type, groups)

    # ทำเครื่องหมายว่าเคยถูกนำไปใช้แล้ว แต่ยังคงอยู่ในคลังและเลือกซ้ำได้
    used_ids = [str(r["id"]) for r in allowed_rows]
    if used_ids:
        used_placeholders = ",".join("?" * len(used_ids))
        db.execute(
            f"UPDATE team_pool SET status = 'used' WHERE id IN ({used_placeholders})",
            used_ids,
        )

    db.commit()
    emit_tournament_reload(tournament_id, reason='create_from_pool')
    flash("สร้างทัวร์นาเมนต์ใหม่จากทีมตกรอบสำเร็จ", "success")
    return redirect(url_for("view_tournament", tournament_id=new_tournament_id))


@app.route("/tournaments/<int:tournament_id>/delete", methods=["POST"])
@login_required
def delete_tournament(tournament_id):
    tournament = get_tournament_for_user(tournament_id, current_user())
    if not tournament:
        flash("ไม่พบทัวร์นาเมนต์หรือคุณไม่มีสิทธิ์ลบ", "error")
        return redirect(url_for("dashboard"))

    db = get_db()
    if table_exists(db, "manual_group_rankings"):
        db.execute("DELETE FROM manual_group_rankings WHERE round_id IN (SELECT id FROM tournament_rounds WHERE tournament_id = ?)", (tournament_id,))
    db.execute("DELETE FROM round_scores WHERE round_id IN (SELECT id FROM tournament_rounds WHERE tournament_id = ?)", (tournament_id,))
    db.execute("DELETE FROM round_slots WHERE round_id IN (SELECT id FROM tournament_rounds WHERE tournament_id = ?)", (tournament_id,))
    db.execute("DELETE FROM tournament_rounds WHERE tournament_id = ?", (tournament_id,))
    db.execute("DELETE FROM eliminated_teams WHERE tournament_id = ?", (tournament_id,))
    db.execute("DELETE FROM team_pool WHERE tournament_id = ?", (tournament_id,))
    db.execute("DELETE FROM tournament_teams WHERE tournament_id = ?", (tournament_id,))
    db.execute("DELETE FROM tournaments WHERE id = ?", (tournament_id,))
    db.commit()
    emit_tournament_reload(tournament_id, reason='delete_tournament')

    flash("ลบทัวร์นาเมนต์แล้ว", "success")
    return redirect(url_for("dashboard"))


# ------------------------- bulk events: นำเข้าจาก Excel / สร้างหลายอีเวนต์ / ส่งออก Excel -------------------------
DEFAULT_RIGHT_LOGO = os.path.join(BASE_DIR, "static", "tbf_logo.png")
BULK_DEFAULT_OFF_CATEGORIES = {"ชู้ตติ้ง"}
AVOID_MODES = {
    "province": "แยกทีมจังหวัดเดียวกัน",
    "org": "แยกทีมหน่วยงานเดียวกัน",
    "none": "สุ่มอิสระ",
}


def preview_group_count(team_count, competition_type):
    if competition_type == "knockout":
        return max(1, math.ceil(team_count / 2)) if team_count >= 2 else None
    if team_count < 3:
        return None
    return calculate_group_count(team_count)


def draw_first_round(team_names, competition_type, manual_group_count=None, avoid_same=True, key_func=None, secondary_key_func=None):
    """จับสลากรอบแรก (ตรรกะเดียวกับหน้าสร้างทัวร์นาเมนต์) คืน (groups, qualify_per_group)"""
    if competition_type == "double_knockout":
        if len(team_names) < 3:
            raise ValueError("Double knockout ต้องมีอย่างน้อย 3 ทีม")
        group_sizes = calculate_group_sizes(len(team_names), manual_group_count)
        groups = smart_draw_groups(
            team_names, group_sizes, avoid_same=avoid_same,
            key_func=key_func, secondary_key_func=secondary_key_func,
        )
        for grp in groups:
            while len(grp) < 4:
                grp.append("X")
        return reorder_groups_to_push_byes_last(groups), 2

    if len(team_names) < 2:
        raise ValueError("ต้องมีอย่างน้อย 2 ทีม")
    group_count = manual_group_count or max(1, math.ceil(len(team_names) / 2))
    if group_count > len(team_names):
        raise ValueError("จำนวนสายมากกว่าจำนวนทีมไม่ได้")
    groups = smart_draw_groups(
        team_names, [2] * group_count, avoid_same=avoid_same,
        key_func=key_func, secondary_key_func=secondary_key_func,
    )
    for grp in groups:
        while len(grp) < 2:
            grp.append("X")
    return groups, 1


def make_avoid_key(avoid_mode, province_map):
    if avoid_mode == "province":
        return lambda name: (province_map.get(name) or "").strip() or get_base_name(name)
    return get_base_name


def make_secondary_avoid_key(avoid_mode, province_map):
    """เกณฑ์รองช่วยคละทั้งจังหวัดและหน่วยงานพร้อมกัน"""
    if avoid_mode == "province":
        return get_base_name
    if avoid_mode == "org":
        return lambda name: (province_map.get(name) or "").strip() or get_base_name(name)
    return get_base_name


def get_batch_for_user(batch_id, user):
    db = get_db()
    batch = db.execute("SELECT * FROM tournament_batches WHERE id = ?", (batch_id,)).fetchone()
    if not batch or not user:
        return None
    if user["role"] != "super_admin" and batch["owner_id"] != user["id"]:
        return None
    return batch


def get_draft_for_user(draft_id, user):
    row = get_db().execute("SELECT * FROM import_drafts WHERE id = ?", (draft_id,)).fetchone()
    if not row or (user["role"] != "super_admin" and row["owner_id"] != user["id"]):
        return None
    return row


def read_logo_upload(field_name):
    f = request.files.get(field_name)
    if not f or not f.filename:
        return None
    data = f.read()
    if not data or len(data) > 5 * 1024 * 1024:
        return None
    return data


def logo_sources_for_batch(batch):
    left = batch["left_logo"] if batch else None
    right = None
    if batch and batch["right_logo"]:
        right = batch["right_logo"]
    elif not batch or batch["use_default_right_logo"]:
        right = DEFAULT_RIGHT_LOGO
    return left, right


def tournament_has_scores(tournament_id):
    row = get_db().execute(
        """
        SELECT COUNT(*) AS n FROM round_scores
        WHERE score IS NOT NULL AND round_id IN (SELECT id FROM tournament_rounds WHERE tournament_id = ?)
        """,
        (tournament_id,),
    ).fetchone()
    return (row["n"] or 0) > 0


def tournament_mix_audit(tournament_id):
    """สรุปความถี่การซ้ำจังหวัด/หน่วยงานในสายของรอบแรก"""
    db = get_db()
    round_row = db.execute(
        "SELECT id FROM tournament_rounds WHERE tournament_id = ? ORDER BY round_no LIMIT 1",
        (tournament_id,),
    ).fetchone()
    if not round_row:
        return {"province_pairs": 0, "org_pairs": 0, "province_groups": 0, "org_groups": 0}
    teams = db.execute(
        "SELECT display_name, base_name, province FROM tournament_teams WHERE tournament_id = ?",
        (tournament_id,),
    ).fetchall()
    meta = {t["display_name"]: t for t in teams}
    slots = db.execute(
        "SELECT group_no, team_name FROM round_slots WHERE round_id = ? AND is_bye = 0 ORDER BY group_no, slot_no",
        (round_row["id"],),
    ).fetchall()
    by_group = defaultdict(list)
    for slot in slots:
        if slot["team_name"]:
            by_group[slot["group_no"]].append(slot["team_name"])

    def pair_count(values):
        return sum(n * (n - 1) // 2 for n in Counter(v for v in values if v).values())

    province_pairs = org_pairs = province_groups = org_groups = 0
    for names in by_group.values():
        provinces = [(meta.get(name)["province"] if meta.get(name) else "") or "" for name in names]
        orgs = [(meta.get(name)["base_name"] if meta.get(name) else get_base_name(name)) for name in names]
        pp, op = pair_count(provinces), pair_count(orgs)
        province_pairs += pp
        org_pairs += op
        province_groups += int(pp > 0)
        org_groups += int(op > 0)
    return {
        "province_pairs": province_pairs,
        "org_pairs": org_pairs,
        "province_groups": province_groups,
        "org_groups": org_groups,
    }


def build_export_event(tournament, rounds_mode="all"):
    """เตรียมข้อมูลของ 1 ทัวร์นาเมนต์สำหรับไฟล์ Excel ตารางแบ่งสาย"""
    db = get_db()
    round_views = get_round_views(tournament["id"])
    if rounds_mode == "first":
        round_views = round_views[:1]
    elif rounds_mode == "latest":
        round_views = round_views[-1:]

    title = tournament["event_label"] or tournament["name"]
    rounds = []
    for rv in round_views:
        rnd = rv["round"]
        label = "รอบแรก" if rnd["round_no"] == 1 else rnd["round_name"]
        # ใช้เฉพาะคะแนนที่กรอกจริง (ไม่เอาคะแนนอัตโนมัติจากบาย)
        entered = build_round_score_map(
            db.execute("SELECT * FROM round_scores WHERE round_id = ?", (rnd["id"],)).fetchall()
        )
        groups = []
        for gv in rv["group_views"]:
            slots_out = []
            slots = gv["slots"]
            for idx, slot in enumerate(slots):
                court = slot.get("court_name") if idx % 2 == 0 else None
                scores = [entered.get((gv["group_no"], slot["slot_no"], s)) for s in (1, 2, 3)]
                if slot.get("is_bye"):
                    scores = [None, None, None]
                slots_out.append({
                    "no": slot.get("display_slot_no"),
                    "name": slot.get("team_name") or slot.get("display_name"),
                    "court": court,
                    "scores": scores,
                })
            result = gv.get("result") or {}
            qualified = [
                (s.get("team_name") or s.get("display_name"))
                for s in (result.get("qualified") or [])
                if s
            ]
            groups.append({"group_no": gv["group_no"], "slots": slots_out, "qualified": qualified})
        rounds.append({"label": label, "round_type": rnd["round_type"], "groups": groups})

    # รายชื่อทีม + สาย/ลำดับจากรอบแรก
    first_pos = {}
    all_views = get_round_views(tournament["id"])
    if all_views:
        for gv in all_views[0]["group_views"]:
            for slot in gv["slots"]:
                if not slot.get("is_bye") and slot.get("team_name"):
                    first_pos[slot["team_name"]] = (gv["group_no"], slot.get("display_slot_no"))
    teams = []
    for t in db.execute(
        "SELECT * FROM tournament_teams WHERE tournament_id = ? ORDER BY id", (tournament["id"],)
    ).fetchall():
        keys = t.keys()
        grp_no, no = first_pos.get(t["display_name"], (None, None))
        teams.append({
            "display": t["display_name"],
            "name": (t["full_name"] if "full_name" in keys else None) or t["display_name"],
            "district": t["district"] if "district" in keys else "",
            "province": t["province"] if "province" in keys else "",
            "group_no": grp_no,
            "no": no,
        })
    teams.sort(key=lambda x: (x["no"] is None, x["no"] or 0))

    return {
        "title": title,
        "label": bulk_events.export_event_label(title),
        "rounds": rounds,
        "teams": teams,
    }


def excel_response(tournaments, subtitle, batch=None, rounds_mode="all", filename="ตารางแบ่งสาย.xlsx"):
    events = [build_export_event(t, rounds_mode) for t in tournaments]
    left, right = logo_sources_for_batch(batch)
    data = bulk_events.build_draw_workbook(events, subtitle or "", left_logo=left, right_logo=right)
    return send_file(
        data,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.route("/tournaments/import", methods=["GET", "POST"])
@login_required
def import_events():
    user = current_user()
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("กรุณาเลือกไฟล์ Excel", "error")
            return redirect(url_for("import_events"))
        try:
            sheets = bulk_events.read_workbook_rows(f.read(), f.filename)
            parsed = bulk_events.parse_events(sheets)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("import_events"))
        except Exception as e:  # ไฟล์เสีย / อ่านไม่ได้
            flash(f"อ่านไฟล์ไม่สำเร็จ: {e}", "error")
            return redirect(url_for("import_events"))

        if not parsed["events"]:
            flash("ไม่พบประเภทการแข่งขันในไฟล์ (ต้องมีแถวหัวข้อขึ้นต้นด้วย 'ประเภท...' ตามด้วยรายชื่อทีม)", "error")
            return redirect(url_for("import_events"))

        parsed["events"].sort(key=bulk_events.event_sort_key)
        db = get_db()
        cutoff = (now_dt() - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S")
        db.execute("DELETE FROM import_drafts WHERE created_at < ?", (cutoff,))
        cur = db.execute(
            "INSERT INTO import_drafts (owner_id, filename, payload_json, created_at) VALUES (?, ?, ?, ?)",
            (user["id"], f.filename, json.dumps(parsed, ensure_ascii=False), now_str()),
        )
        db.commit()
        return redirect(url_for("import_preview", draft_id=cur.lastrowid))

    batches = get_db().execute(
        """
        SELECT b.*, (SELECT COUNT(*) FROM tournaments t WHERE t.batch_id = b.id) AS event_count
        FROM tournament_batches b
        WHERE ? = 'super_admin' OR b.owner_id = ?
        ORDER BY b.id DESC
        """,
        (user["role"], user["id"]),
    ).fetchall()
    return render_template("import_events.html", batches=batches)


@app.route("/tournaments/import/<int:draft_id>")
@login_required
def import_preview(draft_id):
    user = current_user()
    draft = get_draft_for_user(draft_id, user)
    if not draft:
        flash("ไม่พบข้อมูลที่นำเข้า กรุณาอัปโหลดไฟล์ใหม่", "error")
        return redirect(url_for("import_events"))
    parsed = json.loads(draft["payload_json"])
    events = parsed["events"]
    for idx, ev in enumerate(events):
        ev["idx"] = idx
        n = len(ev["teams"])
        ev["groups_dk_auto"] = preview_group_count(n, "double_knockout")
        ev["groups_ko"] = preview_group_count(n, "knockout")
        suggested = ev.get("suggested_group_count")
        source = ev.get("group_count_source")
        if not suggested:
            suggested = bulk_events.default_group_count(ev)
            source = "summary" if suggested else None
        ev["group_count_note"] = None
        if suggested and valid_group_count(n, suggested):
            ev["suggested_group_count"] = suggested
            ev["group_count_source"] = source
        else:
            if suggested:
                ev["group_count_note"] = f"ไฟล์ระบุ {suggested} สาย แต่ไม่พอดีกับ {n} ทีม ระบบจึงใช้อัตโนมัติ"
            ev["suggested_group_count"] = None
            ev["group_count_source"] = None
        ev["groups_dk"] = ev["suggested_group_count"] or ev["groups_dk_auto"]
        ev["default_on"] = ev["category"] not in BULK_DEFAULT_OFF_CATEGORIES
    lines = parsed.get("title_lines") or []
    default_subtitle = " ".join(lines[:2]).strip()
    default_batch_name = (lines[1] if len(lines) > 1 else (lines[0] if lines else "")) or os.path.splitext(draft["filename"] or "")[0]
    categories = [c for c in bulk_events.CATEGORY_ORDER if any(e["category"] == c for e in events)]
    ages = sorted({e["age"] for e in events if e["age"]})
    create_ok, create_message = can_create_tournament(user)
    return render_template(
        "import_preview.html",
        draft=draft,
        events=events,
        categories=categories,
        ages=ages,
        default_subtitle=default_subtitle,
        default_batch_name=default_batch_name,
        title_lines=lines,
        avoid_modes=AVOID_MODES,
        create_ok=create_ok,
        create_message=create_message,
        quota=None if user["role"] == "super_admin" else user["create_quota"],
    )


@app.route("/tournaments/import/<int:draft_id>/create", methods=["POST"])
@login_required
def import_create(draft_id):
    user = current_user()
    draft = get_draft_for_user(draft_id, user)
    if not draft:
        flash("ไม่พบข้อมูลที่นำเข้า กรุณาอัปโหลดไฟล์ใหม่", "error")
        return redirect(url_for("import_events"))
    ok, message = can_create_tournament(user)
    if not ok:
        flash(message, "error")
        return redirect(url_for("import_preview", draft_id=draft_id))

    parsed = json.loads(draft["payload_json"])
    events = parsed["events"]
    selected = []
    selected_seen = set()
    for raw in request.form.getlist("events"):
        try:
            idx = int(raw)
        except ValueError:
            continue
        if 0 <= idx < len(events) and idx not in selected_seen:
            selected.append(idx)
            selected_seen.add(idx)
    if not selected:
        flash("กรุณาเลือกอย่างน้อย 1 ประเภท", "error")
        return redirect(url_for("import_preview", draft_id=draft_id))
    if user["role"] != "super_admin" and user["create_quota"] < len(selected):
        flash(f"โควตาสร้างทัวร์นาเมนต์เหลือ {user['create_quota']} รายการ แต่เลือกไว้ {len(selected)} รายการ", "error")
        return redirect(url_for("import_preview", draft_id=draft_id))

    competition_type = request.form.get("competition_type", "double_knockout")
    if competition_type not in {"double_knockout", "knockout"}:
        competition_type = "double_knockout"
    avoid_mode = request.form.get("avoid_mode", "province")
    if avoid_mode not in AVOID_MODES:
        avoid_mode = "province"
    abbreviate = request.form.get("abbreviate") == "on"
    batch_name = request.form.get("batch_name", "").strip() or (draft["filename"] or "ชุดการแข่งขัน")
    subtitle = request.form.get("subtitle", "").strip()
    name_prefix = request.form.get("name_prefix", "").strip()
    use_default_right = 1 if request.form.get("use_default_right_logo") == "on" else 0

    db = get_db()
    cur = db.execute(
        """
        INSERT INTO tournament_batches (name, subtitle, owner_id, left_logo, right_logo, use_default_right_logo, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (batch_name, subtitle, user["id"], read_logo_upload("left_logo"), read_logo_upload("right_logo"), use_default_right, now_str()),
    )
    batch_id = cur.lastrowid

    created, errors = 0, []
    for order, idx in enumerate(selected, start=1):
        ev = events[idx]
        prepared = bulk_events.prepare_team_names(ev["teams"], abbreviate=abbreviate)
        names = [p["display"] for p in prepared]
        province_map = {p["display"]: p.get("province") for p in prepared}
        manual_raw = request.form.get(f"group_count_{idx}", "").strip()
        try:
            manual_group_count = int(manual_raw) if manual_raw else None
            if manual_group_count is not None and manual_group_count <= 0:
                manual_group_count = None
            groups, qualify_per_group = draw_first_round(
                names,
                competition_type,
                manual_group_count,
                avoid_same=(avoid_mode != "none"),
                key_func=make_avoid_key(avoid_mode, province_map),
                secondary_key_func=make_secondary_avoid_key(avoid_mode, province_map),
            )
        except ValueError as e:
            errors.append(f"{ev['title']}: {e}")
            continue

        tname = f"{name_prefix} {ev['title']}".strip() if name_prefix else ev["title"]
        cur = db.execute(
            """
            INSERT INTO tournaments
            (name, owner_id, team_count, group_count, group_sizes_json, avoid_same, competition_type, qualify_per_group,
             status, created_at, batch_id, event_label, event_category, event_gender, event_age, sort_order)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tname, user["id"], len(names), len(groups), ",".join(str(len(x)) for x in groups),
                0 if avoid_mode == "none" else 1, competition_type, qualify_per_group, now_str(),
                batch_id, ev["title"], ev["category"], ev["gender"], ev["age"], order,
            ),
        )
        tournament_id = cur.lastrowid
        for p in prepared:
            db.execute(
                """
                INSERT INTO tournament_teams (tournament_id, display_name, base_name, created_at, full_name, district, province)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (tournament_id, p["display"], get_base_name(p["display"]), now_str(), p["name"], p.get("district"), p.get("province")),
            )
        create_round(tournament_id, 1, "รอบที่ 1", competition_type, groups)
        created += 1
    db.commit()
    for _ in range(created):
        consume_quota(user["id"])

    if created:
        flash(f"สร้างการแข่งขันสำเร็จ {created} ประเภท", "success")
    for err in errors:
        flash(f"สร้างไม่สำเร็จ – {err}", "error")
    if not created:
        db.execute("DELETE FROM tournament_batches WHERE id = ?", (batch_id,))
        db.commit()
        return redirect(url_for("import_preview", draft_id=draft_id))
    return redirect(url_for("view_batch", batch_id=batch_id))


def batch_tournaments(batch_id):
    return get_db().execute(
        """
        SELECT t.*, u.username AS owner_name,
               (SELECT COUNT(*) FROM tournament_rounds r WHERE r.tournament_id = t.id) AS round_count
        FROM tournaments t JOIN users u ON u.id = t.owner_id
        WHERE t.batch_id = ?
        ORDER BY COALESCE(t.sort_order, 9999), t.id
        """,
        (batch_id,),
    ).fetchall()


@app.route("/batches/<int:batch_id>")
@login_required
def view_batch(batch_id):
    user = current_user()
    batch = get_batch_for_user(batch_id, user)
    if not batch:
        flash("ไม่พบชุดการแข่งขัน", "error")
        return redirect(url_for("dashboard"))
    tournaments = batch_tournaments(batch_id)
    categories = [c for c in bulk_events.CATEGORY_ORDER if any((t["event_category"] or "อื่นๆ") == c for t in tournaments)]
    ages = sorted({t["event_age"] for t in tournaments if t["event_age"]})
    mix_audits = {t["id"]: tournament_mix_audit(t["id"]) for t in tournaments}
    return render_template(
        "batch_detail.html",
        batch=batch,
        tournaments=tournaments,
        categories=categories,
        ages=ages,
        avoid_modes=AVOID_MODES,
        mix_audits=mix_audits,
    )


def _selected_ids():
    ids = []
    for raw in request.values.getlist("ids"):
        for part in str(raw).split(","):
            if part.strip().isdigit():
                ids.append(int(part))
    return ids


@app.route("/batches/<int:batch_id>/export")
@login_required
def export_batch(batch_id):
    user = current_user()
    batch = get_batch_for_user(batch_id, user)
    if not batch:
        flash("ไม่พบชุดการแข่งขัน", "error")
        return redirect(url_for("dashboard"))
    tournaments = batch_tournaments(batch_id)
    ids = set(_selected_ids())
    if ids:
        tournaments = [t for t in tournaments if t["id"] in ids]
    if not tournaments:
        flash("กรุณาเลือกอย่างน้อย 1 ประเภท", "error")
        return redirect(url_for("view_batch", batch_id=batch_id))
    rounds_mode = request.args.get("rounds", "all")
    suffix = "" if len(tournaments) != 1 else f"_{tournaments[0]['event_label'] or tournaments[0]['name']}"
    filename = f"ตารางแบ่งสาย_{batch['name']}{suffix}.xlsx".replace("/", "-")
    return excel_response(tournaments, batch["subtitle"], batch=batch, rounds_mode=rounds_mode, filename=filename)


@app.route("/tournaments/<int:tournament_id>/export-excel")
def export_tournament_excel(tournament_id):
    db = get_db()
    tournament = db.execute("SELECT * FROM tournaments WHERE id = ?", (tournament_id,)).fetchone()
    if not tournament:
        flash("ไม่พบทัวร์นาเมนต์", "error")
        return redirect(url_for("home"))
    batch = None
    if tournament["batch_id"]:
        batch = db.execute("SELECT * FROM tournament_batches WHERE id = ?", (tournament["batch_id"],)).fetchone()
    subtitle = batch["subtitle"] if batch and batch["subtitle"] else tournament["name"]
    filename = f"ตารางแบ่งสาย_{tournament['name']}.xlsx".replace("/", "-")
    return excel_response([tournament], subtitle, batch=batch, rounds_mode=request.args.get("rounds", "all"), filename=filename)


@app.route("/batches/<int:batch_id>/update", methods=["POST"])
@login_required
def update_batch(batch_id):
    user = current_user()
    batch = get_batch_for_user(batch_id, user)
    if not batch:
        flash("ไม่พบชุดการแข่งขัน", "error")
        return redirect(url_for("dashboard"))
    db = get_db()
    name = request.form.get("name", "").strip() or batch["name"]
    subtitle = request.form.get("subtitle", "").strip()
    use_default_right = 1 if request.form.get("use_default_right_logo") == "on" else 0
    left = read_logo_upload("left_logo")
    right = read_logo_upload("right_logo")
    left_value = None if request.form.get("remove_left_logo") == "on" else (left or batch["left_logo"])
    right_value = None if request.form.get("remove_right_logo") == "on" else (right or batch["right_logo"])
    db.execute(
        "UPDATE tournament_batches SET name = ?, subtitle = ?, left_logo = ?, right_logo = ?, use_default_right_logo = ? WHERE id = ?",
        (name, subtitle, left_value, right_value, use_default_right, batch_id),
    )
    db.commit()
    flash("บันทึกข้อมูลชุดการแข่งขันแล้ว", "success")
    return redirect(url_for("view_batch", batch_id=batch_id))


@app.route("/batches/<int:batch_id>/redraw", methods=["POST"])
@login_required
def redraw_batch(batch_id):
    """จับสลากรอบแรกใหม่ เฉพาะประเภทที่ยังไม่มีการกรอกคะแนนและยังไม่สร้างรอบถัดไป"""
    user = current_user()
    batch = get_batch_for_user(batch_id, user)
    if not batch:
        flash("ไม่พบชุดการแข่งขัน", "error")
        return redirect(url_for("dashboard"))
    ids = set(_selected_ids())
    avoid_mode = request.form.get("avoid_mode", "province")
    if avoid_mode not in AVOID_MODES:
        avoid_mode = "province"
    db = get_db()
    done, skipped = 0, []
    for t in batch_tournaments(batch_id):
        if t["id"] not in ids:
            continue
        if t["round_count"] > 1 or tournament_has_scores(t["id"]):
            skipped.append(t["name"])
            continue
        teams = db.execute("SELECT * FROM tournament_teams WHERE tournament_id = ? ORDER BY id", (t["id"],)).fetchall()
        names = [row["display_name"] for row in teams]
        province_map = {row["display_name"]: row["province"] for row in teams}
        manual = t["group_count"] if (t["competition_type"] == "knockout" or valid_group_count(len(names), t["group_count"])) else None
        try:
            groups, _ = draw_first_round(
                names, t["competition_type"], manual,
                avoid_same=(avoid_mode != "none"),
                key_func=make_avoid_key(avoid_mode, province_map),
                secondary_key_func=make_secondary_avoid_key(avoid_mode, province_map),
            )
        except ValueError as e:
            skipped.append(f"{t['name']} ({e})")
            continue
        round_ids = [r["id"] for r in db.execute("SELECT id FROM tournament_rounds WHERE tournament_id = ?", (t["id"],)).fetchall()]
        for rid in round_ids:
            db.execute("DELETE FROM manual_group_rankings WHERE round_id = ?", (rid,))
            db.execute("DELETE FROM round_scores WHERE round_id = ?", (rid,))
            db.execute("DELETE FROM round_slots WHERE round_id = ?", (rid,))
        db.execute("DELETE FROM tournament_rounds WHERE tournament_id = ?", (t["id"],))
        db.execute("DELETE FROM eliminated_teams WHERE tournament_id = ?", (t["id"],))
        create_round(t["id"], 1, "รอบที่ 1", t["competition_type"], groups)
        db.execute(
            "UPDATE tournaments SET group_count = ?, group_sizes_json = ? WHERE id = ?",
            (len(groups), ",".join(str(len(x)) for x in groups), t["id"]),
        )
        done += 1
    db.commit()
    for t in batch_tournaments(batch_id):
        if t["id"] in ids:
            emit_tournament_reload(t["id"], reason="redraw")
    if done:
        flash(f"จับสลากใหม่แล้ว {done} ประเภท", "success")
    if skipped:
        flash("ข้าม (มีคะแนนหรือมีรอบถัดไปแล้ว): " + ", ".join(skipped), "error")
    if not done and not skipped:
        flash("กรุณาเลือกอย่างน้อย 1 ประเภท", "error")
    return redirect(url_for("view_batch", batch_id=batch_id))


def delete_tournament_data(db, tournament_id):
    if table_exists(db, "manual_group_rankings"):
        db.execute("DELETE FROM manual_group_rankings WHERE round_id IN (SELECT id FROM tournament_rounds WHERE tournament_id = ?)", (tournament_id,))
    db.execute("DELETE FROM round_scores WHERE round_id IN (SELECT id FROM tournament_rounds WHERE tournament_id = ?)", (tournament_id,))
    db.execute("DELETE FROM round_slots WHERE round_id IN (SELECT id FROM tournament_rounds WHERE tournament_id = ?)", (tournament_id,))
    db.execute("DELETE FROM tournament_rounds WHERE tournament_id = ?", (tournament_id,))
    db.execute("DELETE FROM eliminated_teams WHERE tournament_id = ?", (tournament_id,))
    db.execute("DELETE FROM team_pool WHERE tournament_id = ?", (tournament_id,))
    db.execute("DELETE FROM tournament_teams WHERE tournament_id = ?", (tournament_id,))
    db.execute("DELETE FROM tournaments WHERE id = ?", (tournament_id,))


@app.route("/batches/<int:batch_id>/delete-selected", methods=["POST"])
@login_required
def delete_batch_selected(batch_id):
    user = current_user()
    batch = get_batch_for_user(batch_id, user)
    if not batch:
        flash("ไม่พบชุดการแข่งขัน", "error")
        return redirect(url_for("dashboard"))
    ids = set(_selected_ids())
    db = get_db()
    removed = 0
    for t in batch_tournaments(batch_id):
        if t["id"] in ids:
            delete_tournament_data(db, t["id"])
            removed += 1
    remaining = db.execute("SELECT COUNT(*) AS n FROM tournaments WHERE batch_id = ?", (batch_id,)).fetchone()["n"]
    if request.form.get("delete_batch") == "1" and remaining == 0:
        db.execute("DELETE FROM tournament_batches WHERE id = ?", (batch_id,))
        db.commit()
        flash(f"ลบชุดการแข่งขันแล้ว ({removed} ประเภท)", "success")
        return redirect(url_for("dashboard"))
    db.commit()
    for tid in ids:
        emit_tournament_reload(tid, reason="delete_tournament")
    flash(f"ลบแล้ว {removed} ประเภท", "success")
    return redirect(url_for("view_batch", batch_id=batch_id))


@app.route("/init-db")
def init_db_route():
    init_db()
    return "Database initialized. Default super admin: dekchairukna / yagami125"



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8002))
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
