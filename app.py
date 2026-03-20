import math
import os
import random
import re
import sqlite3
from collections import defaultdict
from datetime import datetime
from functools import wraps

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "tournament.db")

app = Flask(__name__)
app.secret_key = "change-this-secret-key"


# ------------------------- database -------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
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
            status TEXT NOT NULL DEFAULT 'pool',
            created_at TEXT NOT NULL,
            UNIQUE(tournament_id, team_name),
            FOREIGN KEY(tournament_id) REFERENCES tournaments(id)
        );
        """
    )
    db.commit()
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
def get_base_name(team_name):
    cleaned = re.sub(r"\s+", " ", team_name.strip())
    cleaned = re.sub(r"[0-9]+$", "", cleaned)
    cleaned = re.sub(r"[\-–_]+$", "", cleaned).strip()
    return cleaned.lower() or team_name.strip().lower()


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


def smart_draw_groups(team_names, group_sizes, avoid_same=True):
    teams = [t.strip() for t in team_names if t.strip()]
    random.shuffle(teams)

    if avoid_same:
        base_map = defaultdict(list)
        for team in teams:
            base_map[get_base_name(team)].append(team)

        ordered = []
        base_keys = sorted(base_map.keys(), key=lambda k: len(base_map[k]), reverse=True)
        max_len = max(len(v) for v in base_map.values()) if base_map else 0
        for i in range(max_len):
            for key in base_keys:
                if i < len(base_map[key]):
                    ordered.append(base_map[key][i])
        teams = ordered

    groups = [[] for _ in group_sizes]
    capacities = list(group_sizes)

    for team in teams:
        placed = False
        preferred_order = list(range(len(groups)))
        random.shuffle(preferred_order)

        if avoid_same:
            preferred_order.sort(
                key=lambda gi: any(get_base_name(team) == get_base_name(existing) for existing in groups[gi])
            )

        for gi in preferred_order:
            if len(groups[gi]) >= capacities[gi]:
                continue
            if avoid_same and any(get_base_name(team) == get_base_name(existing) for existing in groups[gi]):
                continue
            groups[gi].append(team)
            placed = True
            break

        if not placed:
            for gi in preferred_order:
                if len(groups[gi]) < capacities[gi]:
                    groups[gi].append(team)
                    placed = True
                    break

        if not placed:
            raise ValueError("ไม่สามารถจัดสายได้ กรุณาลองใหม่")

    return groups


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


def compute_group_results(round_type, slots, score_map):
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
            grouped[slot["group_no"]].append(slot)

        scores = db.execute(
            "SELECT * FROM round_scores WHERE round_id = ?",
            (rnd["id"],),
        ).fetchall()
        base_score_map = build_round_score_map(scores)

        group_views = []
        merged_score_map = dict(base_score_map)

        for group_no, group_slots in grouped.items():
            local_score_map = apply_bye_auto_scores(rnd["round_type"], group_slots, dict(base_score_map))
            merged_score_map.update(local_score_map)

            res = compute_group_results(rnd["round_type"], group_slots, local_score_map)
            stage_state = build_stage_locks(rnd["round_type"], group_slots, local_score_map)

            group_views.append({
                "group_no": group_no,
                "slots": group_slots,
                "result": res,
                "stage_state": stage_state,
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

            source_text = f"ทัวร์นาเมนต์ {tournament_id} / รอบ {round_no} / สาย {group_no}"

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
                (tournament_id, team_name, source_text, status, created_at)
                VALUES (?, ?, ?, 'pool', ?)
                """,
                (tournament_id, team_name, source_text, now_str()),
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
        fill_value = 4
        group_count = manual_group_count if manual_group_count and manual_group_count > 0 else max(1, math.ceil(len(names_for_draw) / 4))
        group_sizes = [4] * group_count
    else:
        fill_value = 2
        group_count = manual_group_count if manual_group_count and manual_group_count > 0 else max(1, math.ceil(len(names_for_draw) / 2))
        group_sizes = [2] * group_count

    random_groups = smart_draw_groups(names_for_draw, group_sizes, avoid_same=separate_same)

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


# ------------------------- template globals -------------------------
@app.context_processor
def inject_user():
    return {
        "current_user": current_user(),
        "competition_type_label": competition_type_label,
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
    return render_template("dashboard.html", tournaments=tournaments, create_ok=create_ok, create_message=create_message)


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
        manual_group_count = int(manual_group_count_raw) if manual_group_count_raw else None
        teams = [line.strip() for line in teams_text.splitlines() if line.strip()]

        if not name:
            flash("กรุณากรอกชื่อทัวร์นาเมนต์", "error")
            return render_template("create_tournament.html")
        if len(teams) < 2:
            flash("ต้องมีอย่างน้อย 2 ทีม", "error")
            return render_template("create_tournament.html")

        if competition_type == "double_knockout":
            if len(teams) < 3:
                flash("Double knockout ต้องมีอย่างน้อย 3 ทีม", "error")
                return render_template("create_tournament.html")
            group_sizes = calculate_group_sizes(len(teams), manual_group_count)
            groups = smart_draw_groups(teams, group_sizes, avoid_same=bool(avoid_same))
            for g in groups:
                while len(g) < 4:
                    g.append("X")
            qualify_per_group = 2
        else:
            shuffled = teams[:]
            random.shuffle(shuffled)
            groups = [shuffled[i:i + 2] for i in range(0, len(shuffled), 2)]
            for g in groups:
                while len(g) < 2:
                    g.append("X")
            qualify_per_group = 1

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
    return render_template(
        "tournament_detail.html",
        tournament=tournament,
        round_views=round_views,
        can_manage=can_manage,
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

    if not slot_id or not group_no or not stage_no:
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

    score_rows = db.execute(
        "SELECT * FROM round_scores WHERE round_id = ? AND group_no = ?",
        (round_id, int(group_no)),
    ).fetchall()
    score_map = build_round_score_map(score_rows)

    stage_no_int = int(stage_no)

    stage_states = build_stage_locks(round_row["round_type"], slots, score_map)
    current_state = stage_states.get(slot["slot_no"], {}).get(stage_no_int, {"locked": False})

    if current_state.get("locked"):
        return {"ok": False, "message": "ช่องนี้ถูกล็อกแล้ว"}, 400

    if not stage_is_editable(round_row["round_type"], slots, stage_no_int, slot["slot_no"], score_map):
        return {"ok": False, "message": "ยังไม่ถึงรอบของช่องนี้"}, 400

    db.execute(
        "UPDATE round_slots SET court_name = ? WHERE id = ?",
        (court_name or None, slot["id"]),
    )

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

    db.commit()
    return {"ok": True}


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

    flash("ประมวลผลรอบนี้แล้ว", "success")
    return redirect(url_for("view_tournament", tournament_id=round_row["tournament_id"]) + f"#round-{round_row['round_no']}-group-{group_no}")


@app.route("/tournaments/<int:tournament_id>/next-round", methods=["POST"])
@login_required
def create_next_round(tournament_id):
    tournament = get_tournament_for_user(tournament_id, current_user())
    if not tournament:
        flash("ไม่พบทัวร์นาเมนต์หรือคุณไม่มีสิทธิ์จัดการ", "error")
        return redirect(url_for("dashboard"))

    source_round_id = int(request.form.get("source_round_id"))
    target_round_type = request.form.get("round_type", "double_knockout").strip()
    if target_round_type not in {"double_knockout", "knockout"}:
        target_round_type = "double_knockout"

    manual_group_count_raw = request.form.get("next_group_count", "").strip()
    manual_group_count = int(manual_group_count_raw) if manual_group_count_raw else None
    separate_same = True if request.form.get("separate_same") == "1" else False

    round_views = get_round_views(tournament_id)
    source_view = next((rv for rv in round_views if rv["round"]["id"] == source_round_id), None)
    if not source_view:
        flash("ไม่พบรอบต้นทาง", "error")
        return redirect(url_for("view_tournament", tournament_id=tournament_id))

    sync_eliminated_for_round(tournament_id, source_view["round"]["round_no"], source_view)
    collect_eliminated_from_round(tournament_id, source_view)

    round_id, round_no = create_next_round_from_round_view(
        tournament=tournament,
        round_view=source_view,
        target_round_type=target_round_type,
        manual_group_count=manual_group_count,
        separate_same=separate_same,
    )

    flash(f"สร้างรอบถัดไปสำเร็จ (รอบที่ {round_no})", "success")
    return redirect(url_for("view_tournament", tournament_id=tournament_id) + f"#saved-round-{round_id}")


@app.route("/tournaments/<int:tournament_id>/eliminated")
@login_required
def eliminated_pool(tournament_id):
    tournament = get_tournament_for_user(tournament_id, current_user())
    if not tournament:
        flash("ไม่พบทัวร์นาเมนต์หรือคุณไม่มีสิทธิ์จัดการ", "error")
        return redirect(url_for("dashboard"))

    rows = get_db().execute(
        """
        SELECT * FROM team_pool
        WHERE tournament_id = ? AND status = 'pool'
        ORDER BY id DESC
        """,
        (tournament_id,),
    ).fetchall()

    return render_template("eliminated_pool.html", tournament=tournament, eliminated_rows=rows)


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
        INSERT INTO team_pool (tournament_id, team_name, source_text, status, created_at)
        VALUES (?, ?, ?, 'pool', ?)
        """,
        (tournament_id, team_name, "เพิ่มเองโดยผู้ดูแล", now_str()),
    )
    db.commit()

    flash("เพิ่มทีมเข้าคลังแล้ว", "success")
    return redirect(url_for("eliminated_pool", tournament_id=tournament_id))


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
        SELECT * FROM team_pool
        WHERE tournament_id = ? AND id IN ({placeholders}) AND status = 'pool'
        ORDER BY id
        """,
        [tournament_id] + selected_ids,
    ).fetchall()

    teams = [r["team_name"] for r in rows]
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

    db.execute(
        f"""
        UPDATE team_pool
        SET status = 'used'
        WHERE tournament_id = ? AND id IN ({placeholders})
        """,
        [tournament_id] + selected_ids,
    )
    db.commit()
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
    db.execute("DELETE FROM round_scores WHERE round_id IN (SELECT id FROM tournament_rounds WHERE tournament_id = ?)", (tournament_id,))
    db.execute("DELETE FROM round_slots WHERE round_id IN (SELECT id FROM tournament_rounds WHERE tournament_id = ?)", (tournament_id,))
    db.execute("DELETE FROM tournament_rounds WHERE tournament_id = ?", (tournament_id,))
    db.execute("DELETE FROM eliminated_teams WHERE tournament_id = ?", (tournament_id,))
    db.execute("DELETE FROM team_pool WHERE tournament_id = ?", (tournament_id,))
    db.execute("DELETE FROM tournament_teams WHERE tournament_id = ?", (tournament_id,))
    db.execute("DELETE FROM tournaments WHERE id = ?", (tournament_id,))
    db.commit()

    flash("ลบทัวร์นาเมนต์แล้ว", "success")
    return redirect(url_for("dashboard"))


@app.route("/init-db")
def init_db_route():
    init_db()
    return "Database initialized. Default super admin: dekchairukna / yagami1225"



if __name__ == "__main__":
    with app.app_context():
        init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
