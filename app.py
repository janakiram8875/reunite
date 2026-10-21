import json
import os
from datetime import datetime
from pathlib import Path

import mysql.connector
from flask import Flask, jsonify, request, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("FINDIT_SECRET_KEY", "change-this-secret-key-before-deployment")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

DB_CONFIG = {
    "host": os.environ.get("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.environ.get("MYSQL_PORT", "3306")),
    "user": os.environ.get("MYSQL_USER", "root"),
    "password": os.environ.get("MYSQL_PASSWORD", ""),
    "database": os.environ.get("MYSQL_DATABASE", "findit_campus"),
}


def db_connection():
    return mysql.connector.connect(**DB_CONFIG)


def init_db():
    # Database itself must exist first; create it in phpMyAdmin using schema.sql.
    conn = db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS findit_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(120) NOT NULL,
            email VARCHAR(190) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS findit_items (
            id VARCHAR(80) PRIMARY KEY,
            owner_id INT NOT NULL,
            item_type VARCHAR(20) NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'active',
            data LONGTEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_items_owner (owner_id),
            INDEX idx_items_type_status (item_type, status),
            CONSTRAINT fk_findit_item_owner FOREIGN KEY (owner_id) REFERENCES findit_users(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS findit_notifications (
            id VARCHAR(100) PRIMARY KEY,
            from_user_id INT NOT NULL,
            to_user_id INT NOT NULL,
            data LONGTEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_notifications_to (to_user_id),
            INDEX idx_notifications_from (from_user_id),
            CONSTRAINT fk_findit_notification_from FOREIGN KEY (from_user_id) REFERENCES findit_users(id),
            CONSTRAINT fk_findit_notification_to FOREIGN KEY (to_user_id) REFERENCES findit_users(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    conn.commit()
    cur.close()
    conn.close()


def current_user_id():
    return session.get("user_id")


def public_user(row):
    return {"id": row[0], "name": row[1], "email": row[2], "createdAt": str(row[3]) if row[3] else None}


def require_login():
    if not current_user_id():
        return jsonify({"error": "Please login first."}), 401
    return None


@app.get("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/api/me")
def api_me():
    uid = current_user_id()
    if not uid:
        return jsonify({"user": None})
    conn = db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, created_at FROM findit_users WHERE id=%s", (uid,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        session.clear()
        return jsonify({"user": None})
    return jsonify({"user": public_user(row)})


@app.post("/api/register")
def api_register():
    body = request.get_json(silent=True) or {}
    name = str(body.get("name", "")).strip()
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    if not name or not email or len(password) < 6:
        return jsonify({"error": "Please enter a name, valid email, and password with at least 6 characters."}), 400
    try:
        conn = db_connection(); cur = conn.cursor()
        cur.execute("INSERT INTO findit_users (name,email,password_hash) VALUES (%s,%s,%s)",
                    (name, email, generate_password_hash(password)))
        conn.commit()
        cur.close(); conn.close()
        return jsonify({"message": "Registration successful."}), 201
    except mysql.connector.IntegrityError:
        return jsonify({"error": "Email already registered. Please login."}), 409
    except mysql.connector.Error as exc:
        app.logger.exception("Registration database error")
        return jsonify({"error": "Database error during registration. Check MySQL is running and database setup is complete."}), 500


@app.post("/api/login")
def api_login():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    conn = db_connection(); cur = conn.cursor()
    cur.execute("SELECT id,name,email,password_hash,created_at FROM findit_users WHERE email=%s", (email,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row or not check_password_hash(row[3], password):
        return jsonify({"error": "Invalid email or password."}), 401
    session.clear()
    session["user_id"] = row[0]
    return jsonify({"user": {"id": row[0], "name": row[1], "email": row[2], "createdAt": str(row[4]) if row[4] else None}})


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify({"message": "Logged out."})


@app.get("/api/items")
def api_items():
    denied = require_login()
    if denied: return denied
    conn = db_connection(); cur = conn.cursor()
    cur.execute("SELECT data FROM findit_items ORDER BY created_at DESC")
    rows = cur.fetchall()
    cur.close(); conn.close()
    result = []
    for row in rows:
        try: result.append(json.loads(row[0]))
        except (TypeError, json.JSONDecodeError): continue
    return jsonify({"items": result})


def item_is_editable(cur, item_id, uid, item_data):
    cur.execute("SELECT owner_id, data FROM findit_items WHERE id=%s", (item_id,))
    row = cur.fetchone()
    if not row:
        return str(item_data.get("reporterId")) == str(uid)
    if int(row[0]) == int(uid):
        return True
    # Permit updating the other half of a matched pair only when it is linked
    # to one of this user's own records. This supports the existing match/receive UI.
    cur.execute("SELECT data FROM findit_items WHERE owner_id=%s", (uid,))
    for own_row in cur.fetchall():
        try:
            own = json.loads(own_row[0])
            if str(own.get("matchedItemId")) == str(item_id) or str(item_data.get("matchedItemId")) == str(own.get("id")):
                return True
        except (TypeError, json.JSONDecodeError):
            pass
    return False


@app.post("/api/items/sync")
def api_items_sync():
    denied = require_login()
    if denied: return denied
    uid = current_user_id()
    body = request.get_json(silent=True) or {}
    incoming = body.get("items", [])
    if not isinstance(incoming, list):
        return jsonify({"error": "Items must be sent as a list."}), 400
    conn = db_connection(); cur = conn.cursor()
    synced = 0
    try:
        for item in incoming:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            item_id = str(item["id"])
            if not item_is_editable(cur, item_id, uid, item):
                continue
            # A new item always belongs to the authenticated account.
            cur.execute("SELECT owner_id FROM findit_items WHERE id=%s", (item_id,))
            existing = cur.fetchone()
            if existing:
                owner_id = int(existing[0])
            else:
                if str(item.get("reporterId")) != str(uid):
                    continue
                owner_id = uid
                item["reporterId"] = uid
            item_type = str(item.get("type", "lost"))[:20]
            status = str(item.get("status", "active"))[:30]
            cur.execute("""
                INSERT INTO findit_items (id,owner_id,item_type,status,data)
                VALUES (%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE item_type=VALUES(item_type), status=VALUES(status), data=VALUES(data)
            """, (item_id, owner_id, item_type, status, json.dumps(item, ensure_ascii=False)))
            synced += 1
        conn.commit()
    except Exception:
        conn.rollback()
        app.logger.exception("Item sync error")
        cur.close(); conn.close()
        return jsonify({"error": "Could not save item changes to MySQL."}), 500
    cur.close(); conn.close()
    return jsonify({"message": "Items synced.", "synced": synced})


@app.get("/api/notifications")
def api_notifications():
    denied = require_login()
    if denied: return denied
    uid = current_user_id()
    conn = db_connection(); cur = conn.cursor()
    cur.execute("SELECT data FROM findit_notifications WHERE from_user_id=%s OR to_user_id=%s ORDER BY created_at", (uid, uid))
    rows = cur.fetchall()
    cur.close(); conn.close()
    result = []
    for row in rows:
        try: result.append(json.loads(row[0]))
        except (TypeError, json.JSONDecodeError): continue
    return jsonify({"notifications": result})


@app.post("/api/notifications/sync")
def api_notifications_sync():
    denied = require_login()
    if denied: return denied
    uid = current_user_id()
    body = request.get_json(silent=True) or {}
    incoming = body.get("notifications", [])
    if not isinstance(incoming, list):
        return jsonify({"error": "Notifications must be sent as a list."}), 400
    conn = db_connection(); cur = conn.cursor()
    synced = 0
    try:
        for note in incoming:
            if not isinstance(note, dict) or not note.get("id"):
                continue
            note_id = str(note["id"])
            cur.execute("SELECT from_user_id,to_user_id FROM findit_notifications WHERE id=%s", (note_id,))
            existing = cur.fetchone()
            if existing:
                if uid not in (int(existing[0]), int(existing[1])):
                    continue
                from_id, to_id = int(existing[0]), int(existing[1])
            else:
                if str(note.get("fromUserId")) != str(uid):
                    continue
                try:
                    from_id, to_id = int(note.get("fromUserId")), int(note.get("toUserId"))
                except (TypeError, ValueError):
                    continue
            cur.execute("""
                INSERT INTO findit_notifications (id,from_user_id,to_user_id,data)
                VALUES (%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE data=VALUES(data), from_user_id=VALUES(from_user_id), to_user_id=VALUES(to_user_id)
            """, (note_id, from_id, to_id, json.dumps(note, ensure_ascii=False)))
            synced += 1
        conn.commit()
    except Exception:
        conn.rollback()
        app.logger.exception("Notification sync error")
        cur.close(); conn.close()
        return jsonify({"error": "Could not save notification changes to MySQL."}), 500
    cur.close(); conn.close()
    return jsonify({"message": "Notifications synced.", "synced": synced})


if __name__ == "__main__":
    try:
        init_db()
    except mysql.connector.Error as exc:
        print("\nMySQL connection/setup failed:", exc)
        print("Start MySQL in XAMPP, create the findit_campus database using schema.sql, then run app.py again.\n")
        raise
    app.run(host="127.0.0.1", port=5000, debug=True)
