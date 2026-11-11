import warnings
warnings.filterwarnings("ignore")
import argparse, os, re, secrets, socket, sqlite3, threading, time, uuid, json
from collections import defaultdict, deque
from functools import wraps
from flask import Flask, Response, g, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "social.db"))
UPLOAD_FOLDER = os.path.join(BASE, "uploads")
APP_NAME = "VSI"
SLOGAN = "Твой код оживляет мечты"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def load_secret_key():
    key = os.environ.get("SECRET_KEY")
    if key: return key
    path = os.path.join(os.path.dirname(DB_PATH), ".secret_key")
    if os.path.exists(path):
        with open(path) as f: return f.read().strip()
    key = secrets.token_hex(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f: f.write(key)
    return key

app = Flask(__name__, static_folder=None)
app.config.update(SECRET_KEY=load_secret_key(), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=60*60*24*30, MAX_CONTENT_LENGTH=64*1024*1024, UPLOAD_FOLDER=UPLOAD_FOLDER)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, username_lower TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, bio TEXT NOT NULL DEFAULT '', theme TEXT DEFAULT 'dark', volume INTEGER DEFAULT 50, created INTEGER NOT NULL, last_seen INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS user_photos (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, photo_url TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, text TEXT NOT NULL, image_url TEXT DEFAULT '', created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS likes (user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE, PRIMARY KEY (user_id, post_id));
CREATE TABLE IF NOT EXISTS post_reactions (user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE, sticker TEXT NOT NULL, PRIMARY KEY (user_id, post_id));
CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, text TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, msg_type TEXT NOT NULL DEFAULT 'text', content TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS friends (user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, friend_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created INTEGER NOT NULL, PRIMARY KEY (user_id, friend_id));
CREATE TABLE IF NOT EXISTS calls (id INTEGER PRIMARY KEY AUTOINCREMENT, caller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, status TEXT NOT NULL DEFAULT 'ringing', is_video INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stories (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, media_url TEXT NOT NULL, created INTEGER NOT NULL);
"""

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None: db.close()

def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    try:
        con.execute("PRAGMA journal_mode = WAL")
        con.executescript(SCHEMA)
        cols = {r[1] for r in con.execute("PRAGMA table_info(users)").fetchall()}
        if "theme" not in cols: con.execute("ALTER TABLE users ADD COLUMN theme TEXT DEFAULT 'dark'")
        if "volume" not in cols: con.execute("ALTER TABLE users ADD COLUMN volume INTEGER DEFAULT 50")
        con.commit()
    finally:
        con.close()

_hits = defaultdict(deque)
_hits_lock = threading.Lock()

def rate_limited(key, limit, per_seconds):
    now = time.time()
    with _hits_lock:
        q = _hits[key]
        while q and now - q[0] > per_seconds: q.popleft()
        if len(q) >= limit: return True
        q.append(now)
        return False

def err(msg, code=400):
    return jsonify(error=msg), code

@app.before_request
def update_last_seen():
    if request.path.startswith("/api/") and not request.path.startswith("/api/me"):
        uid = session.get("uid")
        if uid:
            try:
                db = get_db()
                db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (int(time.time()), uid))
                db.commit()
            except Exception: pass
    if request.path.startswith("/api/") and request.method in ("POST", "PUT", "DELETE"):
        if request.headers.get("X-Requested-With") != "XMLHttpRequest":
            return err("Запрещено", 403)

def current_user():
    uid = session.get("uid")
    if not uid: return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        user = current_user()
        if not user: return err("Нужно войти", 401)
        g.user = user
        return fn(*a, **kw)
    return wrapper

def json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}

USERNAME_RE = re.compile(r"^[A-Za-z0-9_А-Яа-яЁё]{3,20}$")

def user_dict(row):
    return {"id": row["id"], "username": row["username"], "bio": row["bio"], "last_seen": row["last_seen"], "theme": row["theme"], "volume": row["volume"]}

@app.get("/api/me")
def api_me():
    user = current_user()
    return jsonify(user=user_dict(user) if user else None)

@app.post("/api/settings")
@login_required
def api_save_settings():
    data = json_body()
    theme = str(data.get("theme", "dark"))
    vol = int(data.get("volume", 50))
    db = get_db()
    db.execute("UPDATE users SET theme = ?, volume = ? WHERE id = ?", (theme, vol, g.user["id"]))
    db.commit()
    return jsonify(user=user_dict(db.execute("SELECT * FROM users WHERE id = ?", (g.user["id"],)).fetchone()))

@app.post("/api/register")
def api_register():
    if rate_limited(("reg", request.remote_addr), 5, 3600): return err("Слишком много регистраций", 429)
    data = json_body()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    if not USERNAME_RE.match(username): return err("Имя: 3–20 символов, буквы, цифры и _")
    if len(password) < 6: return err("Пароль от 6 символов")
    db = get_db()
    try:
        cur = db.execute("INSERT INTO users (username, username_lower, password_hash, created, last_seen) VALUES (?, ?, ?, ?, ?)", (username, username.lower(), generate_password_hash(password), int(time.time()), int(time.time())))
        db.commit()
    except sqlite3.IntegrityError: return err("Имя занято")
    session.clear()
    session.permanent = True
    session["uid"] = cur.lastrowid
    return jsonify(user=user_dict(current_user()))

@app.post("/api/login")
def api_login():
    if rate_limited(("login", request.remote_addr), 10, 300): return err("Слишком много попыток", 429)
    data = json_body()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    row = get_db().execute("SELECT * FROM users WHERE username_lower = ?", (username.lower(),)).fetchone()
    if not row or not check_password_hash(row["password_hash"], password): return err("Неверное имя или пароль", 401)
    session.clear()
    session.permanent = True
    session["uid"] = row["id"]
    return jsonify(user=user_dict(row))

@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify(ok=True)

@app.post("/api/me/update")
@login_required
def api_update_profile():
    data = json_body()
    new_bio = str(data.get("bio", g.user["bio"])).strip()[:200]
    new_username = str(data.get("username", g.user["username"])).strip()
    new_pass = str(data.get("password", "")).strip()
    if not USERNAME_RE.match(new_username): return err("Некорректное имя")
    db = get_db()
    try:
        db.execute("UPDATE users SET bio = ?, username = ?, username_lower = ? WHERE id = ?", (new_bio, new_username, new_username.lower(), g.user["id"]))
        if new_pass:
            if len(new_pass) < 6: return err("Пароль от 6 символов")
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_pass), g.user["id"]))
        db.commit()
    except sqlite3.IntegrityError:
        return err("Это имя уже занято")
    return jsonify(user=user_dict(db.execute("SELECT * FROM users WHERE id = ?", (g.user["id"],)).fetchone()))

@app.post("/api/photos")
@login_required
def api_add_photo():
    url = str(json_body().get("url", "")).strip()
    if not url: return err("Нет URL")
    db = get_db()
    db.execute("INSERT INTO user_photos (user_id, photo_url) VALUES (?, ?)", (g.user["id"], url))
    db.commit()
    return jsonify(ok=True)

@app.delete("/api/photos/<int:photo_id>")
@login_required
def api_del_photo(photo_id):
    db = get_db()
    db.execute("DELETE FROM user_photos WHERE id = ? AND user_id = ?", (photo_id, g.user["id"]))
    db.commit()
    return jsonify(ok=True)

@app.get("/api/users/<username>/photos")
@login_required
def api_user_photos(username):
    db = get_db()
    u = db.execute("SELECT id FROM users WHERE username_lower = ?", (username.lower(),)).fetchone()
    if not u: return err("Не найден", 404)
    rows = db.execute("SELECT id, photo_url FROM user_photos WHERE user_id = ?", (u["id"],)).fetchall()
    return jsonify(photos=[dict(r) for r in rows])

@app.get("/api/friends")
@login_required
def api_friends():
    rows = get_db().execute("SELECT u.id, u.username, u.bio, u.last_seen FROM friends f JOIN users u ON u.id = f.friend_id WHERE f.user_id = ? ORDER BY u.username", (g.user["id"],)).fetchall()
    return jsonify(friends=[user_dict(r) for r in rows])

@app.post("/api/friends/<username>")
@login_required
def api_friend_add(username):
    db = get_db()
    other = db.execute("SELECT id FROM users WHERE username_lower = ?", (username.lower(),)).fetchone()
    if not other: return err("Пользователь не найден", 404)
    if other["id"] == g.user["id"]: return err("Нельзя добавить себя")
    try:
        db.execute("INSERT INTO friends (user_id, friend_id, created) VALUES (?, ?, ?)", (g.user["id"], other["id"], int(time.time())))
        db.execute("INSERT INTO friends (user_id, friend_id, created) VALUES (?, ?, ?)", (other["id"], g.user["id"], int(time.time())))
        db.commit()
    except sqlite3.IntegrityError: pass
    return jsonify(ok=True)

@app.delete("/api/friends/<username>")
@login_required
def api_friend_delete(username):
    db = get_db()
    other = db.execute("SELECT id FROM users WHERE username_lower = ?", (username.lower(),)).fetchone()
    if not other: return err("Пользователь не найден", 404)
    db.execute("DELETE FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)", (g.user["id"], other["id"], other["id"], g.user["id"]))
    db.commit()
    return jsonify(ok=True)

@app.get("/api/stories")
@login_required
def api_stories():
    cutoff = int(time.time()) - 86400
    db = get_db()
    db.execute("DELETE FROM stories WHERE created < ?", (cutoff,))
    db.commit()
    rows = db.execute("SELECT s.id, s.media_url, s.created, u.username FROM stories s JOIN users u ON u.id = s.user_id WHERE s.created > ? ORDER BY s.created DESC", (cutoff,)).fetchall()
    grouped = {}
    for r in rows:
        if r["username"] not in grouped: grouped[r["username"]] = []
        grouped[r["username"]].append({"id": r["id"], "media_url": r["media_url"], "created": r["created"]})
    return jsonify(stories=[{"username": u, "items": items} for u, items in grouped.items()])

@app.post("/api/stories")
@login_required
def api_story_add():
    media_url = str(json_body().get("media_url", "")).strip()
    if not media_url: return err("Нет медиа")
    db = get_db()
    db.execute("INSERT INTO stories (user_id, media_url, created) VALUES (?, ?, ?)", (g.user["id"], media_url, int(time.time())))
    db.commit()
    return jsonify(ok=True)

POST_SELECT = """
SELECT p.id, p.text, p.image_url, p.created, u.username,
       (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS likes,
       (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comments,
       EXISTS(SELECT 1 FROM likes l WHERE l.post_id = p.id AND l.user_id = :me) AS liked,
       (SELECT sticker FROM post_reactions r WHERE r.post_id = p.id AND r.user_id = :me) AS my_reaction
FROM posts p JOIN users u ON u.id = p.user_id
"""

def post_dict(row, me_name):
    db = get_db()
    reactions = db.execute("SELECT r.sticker, u.username FROM post_reactions r JOIN users u ON u.id = r.user_id WHERE r.post_id = ?", (row["id"],)).fetchall()
    reaction_list = [{"sticker": r["sticker"], "username": r["username"]} for r in reactions]
    reaction_counts = {}
    for r in reaction_list: reaction_counts[r["sticker"]] = reaction_counts.get(r["sticker"], 0) + 1
    return {"id": row["id"], "text": row["text"], "image_url": row["image_url"], "created": row["created"], "username": row["username"], "likes": row["likes"], "comments": row["comments"], "liked": bool(row["liked"]), "mine": row["username"] == me_name, "my_reaction": row["my_reaction"], "reactions": reaction_list, "reaction_counts": reaction_counts}

@app.get("/api/posts")
@login_required
def api_posts():
    username = request.args.get("user", "").strip()
    before = request.args.get("before", type=int) or 2**62
    sql = POST_SELECT + " WHERE p.id < :before"
    params = {"me": g.user["id"], "before": before}
    if username:
        sql += " AND u.username = :uname"
        params["uname"] = username
    sql += " ORDER BY p.id DESC LIMIT 21"
    rows = get_db().execute(sql, params).fetchall()
    return jsonify(posts=[post_dict(r, g.user["username"]) for r in rows[:20]], more=len(rows) > 20)

@app.post("/api/posts")
@login_required
def api_post_create():
    if rate_limited(("post", g.user["id"]), 20, 600): return err("Не так быстро", 429)
    data = json_body()
    text = str(data.get("text", "")).strip()
    image_url = str(data.get("image_url", "")).strip()
    if not text and not image_url: return err("Напиши что-нибудь или прикрепи фото")
    if len(text) > 1000: return err("Максимум 1000 символов")
    db = get_db()
    cur = db.execute("INSERT INTO posts (user_id, text, image_url, created) VALUES (?, ?, ?, ?)", (g.user["id"], text, image_url, int(time.time())))
    db.commit()
    row = db.execute(POST_SELECT + " WHERE p.id = :id", {"me": g.user["id"], "id": cur.lastrowid}).fetchone()
    return jsonify(post=post_dict(row, g.user["username"]))

@app.delete("/api/posts/<int:post_id>")
@login_required
def api_post_delete(post_id):
    db = get_db()
    cur = db.execute("DELETE FROM posts WHERE id = ? AND user_id = ?", (post_id, g.user["id"]))
    db.commit()
    return jsonify(ok=True) if cur.rowcount else err("Пост не найден", 404)

@app.post("/api/posts/<int:post_id>/like")
@login_required
def api_like(post_id):
    db = get_db()
    if not db.execute("SELECT 1 FROM posts WHERE id = ?", (post_id,)).fetchone(): return err("Пост не найден", 404)
    cur = db.execute("DELETE FROM likes WHERE user_id = ? AND post_id = ?", (g.user["id"], post_id))
    liked = cur.rowcount == 0
    if liked: db.execute("INSERT OR IGNORE INTO likes (user_id, post_id) VALUES (?, ?)", (g.user["id"], post_id))
    db.commit()
    n = db.execute("SELECT COUNT(*) FROM likes WHERE post_id = ?", (post_id,)).fetchone()[0]
    return jsonify(liked=liked, likes=n)

@app.post("/api/posts/<int:post_id>/react")
@login_required
def api_post_react(post_id):
    db = get_db()
    if not db.execute("SELECT 1 FROM posts WHERE id = ?", (post_id,)).fetchone(): return err("Пост не найден", 404)
    sticker = str(json_body().get("sticker", "")).strip()
    if not sticker: return err("Нет стикера")
    cur = db.execute("SELECT sticker FROM post_reactions WHERE user_id = ? AND post_id = ?", (g.user["id"], post_id)).fetchone()
    if cur and cur["sticker"] == sticker:
        db.execute("DELETE FROM post_reactions WHERE user_id = ? AND post_id = ?", (g.user["id"], post_id))
    else:
        db.execute("INSERT OR REPLACE INTO post_reactions (user_id, post_id, sticker) VALUES (?, ?, ?)", (g.user["id"], post_id, sticker))
    db.commit()
    row = db.execute(POST_SELECT + " WHERE p.id = :id", {"me": g.user["id"], "id": post_id}).fetchone()
    return jsonify(post=post_dict(row, g.user["username"]))

@app.get("/api/posts/<int:post_id>/comments")
@login_required
def api_comments(post_id):
    rows = get_db().execute("SELECT c.id, c.text, c.created, u.username FROM comments c JOIN users u ON u.id = c.user_id WHERE c.post_id = ? ORDER BY c.id LIMIT 200", (post_id,)).fetchall()
    return jsonify(comments=[{**dict(r), "mine": r["username"] == g.user["username"]} for r in rows])

@app.post("/api/posts/<int:post_id>/comments")
@login_required
def api_comment_create(post_id):
    if rate_limited(("comment", g.user["id"]), 30, 600): return err("Не так быстро", 429)
    text = str(json_body().get("text", "")).strip()
    if not text: return err("Пустой комментарий")
    if len(text) > 500: return err("Максимум 500 символов")
    db = get_db()
    if not db.execute("SELECT 1 FROM posts WHERE id = ?", (post_id,)).fetchone(): return err("Пост не найден", 404)
    created = int(time.time())
    cur = db.execute("INSERT INTO comments (post_id, user_id, text, created) VALUES (?, ?, ?, ?)", (post_id, g.user["id"], text, created))
    db.commit()
    return jsonify(comment={"id": cur.lastrowid, "text": text, "created": created, "username": g.user["username"], "mine": True})

@app.delete("/api/comments/<int:comment_id>")
@login_required
def api_comment_delete(comment_id):
    db = get_db()
    cur = db.execute("DELETE FROM comments WHERE id = ? AND user_id = ?", (comment_id, g.user["id"]))
    db.commit()
    return jsonify(ok=True) if cur.rowcount else err("Комментарий не найден", 404)

@app.get("/api/users")
@login_required
def api_users():
    q = request.args.get("q", "").strip()[:30]
    like = "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    rows = get_db().execute("SELECT id, username, bio, created, last_seen FROM users WHERE username_lower LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT 50", (like,)).fetchall()
    db = get_db()
    friends = {r["friend_id"] for r in db.execute("SELECT friend_id FROM friends WHERE user_id = ?", (g.user["id"],)).fetchall()}
    res = []
    for r in rows:
        if r["id"] == g.user["id"]: continue
        d = user_dict(r)
        d["is_friend"] = r["id"] in friends
        res.append(d)
    return jsonify(users=res)

@app.get("/api/users/<username>")
@login_required
def api_user(username):
    db = get_db()
    row = db.execute("SELECT id, username, bio, created, last_seen FROM users WHERE username_lower = ?", (username.lower(),)).fetchone()
    if not row: return err("Пользователь не найден", 404)
    n = db.execute("SELECT COUNT(*) FROM posts WHERE user_id = ?", (row["id"],)).fetchone()[0]
    is_friend = bool(db.execute("SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ?", (g.user["id"], row["id"])).fetchone())
    return jsonify(user={**user_dict(row), "posts": n, "is_friend": is_friend})

@app.get("/api/dialogs")
@login_required
def api_dialogs():
    rows = get_db().execute("""
        SELECT u.username, u.id, u.last_seen,
               (SELECT content FROM messages m WHERE (m.sender_id = u.id AND m.receiver_id = :me) OR (m.sender_id = :me AND m.receiver_id = u.id) ORDER BY m.id DESC LIMIT 1) as last_msg,
               (SELECT created FROM messages m WHERE (m.sender_id = u.id AND m.receiver_id = :me) OR (m.sender_id = :me AND m.receiver_id = u.id) ORDER BY m.id DESC LIMIT 1) as last_time
        FROM users u WHERE u.id IN (SELECT DISTINCT sender_id FROM messages WHERE receiver_id = :me UNION SELECT DISTINCT receiver_id FROM messages WHERE sender_id = :me) ORDER BY last_time DESC
    """, {"me": g.user["id"]}).fetchall()
    return jsonify(dialogs=[dict(r) for r in rows])

@app.get("/api/messages/<username>")
@login_required
def api_messages_get(username):
    db = get_db()
    other = db.execute("SELECT id, username, last_seen FROM users WHERE username_lower = ?", (username.lower(),)).fetchone()
    if not other: return err("Пользователь не найден", 404)
    msgs = db.execute("""
        SELECT m.*, u.username as sender_name FROM messages m JOIN users u ON u.id = m.sender_id
        WHERE (m.sender_id = :me AND m.receiver_id = :other) OR (m.sender_id = :other AND m.receiver_id = :me)
        ORDER BY m.id ASC LIMIT 100
    """, {"me": g.user["id"], "other": other["id"]}).fetchall()
    return jsonify(messages=[dict(m) for m in msgs], other_user=dict(other))

@app.post("/api/messages/<username>")
@login_required
def api_messages_send(username):
    if rate_limited(("msg", g.user["id"]), 30, 60): return err("Не так быстро", 429)
    db = get_db()
    other = db.execute("SELECT id FROM users WHERE username_lower = ?", (username.lower(),)).fetchone()
    if not other: return err("Пользователь не найден", 404)
    data = json_body()
    msg_type = data.get("type", "text")
    content = str(data.get("content", "")).strip()
    if not content: return err("Пустое сообщение")
    created = int(time.time())
    cur = db.execute("INSERT INTO messages (sender_id, receiver_id, msg_type, content, created) VALUES (?, ?, ?, ?, ?)", (g.user["id"], other["id"], msg_type, content, created))
    db.commit()
    return jsonify(message={"id": cur.lastrowid, "sender_id": g.user["id"], "receiver_id": other["id"], "msg_type": msg_type, "content": content, "created": created, "sender_name": g.user["username"]})

@app.post("/api/upload")
@login_required
def api_upload():
    if "file" not in request.files: return err("Нет файла")
    file = request.files["file"]
    if file.filename == "": return err("Пустое имя файла")
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in [".jpg", ".jpeg", ".png", ".gif", ".mp4", ".webm"]: return err("Только jpg, png, gif, mp4, webm")
    filename = f"{uuid.uuid4().hex}{ext}"
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return jsonify(url=f"/uploads/{filename}")

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.get("/api/poll")
@login_required
def api_poll():
    db = get_db()
    incoming = db.execute("SELECT c.*, u.username as caller_name FROM calls c JOIN users u ON u.id = c.caller_id WHERE c.receiver_id = ? AND c.status = 'ringing' ORDER BY c.id DESC LIMIT 1", (g.user["id"],)).fetchone()
    outgoing = db.execute("SELECT c.*, u.username as receiver_name FROM calls c JOIN users u ON u.id = c.receiver_id WHERE c.caller_id = ? AND c.status IN ('ringing', 'accepted') ORDER BY c.id DESC LIMIT 1", (g.user["id"],)).fetchone()
    return jsonify(incoming=dict(incoming) if incoming else None, outgoing=dict(outgoing) if outgoing else None)

@app.post("/api/call/start/<username>")
@login_required
def api_call_start(username):
    db = get_db()
    other = db.execute("SELECT id FROM users WHERE username_lower = ?", (username.lower(),)).fetchone()
    if not other: return err("Пользователь не найден", 404)
    is_video = 1 if json_body().get("video") else 0
    db.execute("UPDATE calls SET status = 'ended' WHERE caller_id = ? AND status = 'ringing'", (g.user["id"],))
    cur = db.execute("INSERT INTO calls (caller_id, receiver_id, status, is_video, created) VALUES (?, ?, 'ringing', ?, ?)", (g.user["id"], other["id"], is_video, int(time.time())))
    db.commit()
    return jsonify(call_id=cur.lastrowid)

@app.post("/api/call/accept/<int:call_id>")
@login_required
def api_call_accept(call_id):
    db = get_db()
    db.execute("UPDATE calls SET status = 'accepted' WHERE id = ? AND receiver_id = ?", (call_id, g.user["id"]))
    db.commit()
    return jsonify(ok=True)

@app.post("/api/call/reject/<int:call_id>")
@login_required
def api_call_reject(call_id):
    db = get_db()
    db.execute("UPDATE calls SET status = 'rejected' WHERE id = ? AND receiver_id = ?", (call_id, g.user["id"]))
    db.commit()
    return jsonify(ok=True)

@app.post("/api/call/end/<int:call_id>")
@login_required
def api_call_end(call_id):
    db = get_db()
    db.execute("UPDATE calls SET status = 'ended' WHERE id = ? AND (caller_id = ? OR receiver_id = ?)", (call_id, g.user["id"], g.user["id"]))
    db.commit()
    return jsonify(ok=True)

@app.post("/api/webrtc/signal")
@login_required
def api_webrtc_signal():
    data = json_body()
    db = get_db()
    db.execute("INSERT INTO messages (sender_id, receiver_id, msg_type, content, created) VALUES (?, 0, 'webrtc', ?, ?)", (g.user["id"], f"{data.get('call_id')}::{json.dumps(data.get('signal'))}", int(time.time())))
    db.commit()
    return jsonify(ok=True)

@app.get("/api/webrtc/signals/<int:call_id>")
@login_required
def api_webrtc_signals(call_id):
    db = get_db()
    call = db.execute("SELECT caller_id, receiver_id FROM calls WHERE id = ?", (call_id,)).fetchone()
    if not call: return err("Звонок не найден", 404)
    other_id = call["receiver_id"] if call["caller_id"] == g.user["id"] else call["caller_id"]
    rows = db.execute("SELECT content FROM messages WHERE sender_id = ? AND msg_type = 'webrtc' AND content LIKE ?", (other_id, f"{call_id}::%")).fetchall()
    signals = []
    for r in rows:
        try: signals.append(json.loads(r["content"].split("::", 1)[1]))
        except: pass
    db.execute("DELETE FROM messages WHERE sender_id = ? AND msg_type = 'webrtc' AND content LIKE ?", (other_id, f"{call_id}::%"))
    db.commit()
    return jsonify(signals=signals)

INDEX_HTML = r"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<title>VSI</title>
<link rel="icon" href="/logo.jpg">
<style>
:root{
  --bg:#0a0614; --card:#1a1033; --card2:#241547; --line:#3a2666;
  --gold:#facc15; --text:#f4f4f9; --danger:#f87171; --online:#22c55e;
}
[data-theme="light"] {
  --bg:#f3f4f6; --card:#ffffff; --card2:#f9fafb; --line:#e5e7eb;
  --gold:#d97706; --text:#111827; --danger:#dc2626;
}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;background:var(--bg);color:var(--text);font-family:sans-serif;display:flex;flex-direction:column;height:100vh;overflow:hidden;transition:0.3s}
a{color:var(--gold);text-decoration:none}
button{font-family:inherit;cursor:pointer}
input,textarea{font-family:inherit;color:var(--text);background:var(--card2);border:1px solid var(--line);border-radius:10px;padding:10px;width:100%;outline:none}
.btn{background:var(--gold);color:black;border:none;border-radius:10px;padding:10px 15px;font-weight:bold}
.btn.ghost{background:transparent;color:var(--text);border:1px solid var(--line)}
.top{display:flex;align-items:center;justify-content:space-between;padding:10px 20px;background:var(--card);border-bottom:1px solid var(--line);z-index:10;position:relative}
.brand{font-size:20px;font-weight:bold;color:var(--gold);letter-spacing:2px}
.menu-btn{display:none;background:none;border:none;color:var(--gold);font-size:24px;cursor:pointer;padding:0 10px}
.layout{display:flex;flex:1;overflow:hidden;position:relative}
.side{width:240px;background:var(--card);border-right:1px solid var(--line);padding:15px;display:flex;flex-direction:column;overflow-y:auto;transition:0.3s}
.main{flex:1;overflow-y:auto;padding:20px;display:flex;flex-direction:column;align-items:center}
.wrap{width:100%;max-width:600px}
.card{background:var(--card);border:1px solid var(--line);border-radius:15px;padding:15px;margin-bottom:15px;box-shadow:0 4px 6px rgba(0,0,0,0.1)}
.avatar{width:40px;height:40px;border-radius:50%;background:linear-gradient(135deg,var(--gold),#a855f7);display:inline-flex;align-items:center;justify-content:center;font-weight:bold;color:black;position:relative;flex:none}
.status-dot{position:absolute;bottom:0;right:0;width:12px;height:12px;border-radius:50%;border:2px solid var(--card)}
.online{background:var(--online)}.offline{background:gray}
.nav-btn{display:block;padding:10px;margin-bottom:5px;border-radius:10px;color:var(--text);text-align:left;background:transparent;border:none;font-size:16px;width:100%}
.nav-btn:hover{background:var(--card2);color:var(--gold)}
.post-text{white-space:pre-wrap;margin-bottom:10px}
.post-img{max-width:100%;border-radius:10px;margin-bottom:10px}
.acts{display:flex;gap:10px;border-top:1px solid var(--line);padding-top:10px;margin-top:10px}
.act{background:transparent;border:none;color:gray;cursor:pointer;flex:1;font-size:14px}
.act.on{color:var(--gold);font-weight:bold}
.chat-layout{display:flex;flex-direction:column;height:100%}
.messages{flex:1;overflow-y:auto;padding:10px;display:flex;flex-direction:column;gap:10px}
.msg{max-width:80%;padding:10px;border-radius:12px;word-wrap:break-word}
.msg.me{align-self:flex-end;background:#a855f7;color:white}
.msg.them{align-self:flex-start;background:var(--card2)}
.msg-img{max-width:100%;border-radius:10px;margin-top:5px}
.call-overlay{position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.95);z-index:1000;display:none;flex-direction:column;align-items:center;justify-content:center}
.call-box{width:90%;max-width:800px;aspect-ratio:16/9;background:black;border:2px solid var(--gold);border-radius:15px;position:relative;overflow:hidden}
video{width:100%;height:100%;object-fit:cover}
#localVid{position:absolute;bottom:10px;right:10px;width:30%;max-width:150px;border:2px solid white;border-radius:10px}
.sidebar-overlay{display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.5);z-index:50}
.gallery-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(100px,1fr));gap:10px;margin-top:10px}
.gallery-grid img{width:100%;aspect-ratio:1;object-fit:cover;border-radius:10px;cursor:pointer}

@media(max-width:900px){
  .menu-btn{display:block}
  .layout{flex-direction:column}
  .side{position:fixed;top:0;left:-240px;height:100vh;z-index:60;padding-top:60px}
  .side.open{left:0}
  .sidebar-overlay.open{display:block}
  .top{padding:10px}
  .main{padding:10px; padding-bottom:80px}
  .wrap{max-width:100%}
}
</style>
</head>
<body>
<div id="root"></div>
<script>
let me = null, usersCache = [], postsCache = [], storiesCache = [];
let currentCallId = null, peerConnection = null, localStream = null;
let pollInt = null, rtcInt = null, pendingCandidates = [], remoteSet = false;
let ringInterval = null, audioCtx = null;
const STICKERS = ['❤️','😂','🔥','👍','😢'];
const servers = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

async function api(path, method='GET', body) {
  const r = await fetch('/api' + path, {method, headers:{'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'}, body: body?JSON.stringify(body):undefined});
  const data = await r.json();
  if(!r.ok) throw new Error(data.error||'Ошибка');
  return data;
}
function el(tag, cls='', html='') { const e=document.createElement(tag); if(cls)e.className=cls; if(html)e.innerHTML=html; return e; }

function initAudio() { if(!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)(); }
function playRingTone() {
  initAudio();
  if(audioCtx.state === 'suspended') audioCtx.resume();
  const osc = audioCtx.createOscillator(), gain = audioCtx.createGain();
  osc.type = 'sine'; osc.frequency.setValueAtTime(800, audioCtx.currentTime); osc.frequency.setValueAtTime(600, audioCtx.currentTime + 0.2);
  gain.gain.setValueAtTime(0, audioCtx.currentTime);
  gain.gain.linearRampToValueAtTime((me.volume/100)*0.2, audioCtx.currentTime + 0.1);
  gain.gain.linearRampToValueAtTime(0, audioCtx.currentTime + 0.4);
  osc.connect(gain); gain.connect(audioCtx.destination); osc.start(); osc.stop(audioCtx.currentTime + 0.4);
}
function startRing() { if(ringInterval) return; playRingTone(); ringInterval = setInterval(playRingTone, 1500); }
function stopRing() { if(ringInterval) { clearInterval(ringInterval); ringInterval = null; } }

async function start() {
  try {
    const res = await api('/me');
    if(res.user) { me=res.user; applyTheme(); renderApp(); } else { renderAuth(); }
  } catch(e) { renderAuth(); }
}
function applyTheme() { document.documentElement.setAttribute('data-theme', me.theme || 'dark'); }

function renderAuth() {
  const root = document.getElementById('root');
  root.innerHTML = `
    <div style="display:flex;height:100vh;align-items:center;justify-content:center">
      <div class="card" style="width:350px;text-align:center">
        <h2 style="color:var(--gold)">VSI</h2>
        <input id="au" placeholder="Имя" style="margin-bottom:10px">
        <input id="ap" type="password" placeholder="Пароль" style="margin-bottom:10px">
        <button class="btn" onclick="doLogin()" style="width:100%;margin-bottom:5px">Войти</button>
        <button class="btn ghost" onclick="doReg()" style="width:100%">Регистрация</button>
      </div>
    </div>`;
}
async function doLogin() {
  try { const r=await api('/login','POST',{username:document.getElementById('au').value,password:document.getElementById('ap').value}); me=r.user; applyTheme(); renderApp(); } catch(e){alert(e.message)}
}
async function doReg() {
  try { const r=await api('/register','POST',{username:document.getElementById('au').value,password:document.getElementById('ap').value}); me=r.user; applyTheme(); renderApp(); } catch(e){alert(e.message)}
}

function renderApp() {
  const root = document.getElementById('root');
  root.innerHTML = `
    <div class="top">
      <div style="display:flex;align-items:center;gap:10px">
        <button class="menu-btn" onclick="toggleMenu()">☰</button>
        <div class="brand">VSI</div>
      </div>
      <button class="btn ghost" onclick="doLogout()">Выйти</button>
    </div>
    <div class="layout">
      <div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleMenu()"></div>
      <div class="side" id="sidebar">
        <button class="nav-btn" onclick="route('#/')">🏠 Лента</button>
        <button class="nav-btn" onclick="route('#/people')">🔍 Люди</button>
        <button class="nav-btn" onclick="route('#/chats')">💬 Сообщения</button>
        <button class="nav-btn" onclick="route('#/friends')">👥 Друзья</button>
        <button class="nav-btn" onclick="route('#/profile/'+me.username)">👤 Мой профиль</button>
        <button class="nav-btn" onclick="route('#/settings')">⚙️ Настройки</button>
      </div>
      <div class="main"><div class="wrap" id="main-content"></div></div>
    </div>
    <div class="call-overlay" id="callUI">
      <div class="call-box" id="callBox"><video id="remoteVid" autoplay playsinline></video><video id="localVid" autoplay playsinline muted></video></div>
      <h3 id="callStatus" style="margin-top:15px">Звонок...</h3>
      <div style="margin-top:20px;display:flex;gap:20px">
        <button class="btn" style="border-radius:50%;width:60px;height:60px;background:var(--danger);color:white;font-size:24px;padding:0" onclick="endCall()">📵</button>
        <button class="btn" id="acceptBtn" style="border-radius:50%;width:60px;height:60px;background:#22c55e;color:white;font-size:24px;padding:0;display:none" onclick="acceptCall()">✅</button>
      </div>
    </div>`;
  window.onhashchange = () => route(location.hash);
  route(location.hash || '#/');
  setInterval(pollEvents, 2000);
}

function toggleMenu() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebarOverlay').classList.toggle('open');
}

async function doLogout() { await api('/logout','POST'); location.reload(); }

async function route(hash) {
  if(window.innerWidth <= 900) {
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebarOverlay').classList.remove('open');
  }
  if(hash.startsWith('#/profile/')) return renderProfile(decodeURIComponent(hash.split('/')[2]));
  if(hash === '#/people') return renderPeople();
  if(hash === '#/chats') return renderChats();
  if(hash.startsWith('#/chat/')) return renderChat(decodeURIComponent(hash.split('/')[2]));
  if(hash === '#/friends') return renderFriends();
  if(hash === '#/settings') return renderSettings();
  renderFeed();
}

async function renderSettings() {
  const mc = document.getElementById('main-content');
  mc.innerHTML = `
    <h2>Настройки</h2>
    <div class="card">
      <h3>Громкость звонка</h3>
      <input type="range" min="0" max="100" value="${me.volume}" id="volRange" oninput="document.getElementById('volVal').textContent=this.value+'%'">
      <div id="volVal" style="text-align:right">${me.volume}%</div>
    </div>
    <div class="card">
      <h3>Тема интерфейса</h3>
      <select id="themeSelect">
        <option value="dark" ${me.theme==='dark'?'selected':''}>Тёмная (космос)</option>
        <option value="light" ${me.theme==='light'?'selected':''}>Светлая</option>
      </select>
    </div>
    <button class="btn" onclick="saveSettings()" style="width:100%">Сохранить</button>
  `;
}
async function saveSettings() {
  const v = document.getElementById('volRange').value;
  const t = document.getElementById('themeSelect').value;
  const r = await api('/settings', 'POST', { volume: v, theme: t });
  me = r.user;
  applyTheme();
  alert('Настройки сохранены!');
}

async function renderPeople() {
  const mc = document.getElementById('main-content');
  mc.innerHTML = `<h2>Поиск людей</h2><input id="searchInput" placeholder="Введи имя..." onkeyup="filterPeople()" style="margin-bottom:15px"><div id="peopleList"></div>`;
  const r = await api('/users?q=');
  usersCache = r.users;
  renderPeopleList(usersCache);
}
function filterPeople() {
  const q = document.getElementById('searchInput').value.toLowerCase();
  renderPeopleList(usersCache.filter(u => u.username.toLowerCase().includes(q)));
}
function renderPeopleList(list) {
  const pl = document.getElementById('peopleList');
  pl.innerHTML = '';
  list.forEach(u => {
    const div = document.createElement('div');
    div.className = 'card';
    div.style.display = 'flex'; div.style.justifyContent = 'space-between'; div.style.alignItems = 'center';
    div.innerHTML = `<div><b style="color:var(--gold);cursor:pointer" onclick="route('#/profile/${u.username}')">${u.username}</b><div style="font-size:12px;color:gray">${u.bio||'Нет описания'}</div></div>
      <button class="btn ${u.is_friend?'ghost':''}" onclick="toggleFriend('${u.username}', ${u.is_friend}, true)">${u.is_friend?'Удалить':'Добавить'}</button>`;
    pl.appendChild(div);
  });
}

async function renderFeed() {
  const mc = document.getElementById('main-content');
  mc.innerHTML = `<div class="card"><textarea id="postText" rows="3" placeholder="Что нового?"></textarea><div style="margin-top:10px;display:flex;justify-content:space-between"><input type="file" id="postFile" accept="image/*" style="width:auto"><button class="btn" onclick="createPost()">Опубликовать</button></div></div><div id="feed"></div>`;
  try {
    const [p, s] = await Promise.all([api('/posts'), api('/stories')]);
    postsCache = p.posts; storiesCache = s.stories;
    if(storiesCache.length) {
      const sBar = el('div','card','<div style="display:flex;gap:10px;overflow-x:auto">' + storiesCache.map(st => `<div style="text-align:center;cursor:pointer" onclick="viewStory('${st.username}',0)"><div class="avatar" style="width:60px;height:60px;font-size:24px;border:3px solid var(--gold)">${st.username[0]}</div><div style="font-size:12px;margin-top:5px">${st.username}</div></div>`).join('') + '</div>');
      document.getElementById('feed').appendChild(sBar);
    }
    postsCache.forEach(p => {
      const c = el('div','card');
      c.innerHTML = `<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px"><div class="avatar">${p.username[0]}</div><div><div style="font-weight:bold;color:var(--gold);cursor:pointer" onclick="route('#/profile/${p.username}')">${p.username}</div><div style="font-size:12px;color:gray">${new Date(p.created*1000).toLocaleString()}</div></div></div>${p.text ? `<div class="post-text">${p.text}</div>` : ''}${p.image_url ? `<img src="${p.image_url}" class="post-img">` : ''}<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px">${Object.entries(p.reaction_counts).map(([s,c])=>`<span style="background:var(--card2);padding:3px 8px;border-radius:10px;font-size:14px">${s} ${c}</span>`).join('')}</div><div class="acts"><button class="act ${p.liked?'on':''}" onclick="toggleLike(${p.id})">👍 ${p.likes}</button><button class="act" onclick="showStickers(${p.id})">😊 Реакция</button><button class="act" onclick="toggleComments(${p.id})">💬 ${p.comments}</button>${p.mine ? `<button class="act" style="color:var(--danger)" onclick="deletePost(${p.id})">🗑</button>` : ''}</div><div id="comments-${p.id}" style="display:none;margin-top:10px"></div><div id="stickers-${p.id}" style="display:none;margin-top:10px;gap:10px">${STICKERS.map(s=>`<button style="font-size:24px;background:none;border:none;cursor:pointer" onclick="react(${p.id},'${s}')">${s}</button>`).join('')}</div>`;
      document.getElementById('feed').appendChild(c);
    });
  } catch(e) { mc.innerHTML += `<p style="color:red">${e.message}</p>`; }
}

async function createPost() {
  let img = '';
  const file = document.getElementById('postFile').files[0];
  if(file) { const fd = new FormData(); fd.append('file', file); const r = await fetch('/api/upload', {method:'POST', body:fd, headers:{'X-Requested-With':'XMLHttpRequest'}}); const d = await r.json(); if(d.url) img = d.url; }
  await api('/posts','POST',{text:document.getElementById('postText').value, image_url:img}); renderFeed();
}
async function toggleLike(id) { await api('/posts/'+id+'/like','POST'); renderFeed(); }
async function deletePost(id) { if(confirm('Удалить?')) { await api('/posts/'+id,'DELETE'); renderFeed(); } }
async function react(id, s) { await api('/posts/'+id+'/react','POST',{sticker:s}); renderFeed(); }
function showStickers(id) { const el=document.getElementById('stickers-'+id); el.style.display = el.style.display==='none'?'flex':'none'; }
async function toggleComments(id) { const el = document.getElementById('comments-'+id); if(el.style.display==='block') { el.style.display='none'; return; } el.style.display='block'; const r = await api('/posts/'+id+'/comments'); el.innerHTML = `<div>${r.comments.map(c=>`<div style="margin-bottom:5px"><b style="color:var(--gold)">${c.username}:</b> ${c.text}</div>`).join('')}</div><div style="display:flex;gap:5px;margin-top:5px"><input id="ci-${id}" placeholder="Комментарий..."><button class="btn" onclick="addComment(${id})">➤</button></div>`; }
async function addComment(id) { const t = document.getElementById('ci-'+id).value; if(!t) return; await api('/posts/'+id+'/comments','POST',{text:t}); toggleComments(id); toggleComments(id); }

async function renderChats() {
  const mc = document.getElementById('main-content');
  const r = await api('/dialogs');
  mc.innerHTML = `<h2>Диалоги</h2>` + (r.dialogs.length ? r.dialogs.map(d=>`<div class="card" style="cursor:pointer" onclick="route('#/chat/${d.username}')"><div style="display:flex;align-items:center;gap:10px"><div class="avatar">${d.username[0]}</div><div><b style="color:var(--gold)">${d.username}</b><div style="font-size:12px;color:gray">${d.last_msg||'Нет сообщений'}</div></div></div></div>`).join('') : '<p>Нет диалогов.</p>');
}

async function renderChat(username) {
  const mc = document.getElementById('main-content');
  mc.innerHTML = `<div class="chat-layout"><div style="padding:10px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between"><b>${username}</b><div><button class="btn ghost" onclick="startCall('${username}',false)">📞</button> <button class="btn ghost" onclick="startCall('${username}',true)">📹</button></div></div><div class="messages" id="msgList"></div><div style="padding:10px;display:flex;gap:5px"><input id="msgInput" placeholder="Сообщение..."><input type="file" id="msgFile" style="display:none" onchange="sendFile('${username}')"><button class="btn" onclick="document.getElementById('msgFile').click()">📎</button><button class="btn" onclick="sendMsg('${username}')">➤</button></div></div>`;
  const r = await api('/messages/'+username);
  const ml = document.getElementById('msgList');
  r.messages.forEach(m => { const d = el('div', 'msg ' + (m.sender_id===me.id?'me':'them')); if(m.msg_type === 'image' || m.msg_type === 'circle') d.innerHTML = `<img src="${m.content}" class="msg-img">`; else if(m.msg_type === 'sticker') d.innerHTML = `<span style="font-size:40px">${m.content}</span>`; else d.textContent = m.content; ml.appendChild(d); });
  ml.scrollTop = ml.scrollHeight;
}
async function sendMsg(u) { const t = document.getElementById('msgInput').value; if(!t) return; await api('/messages/'+u,'POST',{type:'text',content:t}); document.getElementById('msgInput').value=''; renderChat(u); }
async function sendFile(u) { const f = document.getElementById('msgFile').files[0]; if(!f) return; const fd = new FormData(); fd.append('file', f); const r = await fetch('/api/upload', {method:'POST', body:fd, headers:{'X-Requested-With':'XMLHttpRequest'}}); const d = await r.json(); await api('/messages/'+u,'POST',{type:'image',content:d.url}); renderChat(u); }

async function renderFriends() {
  const mc = document.getElementById('main-content');
  const r = await api('/friends');
  mc.innerHTML = `<h2>Мои друзья</h2>` + (r.friends.length ? r.friends.map(u=>`<div class="card" style="display:flex;justify-content:space-between;align-items:center"><div><b style="color:var(--gold)">${u.username}</b></div><button class="btn ghost" onclick="route('#/chat/${u.username}')">💬 Написать</button></div>`).join('') : '<p>Пока нет друзей.</p>');
}

async function renderProfile(username) {
  const mc = document.getElementById('main-content');
  const u = (await api('/users/'+username)).user;
  const photos = (await api('/users/'+username+'/photos')).photos;
  const isMe = u.username === me.username;
  mc.innerHTML = `
    <div class="card" style="text-align:center">
      <div class="avatar" style="width:80px;height:80px;font-size:32px;margin:0 auto">${u.username[0]}</div>
      <h2 style="color:var(--gold)">${u.username}</h2>
      <p>${u.bio||'Нет описания'}</p>
      <div style="display:flex;flex-direction:column;gap:10px;margin-top:20px">
        ${isMe 
          ? `<button class="btn" onclick="editProfile()">⚙️ Редактировать профиль</button>
             <button class="btn ghost" onclick="uploadStory()">📷 Загрузить сторис</button>
             <button class="btn ghost" onclick="addGalleryPhoto()">🖼️ Добавить фото в галерею</button>`
          : `<button class="btn" onclick="toggleFriend('${u.username}', ${u.is_friend}, false)">${u.is_friend?'❌ Удалить из друзей':'🤝 Добавить в друзья'}</button>
             <button class="btn ghost" onclick="route('#/chat/${u.username}')">💬 Написать сообщение</button>`
        }
      </div>
      ${photos.length ? `<h3 style="text-align:left;margin-top:20px">Фотографии</h3><div class="gallery-grid">${photos.map(p=>`<img src="${p.photo_url}">`).join('')}</div>` : ''}
    </div>`;
}

function addGalleryPhoto() {
  const input = document.createElement('input');
  input.type = 'file'; input.accept = 'image/*';
  input.onchange = async e => {
    const file = e.target.files[0]; if(!file) return;
    const fd = new FormData(); fd.append('file', file);
    const r = await fetch('/api/upload', {method:'POST', body:fd, headers:{'X-Requested-With':'XMLHttpRequest'}});
    const d = await r.json();
    if(d.url) { await api('/photos','POST',{url:d.url}); renderProfile(me.username); }
  };
  input.click();
}

function uploadStory() {
  const input = document.createElement('input');
  input.type = 'file'; input.accept = 'image/*';
  input.onchange = async e => {
    const file = e.target.files[0]; if(!file) return;
    const fd = new FormData(); fd.append('file', file);
    const r = await fetch('/api/upload', {method:'POST', body:fd, headers:{'X-Requested-With':'XMLHttpRequest'}});
    const d = await r.json();
    if(d.url) { await api('/stories','POST',{media_url:d.url}); alert('Сторис добавлена!'); route('#/'); }
  };
  input.click();
}

async function editProfile() {
  const newName = prompt('Новое имя (оставь пустым, чтобы не менять):', me.username);
  if(newName === null) return;
  const newBio = prompt('О себе:', me.bio||'');
  if(newBio === null) return;
  const newPass = prompt('Новый пароль (пусто - не менять):', '');
  if(newPass === null) return;
  
  try {
    const body = { bio: newBio };
    if(newName.trim()) body.username = newName.trim();
    if(newPass.trim()) body.password = newPass.trim();
    const r = await api('/me/update','POST', body);
    me = r.user;
    alert('Профиль обновлён!');
    renderApp();
  } catch(e) { alert(e.message); }
}

async function toggleFriend(u, isF, refreshPeople) { 
  if(isF) await api('/friends/'+u,'DELETE'); else await api('/friends/'+u,'POST'); 
  if(refreshPeople) renderPeople(); else renderProfile(u);
}

// === ЗВОНКИ ===
async function startCall(username, video) {
  try {
    localStream = await navigator.mediaDevices.getUserMedia({audio:true, video});
    const r = await api('/call/start/'+username, 'POST', {video});
    currentCallId = r.call_id;
    document.getElementById('callUI').style.display = 'flex';
    document.getElementById('callStatus').textContent = `Звонок ${username}...`;
    document.getElementById('localVid').srcObject = localStream;
    document.getElementById('acceptBtn').style.display = 'none';
    if(!video) document.getElementById('localVid').style.display='none';
    startRing();
  } catch(e) { alert('Ошибка: '+e.message); }
}

async function pollEvents() {
  if(currentCallId) return;
  try {
    const r = await api('/poll');
    if(r.incoming && r.incoming.status==='ringing') {
      currentCallId = r.incoming.id;
      document.getElementById('callUI').style.display = 'flex';
      document.getElementById('callStatus').textContent = `Входящий от ${r.incoming.caller_name}...`;
      document.getElementById('acceptBtn').style.display = 'block';
      document.getElementById('localVid').style.display = 'none';
      startRing();
    }
    if(r.outgoing && r.outgoing.status === 'accepted' && !peerConnection) {
       stopRing();
       makePeer();
       const offer = await peerConnection.createOffer();
       await peerConnection.setLocalDescription(offer);
       await api('/webrtc/signal','POST',{call_id:currentCallId, signal:offer});
    }
  } catch(e) {}
}

async function acceptCall() {
  stopRing();
  document.getElementById('acceptBtn').style.display='none';
  try {
    localStream = await navigator.mediaDevices.getUserMedia({audio:true, video:true});
    document.getElementById('localVid').srcObject = localStream;
    document.getElementById('localVid').style.display='block';
    await api('/call/accept/'+currentCallId,'POST');
    document.getElementById('callStatus').textContent = 'Соединение...';
    makePeer();
  } catch(e) { alert(e.message); endCall(); }
}

function makePeer() {
  if(peerConnection) return;
  peerConnection = new RTCPeerConnection(servers);
  localStream.getTracks().forEach(t => peerConnection.addTrack(t, localStream));
  peerConnection.ontrack = e => { document.getElementById('remoteVid').srcObject = e.streams[0]; };
  peerConnection.onicecandidate = async e => { if(e.candidate) await api('/webrtc/signal','POST',{call_id:currentCallId, signal:e.candidate}); };
  if(rtcInt) clearInterval(rtcInt);
  rtcInt = setInterval(async () => {
    if(!currentCallId || !peerConnection) return;
    try {
      const r = await api('/webrtc/signals/'+currentCallId);
      for(const sig of r.signals) {
        if(sig.type === 'offer' && !remoteSet) {
          await peerConnection.setRemoteDescription(new RTCSessionDescription(sig)); remoteSet = true;
          const ans = await peerConnection.createAnswer(); await peerConnection.setLocalDescription(ans);
          await api('/webrtc/signal','POST',{call_id:currentCallId, signal:ans});
        } else if(sig.type === 'answer' && !remoteSet) {
          await peerConnection.setRemoteDescription(new RTCSessionDescription(sig)); remoteSet = true;
        } else if(sig.candidate) {
          if(peerConnection.remoteDescription) await peerConnection.addIceCandidate(new RTCIceCandidate(sig)).catch(()=>{});
          else pendingCandidates.push(sig);
        }
      }
      if(peerConnection.remoteDescription && pendingCandidates.length) {
        for(const c of pendingCandidates) await peerConnection.addIceCandidate(new RTCIceCandidate(c)).catch(()=>{});
        pendingCandidates = [];
      }
    } catch(e) {}
  }, 1000);
}

async function endCall() {
  stopRing();
  if(currentCallId) await api('/call/end/'+currentCallId,'POST').catch(()=>{});
  if(peerConnection) peerConnection.close();
  if(localStream) localStream.getTracks().forEach(t=>t.stop());
  clearInterval(rtcInt);
  document.getElementById('callUI').style.display='none';
  peerConnection = null; localStream = null; currentCallId = null; pendingCandidates=[]; remoteSet=false;
}

window.start = start;
start();
</script>
</body>
</html>
"""

@app.get("/")
def index(): return Response(INDEX_HTML, mimetype="text/html")
@app.get("/logo.jpg")
def logo(): return send_from_directory(BASE, "logo.jpg", max_age=86400)

def main():
    init_db()
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", action="store_true")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)))
    args = ap.parse_args()
    print(f"Сервер: http://127.0.0.1:{args.port}")
    app.run(host="0.0.0.0" if args.server else "127.0.0.1", port=args.port, threaded=True)

if __name__ == "__main__":
    main()
