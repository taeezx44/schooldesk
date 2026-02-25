from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
from datetime import date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

# ── App Setup ──────────────────────────────────────────────────────────────────

app = Flask(__name__)

# Secret key: ใช้ environment variable ถ้ามี ไม่งั้นสร้างไฟล์เก็บไว้ (คงอยู่แม้ restart)
SECRET_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.secret_key')
if os.environ.get('SECRET_KEY'):
    app.secret_key = os.environ['SECRET_KEY']
elif os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'rb') as f:
        app.secret_key = f.read()
else:
    key = os.urandom(32)
    with open(SECRET_KEY_FILE, 'wb') as f:
        f.write(key)
    app.secret_key = key

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['WTF_CSRF_TIME_LIMIT'] = 3600

csrf = CSRFProtect(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

# Init DB on startup (works with both direct run and gunicorn)
with app.app_context():
    pass  # init_db called below after function defined

# Database path: always relative to this file
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scheduler.db')

# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        conn = sqlite3.connect(DB)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with sqlite3.connect(DB) as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS schedule (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                day TEXT NOT NULL,
                time TEXT NOT NULL,
                course TEXT NOT NULL,
                room TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS homework (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                due TEXT NOT NULL,
                subject TEXT NOT NULL,
                description TEXT,
                done INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        ''')

def current_user():
    return session.get('user_id')

# Initialize database
init_db()

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user():
            flash('กรุณาเข้าสู่ระบบก่อน', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not username or not password:
        return render_template('index.html', schedule=[], homework=[],
                               username=None, now_date=date.today().isoformat(),
                               login_error='กรุณากรอกชื่อผู้ใช้และรหัสผ่าน')

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()

    if user and check_password_hash(user['password'], password):
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        return redirect(url_for('index'))

    return render_template('index.html', schedule=[], homework=[],
                           username=None, now_date=date.today().isoformat(),
                           login_error='ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง')

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    password2 = request.form.get('password2', '')

    if not username or not password:
        return render_template('index.html', schedule=[], homework=[],
                               username=None, now_date=date.today().isoformat(),
                               register_error='กรุณากรอกข้อมูลให้ครบ')

    if len(username) < 3 or len(username) > 32:
        return render_template('index.html', schedule=[], homework=[],
                               username=None, now_date=date.today().isoformat(),
                               register_error='ชื่อผู้ใช้ต้องมี 3-32 ตัวอักษร')

    if len(password) < 6:
        return render_template('index.html', schedule=[], homework=[],
                               username=None, now_date=date.today().isoformat(),
                               register_error='รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร')

    if password != password2:
        return render_template('index.html', schedule=[], homework=[],
                               username=None, now_date=date.today().isoformat(),
                               register_error='รหัสผ่านไม่ตรงกัน')

    try:
        db = get_db()
        db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                   (username, generate_password_hash(password)))
        db.commit()
        user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        flash('ยินดีต้อนรับ! สมัครสมาชิกสำเร็จ 🎉', 'success')
        return redirect(url_for('index'))
    except Exception:
        return render_template('index.html', schedule=[], homework=[],
                               username=None, now_date=date.today().isoformat(),
                               register_error='ชื่อผู้ใช้นี้มีอยู่แล้ว')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ── Main ──────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    uid = current_user()
    schedule, homework = [], []
    if uid:
        db = get_db()
        schedule = db.execute('SELECT * FROM schedule WHERE user_id=? ORDER BY day, time', (uid,)).fetchall()
        homework = db.execute('SELECT * FROM homework WHERE user_id=? ORDER BY due', (uid,)).fetchall()
    return render_template('index.html', schedule=schedule, homework=homework,
                           username=session.get('username'),
                           now_date=date.today().isoformat())

# ── Schedule CRUD ─────────────────────────────────────────────────────────────

@app.route('/add_class', methods=['POST'])
@login_required
def add_class():
    day = request.form.get('day', '').strip()
    time = request.form.get('time', '').strip()
    course = request.form.get('course', '').strip()
    room = request.form.get('room', '').strip()
    if not day or not time or not course:
        flash('กรุณากรอกข้อมูลให้ครบ', 'error')
        return redirect(url_for('index'))
    db = get_db()
    db.execute('INSERT INTO schedule (user_id, day, time, course, room) VALUES (?,?,?,?,?)',
               (current_user(), day, time, course, room))
    db.commit()
    return redirect(url_for('index'))

@app.route('/edit_class/<int:cid>', methods=['POST'])
@login_required
def edit_class(cid):
    day = request.form.get('day', '').strip()
    time = request.form.get('time', '').strip()
    course = request.form.get('course', '').strip()
    room = request.form.get('room', '').strip()
    db = get_db()
    db.execute('UPDATE schedule SET day=?, time=?, course=?, room=? WHERE id=? AND user_id=?',
               (day, time, course, room, cid, current_user()))
    db.commit()
    return redirect(url_for('index'))

@app.route('/delete_class/<int:cid>', methods=['POST'])
@login_required
def delete_class(cid):
    db = get_db()
    db.execute('DELETE FROM schedule WHERE id=? AND user_id=?', (cid, current_user()))
    db.commit()
    return redirect(url_for('index'))

# ── Homework CRUD ─────────────────────────────────────────────────────────────

@app.route('/add_homework', methods=['POST'])
@login_required
def add_homework():
    due = request.form.get('due', '').strip()
    subject = request.form.get('subject', '').strip()
    description = request.form.get('description', '').strip()
    if not due or not subject:
        flash('กรุณากรอกข้อมูลให้ครบ', 'error')
        return redirect(url_for('index'))
    db = get_db()
    db.execute('INSERT INTO homework (user_id, due, subject, description) VALUES (?,?,?,?)',
               (current_user(), due, subject, description))
    db.commit()
    return redirect(url_for('index'))

@app.route('/edit_homework/<int:hid>', methods=['POST'])
@login_required
def edit_homework(hid):
    due = request.form.get('due', '').strip()
    subject = request.form.get('subject', '').strip()
    description = request.form.get('description', '').strip()
    db = get_db()
    db.execute('UPDATE homework SET due=?, subject=?, description=? WHERE id=? AND user_id=?',
               (due, subject, description, hid, current_user()))
    db.commit()
    return redirect(url_for('index'))

@app.route('/toggle_homework/<int:hid>', methods=['POST'])
@login_required
def toggle_homework(hid):
    db = get_db()
    db.execute('UPDATE homework SET done = 1 - done WHERE id=? AND user_id=?', (hid, current_user()))
    db.commit()
    return redirect(url_for('index'))

@app.route('/delete_homework/<int:hid>', methods=['POST'])
@login_required
def delete_homework(hid):
    db = get_db()
    db.execute('DELETE FROM homework WHERE id=? AND user_id=?', (hid, current_user()))
    db.commit()
    return redirect(url_for('index'))

# ── Error Handlers ────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='ไม่พบหน้าที่คุณต้องการ'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', code=500, message='เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์'), 500

@app.errorhandler(429)
def ratelimit_error(e):
    return render_template('error.html', code=429, message='คุณส่งคำขอบ่อยเกินไป กรุณารอสักครู่'), 429

# ── PWA ───────────────────────────────────────────────────────────────────────

@app.route('/manifest.json')
def manifest():
    from flask import send_from_directory
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'manifest.json')

@app.route('/sw.js')
def sw():
    from flask import send_from_directory
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'sw.js',
                               mimetype='application/javascript')

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
