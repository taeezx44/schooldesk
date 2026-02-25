### app.py ที่ปรับปรุงแล้ว ###

from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
from datetime import date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ── 1. จัดการ Secret Key ให้ปลอดภัย ──
if os.environ.get('SECRET_KEY'):
    app.secret_key = os.environ['SECRET_KEY']
else:
    # ถ้าไม่มี Environment Variable ให้ใช้คีย์สำรอง (แนะนำให้ตั้งใน Render Dashboard)
    app.secret_key = 'dev-key-placeholder-please-change'

# ── 2. จัดการ Path ฐานข้อมูล (แก้ปัญหาข้อมูลหาย) ──
# ถ้าอยู่บน Render และมีการต่อ Disk ไว้ที่ /data ให้ใช้ที่นั่น
if os.path.exists('/data'):
    DB = '/data/scheduler.db'
else:
    # ถ้ารันในเครื่องตัวเอง ให้ใช้ path ปัจจุบัน
    DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scheduler.db')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB)
        db.row_factory = sqlite3.Row
    return db

# ── 3. ฟังก์ชันสร้างตาราง (รันอัตโนมัติถ้ายังไม่มีไฟล์) ──
def init_db():
    with app.app_context():
        db = get_db()
        # สร้างตาราง users
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
        # สร้างตาราง schedule
        db.execute('''CREATE TABLE IF NOT EXISTS schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            day TEXT NOT NULL,
            time TEXT NOT NULL,
            subject TEXT NOT NULL,
            room TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        # สร้างตาราง homework
        db.execute('''CREATE TABLE IF NOT EXISTS homework (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            deadline TEXT NOT NULL,
            details TEXT,
            done INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        db.commit()

# เรียกใช้งาน init_db เมื่อเริ่มแอป
init_db()

# ... (โค้ดส่วน Route ต่างๆ ของคุณสามารถใช้ของเดิมได้เลย) ...
