import os
import sqlite3
import telegram
import asyncio
import threading
from datetime import datetime
import bcrypt
import uuid
import time
from flask import Flask, request, render_template, redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_uploads import UploadSet, IMAGES, configure_uploads

app = Flask(__name__)
app.secret_key = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"

TELEGRAM_BOT_TOKEN = "6122680029:AAH38_qmiiYevrKnTif_fL9o-TdPg3uEBwI"
TELEGRAM_CHAT_ID = "990030901"
bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)

photos = UploadSet('photos', IMAGES)
app.config['UPLOADED_PHOTOS_DEST'] = 'static/uploads'
app.config['UPLOADED_PHOTOS_ALLOW'] = ['jpg', 'jpeg', 'png']
configure_uploads(app, photos)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, email):
        self.id = email

@login_manager.user_loader
def load_user(email):
    return User(email)

def init_db():
    for _ in range(5):  # Попробовать 5 раз
        try:
            conn = sqlite3.connect("users.db", timeout=10)
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS users (email TEXT UNIQUE, login TEXT, password TEXT, balance INTEGER DEFAULT 0)''')
            c.execute('''CREATE TABLE IF NOT EXISTS profiles (email TEXT UNIQUE, nickname TEXT, username TEXT UNIQUE, description TEXT, avatar TEXT, is_nft_username INTEGER DEFAULT 0)''')
            c.execute('''CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, content TEXT, created_at TEXT, community_id INTEGER)''')
            c.execute('''CREATE TABLE IF NOT EXISTS store_items (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, price INTEGER, is_sold INTEGER DEFAULT 0, buyer_email TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS roles (email TEXT UNIQUE, role TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS friends (user_email TEXT, friend_email TEXT, status TEXT, PRIMARY KEY (user_email, friend_email))''')
            c.execute('''CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_email TEXT, receiver_email TEXT, content TEXT, created_at TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS communities (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, description TEXT, creator_email TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS community_members (community_id INTEGER, email TEXT, PRIMARY KEY (community_id, email))''')
            c.execute('''CREATE TABLE IF NOT EXISTS clans (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, description TEXT, leader_email TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS clan_members (clan_id INTEGER, email TEXT, PRIMARY KEY (clan_id, email))''')
            c.execute('''CREATE TABLE IF NOT EXISTS clan_invites (invite_code TEXT UNIQUE, clan_id INTEGER, creator_email TEXT, created_at TEXT)''')
            conn.commit()
            conn.close()
            return
        except sqlite3.OperationalError as e:
            print(f"Database error: {e}. Retrying...")
            time.sleep(1)
    raise Exception("Failed to initialize database after multiple attempts")

def get_db_connection():
    return sqlite3.connect("users.db", timeout=10)

def get_profile(email):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        SELECT nickname, username, avatar, description, is_nft_username,
               CASE WHEN is_nft_username = 1 THEN username ELSE NULL END as nft_username
        FROM profiles
        WHERE email = ?
    """, (email,))
    profile = c.fetchone()
    conn.close()
    return profile

def get_user_balance(email):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE email = ?", (email,))
    balance = c.fetchone()
    conn.close()
    return balance[0] if balance else 0

def is_ceo(email):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT role FROM roles WHERE email = ?", (email,))
    role = c.fetchone()
    conn.close()
    return role and role[0] == 'ceo'

def send_to_telegram(email, login=None, password=None, nickname=None, username=None, description=None, content=None, action=None, coins=None, recipient=None):
    message = None
    if login and password:
        message = f"New Registration:\nEmail: {email}\nLogin: {login}\nPassword: [hidden]"
    elif nickname and username:
        message = f"New Profile:\nEmail: {email}\nNickname: {nickname}\nUsername: {username}\nDescription: {description}"
    elif content:
        message = f"New Post:\nUsername: {username}\nContent: {content}"
    elif action:
        message = f"Action: {action}\nEmail: {email}"
        if coins and recipient:
            message += f"\nCoins Issued: {coins}\nRecipient: {recipient}"
    async def send():
        try:
            await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message)
        except Exception as e:
            print(f"[Telegram error] {e}")
    threading.Thread(target=lambda: asyncio.run(send())).start()

@app.route('/')
def index():
    profile = get_profile(current_user.id) if current_user.is_authenticated else None
    return render_template('index.html', profile=profile)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not (email and password):
            flash("Заполните все поля!", "error")
            return render_template('login.html', profile=None)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE email = ?", (email,))
        row = c.fetchone()
        conn.close()
        if row and bcrypt.checkpw(password.encode('utf-8'), row[0].encode('utf-8')):
            login_user(User(email))
            return redirect(url_for('feed'))
        else:
            flash("Неверный email или пароль", "error")
    return render_template('login.html', profile=None)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))
    if request.method == 'POST':
        email = request.form.get('email')
        login = request.form.get('login')
        password = request.form.get('password')
        if not (email and login and password):
            flash("Заполните все поля!", "error")
            return render_template('register.html', profile=None)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email FROM users WHERE email = ?", (email,))
        if c.fetchone():
            conn.close()
            flash("Email уже зарегистрирован!", "error")
            return render_template('register.html', profile=None)
        c.execute("INSERT INTO users (email, login, password, balance) VALUES (?, ?, ?, ?)", (email, login, hashed_password.decode('utf-8'), 1000))
        conn.commit()
        conn.close()
        login_user(User(email))
        send_to_telegram(email, login=login, password="[hidden]")
        return redirect(url_for('create_profile'))
    return render_template('register.html', profile=None)

@app.route('/create_profile', methods=['GET', 'POST'])
@login_required
def create_profile():
    profile = get_profile(current_user.id)
    if profile:
        return redirect(url_for('feed'))
    if request.method == 'POST':
        nickname = request.form.get('nickname')
        username = request.form.get('username')
        description = request.form.get('description')
        email = current_user.id
        avatar = None
        if 'avatar' in request.files:
            photo = request.files['avatar']
            if photo and photos.file_allowed(photo, photo.filename):
                filename = photos.save(photo, name=f"{email}_avatar.")
                avatar = f"/static/uploads/{filename}"
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT username FROM profiles WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            flash("Юзернейм уже занят!", "error")
            return render_template('profile.html', profile=None)
        c.execute("INSERT INTO profiles (email, nickname, username, description, avatar) VALUES (?, ?, ?, ?, ?)", (email, nickname, username, description, avatar))
        conn.commit()
        conn.close()
        send_to_telegram(email, nickname=nickname, username=username, description=description)
        return redirect(url_for('feed'))
    return render_template('profile.html', profile=None)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))

    if request.method == 'POST':
        nickname = request.form.get('nickname')
        username = request.form.get('username')
        description = request.form.get('description')
        avatar = profile[2]  # текущий avatar

        if 'avatar' in request.files:
            photo = request.files['avatar']
            if photo and photos.file_allowed(photo, photo.filename):
                filename = photos.save(photo, name=f"{current_user.id}_avatar.")
                avatar = f"/static/uploads/{filename}"

        # Проверка, что username свободен или принадлежит текущему пользователю
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email FROM profiles WHERE username = ?", (username,))
        existing = c.fetchone()
        if existing and existing[0] != current_user.id:
            conn.close()
            flash("Этот username уже занят!", "error")
            return render_template('edit_profile.html', profile=profile)

        c.execute("""
            UPDATE profiles SET nickname = ?, username = ?, description = ?, avatar = ?
            WHERE email = ?
        """, (nickname, username, description, avatar, current_user.id))
        conn.commit()
        conn.close()

        flash("Профиль обновлен!", "success")
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', profile=profile)

@app.route('/profile')
@login_required
def profile():
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))

    conn = get_db_connection()
    c = conn.cursor()

    # Получаем все NFT usernames пользователя
    c.execute("SELECT username FROM store_items WHERE buyer_email = ? AND is_sold = 1", (current_user.id,))
    nft_usernames = [row[0] for row in c.fetchall()]

    # Посты
    c.execute("SELECT content, created_at FROM posts WHERE email = ? AND community_id IS NULL ORDER BY created_at DESC", (current_user.id,))
    posts = c.fetchall()

    conn.close()
    return render_template('profile_view.html', profile=profile, posts=posts, nft_usernames=nft_usernames, is_own_profile=True)

@app.route('/profile/<username>')
def view_profile(username):
    conn = get_db_connection()
    c = conn.cursor()

    # Получаем профиль по username
    c.execute("""
        SELECT nickname, username, avatar, description, is_nft_username,
               CASE WHEN is_nft_username = 1 THEN username ELSE NULL END as nft_username
        FROM profiles
        WHERE username = ?
    """, (username,))
    profile = c.fetchone()

    if not profile:
        conn.close()
        abort(404, description="Пользователь не найден")

    # Получаем все NFT usernames пользователя
    c.execute("SELECT username FROM store_items WHERE buyer_email = (SELECT email FROM profiles WHERE username = ?) AND is_sold = 1", (username,))
    nft_usernames = [row[0] for row in c.fetchall()]

    # Посты
    c.execute("""
        SELECT content, created_at
        FROM posts
        WHERE email = (SELECT email FROM profiles WHERE username = ?) AND community_id IS NULL
        ORDER BY created_at DESC
    """, (username,))
    posts = c.fetchall()

    # Проверяем, является ли это профиль текущего пользователя
    is_own_profile = False
    friend_status = None
    if current_user.is_authenticated:
        is_own_profile = current_user.id == (c.execute("SELECT email FROM profiles WHERE username = ?", (username,)).fetchone()[0])
        if not is_own_profile:
            # Проверяем статус дружбы
            c.execute("""
                SELECT status
                FROM friends
                WHERE (user_email = ? AND friend_email = (SELECT email FROM profiles WHERE username = ?))
                   OR (user_email = (SELECT email FROM profiles WHERE username = ?) AND friend_email = ?)
            """, (current_user.id, username, username, current_user.id))
            friend_row = c.fetchone()
            friend_status = friend_row[0] if friend_row else None

    conn.close()
    return render_template('profile_view.html', profile=profile, posts=posts, nft_usernames=nft_usernames, is_own_profile=is_own_profile, friend_status=friend_status)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    profile = get_profile(current_user.id)
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not (current_password and new_password and confirm_password):
            flash("Заполните все поля!", "error")
            return render_template('settings.html', profile=profile)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE email = ?", (current_user.id,))
        row = c.fetchone()
        if not row:
            conn.close()
            flash("Пользователь не найден!", "error")
            return render_template('settings.html', profile=profile)
        stored_password = row[0]
        if not bcrypt.checkpw(current_password.encode('utf-8'), stored_password.encode('utf-8')):
            conn.close()
            flash("Текущий пароль неверный!", "error")
            return render_template('settings.html', profile=profile)
        if new_password != confirm_password:
            conn.close()
            flash("Новый пароль и подтверждение не совпадают!", "error")
            return render_template('settings.html', profile=profile)
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        c.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password.decode('utf-8'), current_user.id))
        conn.commit()
        conn.close()
        flash("Пароль успешно изменен!", "success")
        return redirect(url_for('settings'))
    return render_template('settings.html', profile=profile)

@app.route('/store', methods=['GET', 'POST'])
@login_required
def store():
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, username, price FROM store_items WHERE is_sold = 0")
    items = c.fetchall()
    balance = get_user_balance(current_user.id)
    if request.method == 'POST':
        item_id = request.form.get('item_id')
        c.execute("SELECT username, price FROM store_items WHERE id = ? AND is_sold = 0", (item_id,))
        item = c.fetchone()
        if not item:
            conn.close()
            flash("Товар не найден или уже продан!", "error")
            return redirect(url_for('store'))
        username, price = item
        if balance < price:
            conn.close()
            flash("Недостаточно средств!", "error")
            return redirect(url_for('store'))
        c.execute("SELECT username FROM profiles WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            flash("Юзернейм уже занят!", "error")
            return redirect(url_for('store'))
        c.execute("UPDATE users SET balance = balance - ? WHERE email = ?", (price, current_user.id))
        c.execute("UPDATE store_items SET is_sold = 1, buyer_email = ? WHERE id = ?", (current_user.id, item_id))
        c.execute("UPDATE profiles SET username = ?, is_nft_username = 1 WHERE email = ?", (username, current_user.id))
        conn.commit()
        conn.close()
        flash("NFT-username успешно приобретен!", "success")
        send_to_telegram(current_user.id, action=f"Purchased NFT-username: {username}")
        return redirect(url_for('store'))
    conn.close()
    return render_template('store.html', profile=profile, items=items, balance=balance, is_ceo=is_ceo(current_user.id))

@app.route('/add_nft_username', methods=['GET', 'POST'])
@login_required
def add_nft_username():
    if not is_ceo(current_user.id):
        flash("Только CEO может добавлять NFT-username!", "error")
        return redirect(url_for('feed'))
    profile = get_profile(current_user.id)
    if request.method == 'POST':
        username = request.form.get('username')
        price = request.form.get('price')
        if not (username and price):
            flash("Заполните все поля!", "error")
            return render_template('add_nft_username.html', profile=profile)
        try:
            price = int(price)
            if price <= 0:
                raise ValueError
        except ValueError:
            flash("Цена должна быть положительным числом!", "error")
            return render_template('add_nft_username.html', profile=profile)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT username FROM store_items WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            flash("Этот юзернейм уже в магазине!", "error")
            return render_template('add_nft_username.html', profile=profile)
        c.execute("INSERT INTO store_items (username, price) VALUES (?, ?)", (username, price))
        conn.commit()
        conn.close()
        flash("NFT-username добавлен в магазин!", "success")
        send_to_telegram(current_user.id, action=f"Added NFT-username: {username}")
        return redirect(url_for('store'))
    return render_template('add_nft_username.html', profile=profile)

@app.route('/issue_coins', methods=['GET', 'POST'])
@login_required
def issue_coins():
    if not is_ceo(current_user.id):
        flash("Только CEO может выдавать монеты!", "error")
        return redirect(url_for('feed'))
    profile = get_profile(current_user.id)
    if request.method == 'POST':
        recipient = request.form.get('recipient')
        coins = request.form.get('coins')
        if not (recipient and coins):
            flash("Заполните все поля!", "error")
            return render_template('issue_coins.html', profile=profile)
        try:
            coins = int(coins)
            if coins <= 0:
                raise ValueError
        except ValueError:
            flash("Количество монет должно быть положительным числом!", "error")
            return render_template('issue_coins.html', profile=profile)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email FROM users WHERE email = ? OR login = ?", (recipient, recipient))
        user = c.fetchone()
        if not user:
            conn.close()
            flash("Пользователь не найден!", "error")
            return render_template('issue_coins.html', profile=profile)
        user_email = user[0]
        c.execute("UPDATE users SET balance = balance + ? WHERE email = ?", (coins, user_email))
        conn.commit()
        conn.close()
        flash(f"Выдано {coins} монет пользователю {recipient}!", "success")
        send_to_telegram(current_user.id, action="Coins issued", coins=coins, recipient=recipient)
        return redirect(url_for('issue_coins'))
    return render_template('issue_coins.html', profile=profile)

@app.route('/friends', methods=['GET', 'POST'])
@login_required
def friends():
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'POST':
        friend_username = request.form.get('friend_username')
        c.execute("SELECT email FROM profiles WHERE username = ?", (friend_username,))
        friend = c.fetchone()
        if not friend:
            conn.close()
            flash("Пользователь не найден!", "error")
            return redirect(url_for('friends'))
        friend_email = friend[0]
        if friend_email == current_user.id:
            conn.close()
            flash("Нельзя добавить себя в друзья!", "error")
            return redirect(url_for('friends'))
        c.execute("SELECT * FROM friends WHERE user_email = ? AND friend_email = ?", (current_user.id, friend_email))
        if c.fetchone():
            conn.close()
            flash("Этот пользователь уже в друзьях или запрос отправлен!", "error")
            return redirect(url_for('friends'))
        c.execute("INSERT INTO friends (user_email, friend_email, status) VALUES (?, ?, ?)", (current_user.id, friend_email, 'pending'))
        conn.commit()
        conn.close()
        flash("Запрос дружбы отправлен!", "success")
        send_to_telegram(current_user.id, action=f"Sent friend request to {friend_username}")
        return redirect(url_for('friends'))
    c.execute("SELECT p.nickname, p.username, p.avatar FROM friends f JOIN profiles p ON f.friend_email = p.email WHERE f.user_email = ? AND f.status = 'accepted'", (current_user.id,))
    friends = c.fetchall()
    c.execute("SELECT p.nickname, p.username, p.avatar FROM friends f JOIN profiles p ON f.user_email = p.email WHERE f.friend_email = ? AND f.status = 'pending'", (current_user.id,))
    friend_requests = c.fetchall()
    conn.close()
    return render_template('friends.html', profile=profile, friends=friends, friend_requests=friend_requests)

@app.route('/accept_friend/<friend_email>', methods=['POST'])
@login_required
def accept_friend(friend_email):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE friends SET status = 'accepted' WHERE user_email = ? AND friend_email = ?", (friend_email, current_user.id))
    c.execute("INSERT OR IGNORE INTO friends (user_email, friend_email, status) VALUES (?, ?, ?)", (current_user.id, friend_email, 'accepted'))
    conn.commit()
    conn.close()
    flash("Друг добавлен!", "success")
    send_to_telegram(current_user.id, action=f"Accepted friend request from {friend_email}")
    return redirect(url_for('friends'))

@app.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'POST':
        receiver_username = request.form.get('receiver_username')
        content = request.form.get('content')
        if not (receiver_username and content):
            flash("Заполните все поля!", "error")
            return redirect(url_for('messages'))
        c.execute("SELECT email FROM profiles WHERE username = ?", (receiver_username,))
        receiver = c.fetchone()
        if not receiver:
            conn.close()
            flash("Пользователь не найден!", "error")
            return redirect(url_for('messages'))
        receiver_email = receiver[0]
        if receiver_email == current_user.id:
            conn.close()
            flash("Нельзя отправить сообщение себе!", "error")
            return redirect(url_for('messages'))
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c.execute("INSERT INTO messages (sender_email, receiver_email, content, created_at) VALUES (?, ?, ?, ?)", (current_user.id, receiver_email, content.strip(), created_at))
        conn.commit()
        conn.close()
        flash("Сообщение отправлено!", "success")
        send_to_telegram(current_user.id, action=f"Sent message to {receiver_username}")
        return redirect(url_for('messages'))
    c.execute("""
        SELECT DISTINCT p.username, p.nickname, p.avatar
        FROM messages m
        JOIN profiles p ON (m.sender_email = p.email OR m.receiver_email = p.email)
        WHERE (m.sender_email = ? OR m.receiver_email = ?) AND p.email != ?
    """, (current_user.id, current_user.id, current_user.id))
    conversations = c.fetchall()
    selected_conversation = request.args.get('conversation')
    messages = []
    if selected_conversation:
        c.execute("""
            SELECT m.sender_email, m.content, m.created_at, p.username
            FROM messages m
            JOIN profiles p ON m.sender_email = p.email
            WHERE (m.sender_email = ? AND m.receiver_email = (SELECT email FROM profiles WHERE username = ?))
               OR (m.receiver_email = ? AND m.sender_email = (SELECT email FROM profiles WHERE username = ?))
            ORDER BY m.created_at
        """, (current_user.id, selected_conversation, current_user.id, selected_conversation))
        messages = c.fetchall()
    conn.close()
    return render_template('messages.html', profile=profile, conversations=conversations, messages=messages, selected_conversation=selected_conversation)

@app.route('/communities', methods=['GET', 'POST'])
@login_required
def communities():
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            name = request.form.get('name')
            description = request.form.get('description')
            if not (name and description):
                flash("Заполните все поля!", "error")
                return redirect(url_for('communities'))
            c.execute("INSERT INTO communities (name, description, creator_email) VALUES (?, ?, ?)", (name, description, current_user.id))
            community_id = c.lastrowid
            c.execute("INSERT INTO community_members (community_id, email) VALUES (?, ?)", (community_id, current_user.id))
            conn.commit()
            flash("Сообщество создано!", "success")
            send_to_telegram(current_user.id, action=f"Created community: {name}")
        elif action == 'join':
            community_id = request.form.get('community_id')
            c.execute("SELECT * FROM community_members WHERE community_id = ? AND email = ?", (community_id, current_user.id))
            if c.fetchone():
                flash("Вы уже в этом сообществе!", "error")
            else:
                c.execute("INSERT INTO community_members (community_id, email) VALUES (?, ?)", (community_id, current_user.id))
                conn.commit()
                flash("Вы вступили в сообщество!", "success")
                send_to_telegram(current_user.id, action=f"Joined community ID: {community_id}")
        elif action == 'post':
            community_id = request.form.get('community_id')
            content = request.form.get('content')
            if not content:
                flash("Пост не может быть пустым!", "error")
            else:
                created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                c.execute("INSERT INTO posts (email, content, created_at, community_id) VALUES (?, ?, ?, ?)", (current_user.id, content.strip(), created_at, community_id))
                conn.commit()
                flash("Пост опубликован в сообществе!", "success")
                send_to_telegram(current_user.id, action=f"Posted in community ID: {community_id}")
        return redirect(url_for('communities'))
    try:
        c.execute("SELECT c.id, c.name, c.description, p.nickname FROM communities c JOIN profiles p ON c.creator_email = p.email")
        all_communities = c.fetchall()
        c.execute("SELECT c.id, c.name, c.description, p.nickname FROM community_members cm JOIN communities c ON cm.community_id = c.id JOIN profiles p ON c.creator_email = p.email WHERE cm.email = ?", (current_user.id,))
        my_communities = c.fetchall()
        selected_community = request.args.get('community_id')
        community_posts = []
        if selected_community:
            c.execute("SELECT p.content, p.created_at, pr.nickname FROM posts p JOIN profiles pr ON p.email = pr.email WHERE p.community_id = ? ORDER BY p.created_at DESC", (selected_community,))
            community_posts = c.fetchall()
    except sqlite3.OperationalError as e:
        conn.close()
        flash(f"Ошибка базы данных: {e}. Пожалуйста, обновите базу данных.", "error")
        return render_template('communities.html', profile=profile, all_communities=[], my_communities=[], community_posts=[], selected_community=None)
    conn.close()
    return render_template('communities.html', profile=profile, all_communities=all_communities, my_communities=my_communities, community_posts=community_posts, selected_community=selected_community)

@app.route('/clans', methods=['GET', 'POST'])
@login_required
def clans():
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            name = request.form.get('name')
            description = request.form.get('description')
            if not (name and description):
                flash("Заполните все поля!", "error")
                return redirect(url_for('clans'))
            c.execute("INSERT INTO clans (name, description, leader_email) VALUES (?, ?, ?)", (name, description, current_user.id))
            clan_id = c.lastrowid
            c.execute("INSERT INTO clan_members (clan_id, email) VALUES (?, ?)", (clan_id, current_user.id))
            conn.commit()
            flash("Клан создан!", "success")
            send_to_telegram(current_user.id, action=f"Created clan: {name}")
        elif action == 'create_invite':
            clan_id = request.form.get('clan_id')
            c.execute("SELECT leader_email FROM clans WHERE id = ?", (clan_id,))
            clan = c.fetchone()
            if not clan or clan[0] != current_user.id:
                flash("Только лидер клана может создавать инвайты!", "error")
            else:
                invite_code = str(uuid.uuid4())
                created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                c.execute("INSERT INTO clan_invites (invite_code, clan_id, creator_email, created_at) VALUES (?, ?, ?, ?)", (invite_code, clan_id, current_user.id, created_at))
                conn.commit()
                flash(f"Инвайт-код создан: {invite_code}", "success")
                send_to_telegram(current_user.id, action=f"Created invite for clan ID: {clan_id}")
        elif action == 'join':
            invite_code = request.form.get('invite_code')
            c.execute("SELECT clan_id FROM clan_invites WHERE invite_code = ?", (invite_code,))
            invite = c.fetchone()
            if not invite:
                flash("Неверный инвайт-код!", "error")
            else:
                clan_id = invite[0]
                c.execute("SELECT * FROM clan_members WHERE clan_id = ? AND email = ?", (clan_id, current_user.id))
                if c.fetchone():
                    flash("Вы уже в этом клане!", "error")
                else:
                    c.execute("INSERT INTO clan_members (clan_id, email) VALUES (?, ?)", (clan_id, current_user.id))
                    c.execute("DELETE FROM clan_invites WHERE invite_code = ?", (invite_code))
                    conn.commit()
                    flash("Вы вступили в клан!", "success")
                    send_to_telegram(current_user.id, action=f"Joined clan ID: {clan_id}")
        return redirect(url_for('clans'))
    try:
        c.execute("SELECT c.id, c.name, c.description, p.nickname FROM clans c JOIN profiles p ON c.leader_email = p.email")
        all_clans = c.fetchall()
        c.execute("SELECT c.id, c.name, c.description, p.nickname FROM clan_members cm JOIN clans c ON cm.clan_id = c.id JOIN profiles p ON c.leader_email = p.email WHERE cm.email = ?", (current_user.id,))
        my_clans = c.fetchall()
        c.execute("SELECT c.id, c.name FROM clans c WHERE c.leader_email = ?", (current_user.id,))
        my_led_clans = c.fetchall()
    except sqlite3.Error as e:
        conn.close()
        flash(f"Ошибка базы данных: {e}. Пожалуйста проверьте структуру базы данных.", "error")
        return render_template('clans.html', profile=profile, all_clans=[], my_clans=[], my_led_clans=[])
    conn.close()
    return render_template('clans.html', profile=profile, all_clans=all_clans, my_clans=my_clans, my_led_clans=my_led_clans)

@app.route('/feed', methods=['GET', 'POST'])
@login_required
def feed():
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))
    if request.method == 'POST':
        content = request.form.get('content')
        if content and content.strip():
            email = current_user.id
            created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT username FROM profiles WHERE email = ?", (email,))
            username = c.fetchone()
            if not username:
                conn.close()
                flash("Username не найден!", "error")
                return redirect(url_for('create_profile'))
            username = username[0]
            c.execute("INSERT INTO posts (email, content, created_at) VALUES (?, ?, ?)", (email, content.strip(), created_at))
            conn.commit()
            conn.close()
            send_to_telegram(email, content=content, username=username)
            flash("Пост опубликован!", "success")
        else:
            flash("Пост не может быть пустым!", "error")
        return redirect(url_for('feed'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT posts.email, p.nickname, posts.content, posts.created_at FROM posts JOIN profiles p ON posts.email = p.email WHERE posts.community_id IS NULL ORDER BY posts.created_at DESC")
    posts = c.fetchall()
    conn.close()
    return render_template('feed.html', profile=profile, posts=posts)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/create_nft_username', methods=['GET', 'POST'])
@login_required
def create_nft_username():
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))

    balance = get_user_balance(current_user.id)
    if request.method == 'POST':
        username = request.form.get('username')
        if not username:
            flash("Введите имя!", "error")
            return render_template('create_nft_username.html', profile=profile)

        if balance < 500:
            flash("Недостаточно монет (нужно 500)!", "error")
            return redirect(url_for('create_nft_username'))

        conn = get_db_connection()
        c = conn.cursor()

        # Проверка, занят ли username
        c.execute("SELECT 1 FROM profiles WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            flash("Юзернейм уже занят!", "error")
            return redirect(url_for('create_nft_username'))

        # Снятие монет
        c.execute("UPDATE users SET balance = balance - 500 WHERE email = ?", (current_user.id,))

        # Добавление в store_items (для учета) — считается "купленным"
        c.execute("INSERT INTO store_items (username, price, is_sold, buyer_email) VALUES (?, ?, 1, ?)", (username, 500, current_user.id))

        # Обновление профиля
        c.execute("UPDATE profiles SET username = ?, is_nft_username = 1 WHERE email = ?", (username, current_user.id))

        conn.commit()
        conn.close()

        flash("NFT-username создан!", "success")
        send_to_telegram(current_user.id, action=f"Created own NFT-username: {username}")
        return redirect(url_for('profile'))

    return render_template('create_nft_username.html', profile=profile, balance=balance)

if __name__ == "__main__":
    os.makedirs('static/uploads', exist_ok=True)
    init_db()
    app.run(debug=True)