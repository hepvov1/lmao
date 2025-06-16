import sys
import os
from flask import Flask, request, redirect, url_for, flash, render_template
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
import sqlite3
from datetime import datetime
from cssmin import cssmin

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Замените на безопасный ключ
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}

# Настройка Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Модель пользователя
class User(UserMixin):
    def __init__(self, email):
        self.id = email

@login_manager.user_loader
def load_user(email):
    return User(email)

# Подключение к БД
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Получение профиля
def get_profile(email):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT nickname, username, avatar, description, has_nft, nft_username, role FROM profiles WHERE email = ?",
              (email,))
    profile = c.fetchone()
    conn.close()
    return profile

# Фильтр strftime
def strftime_filter(dt, fmt):
    return datetime.strptime(dt, '%Y-%m-%d %H:%M:%S').strftime(fmt) if dt else ''

app.jinja_env.filters['strftime'] = strftime_filter

# Минимизация CSS
def minify_css():
    css_path = os.path.join('static', 'css', 'styles.css')
    min_css_path = os.path.join('static', 'css', 'styles.min.css')
    if os.path.exists(css_path):
        with open(css_path, 'r', encoding='utf-8') as f:
            css = f.read()
        with open(min_css_path, 'w', encoding='utf-8') as f:
            f.write(cssmin(css))
    else:
        print(f"Файл {css_path} не найден!")

# Инициализация базы данных
def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        login TEXT NOT NULL,
        password TEXT NOT NULL,
        balance INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS profiles (
        email TEXT PRIMARY KEY,
        nickname TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE,
        avatar TEXT,
        description TEXT,
        has_nft INTEGER DEFAULT 0,
        nft_username TEXT,
        FOREIGN KEY (email) REFERENCES users(email)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_email) REFERENCES users(email)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS friends (
        user_email TEXT,
        friend_email TEXT,
        status TEXT NOT NULL,
        PRIMARY KEY (user_email, friend_email),
        FOREIGN KEY (user_email) REFERENCES users(email),
        FOREIGN KEY (friend_email) REFERENCES users(email)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_email TEXT,
        receiver_email TEXT,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_email) REFERENCES users(email),
        FOREIGN KEY (receiver_email) REFERENCES users(email)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS communities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        creator_email TEXT,
        FOREIGN KEY (creator_email) REFERENCES users(email)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS community_members (
        community_id INTEGER,
        user_email TEXT,
        PRIMARY KEY (community_id, user_email),
        FOREIGN KEY (community_id) REFERENCES communities(id),
        FOREIGN KEY (user_email) REFERENCES users(email)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS community_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        community_id INTEGER,
        user_email TEXT,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (community_id) REFERENCES communities(id),
        FOREIGN KEY (user_email) REFERENCES users(email)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS clans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        leader_email TEXT,
        FOREIGN KEY (leader_email) REFERENCES users(email)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS clan_members (
        clan_id INTEGER,
        user_email TEXT,
        PRIMARY KEY (clan_id, user_email),
        FOREIGN KEY (clan_id) REFERENCES clans(id),
        FOREIGN KEY (user_email) REFERENCES users(email)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS clan_invites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        clan_id INTEGER,
        code TEXT NOT NULL UNIQUE,
        FOREIGN KEY (clan_id) REFERENCES clans(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS nft_usernames (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        price INTEGER NOT NULL,
        owner_email TEXT,
        FOREIGN KEY (owner_email) REFERENCES users(email)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS group_chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        creator_email TEXT NOT NULL,
        FOREIGN KEY (creator_email) REFERENCES users(email)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS group_chat_members (
        chat_id INTEGER,
        user_email TEXT,
        PRIMARY KEY (chat_id, user_email),
        FOREIGN KEY (chat_id) REFERENCES group_chats(id),
        FOREIGN KEY (user_email) REFERENCES users(email)
    )''')
    # Добавление таблицы для сообщений групповых чатов
    c.execute('''CREATE TABLE IF NOT EXISTS group_chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER,
        user_email TEXT,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (chat_id) REFERENCES group_chats(id),
        FOREIGN KEY (user_email) REFERENCES users(email)
    )''')
    conn.commit()
    conn.close()

# Инициализация приложения
if not os.path.exists(os.path.join('static', 'css', 'styles.min.css')):
    minify_css()
init_db()

# Маршруты
@app.route('/')
def index():
    profile = get_profile(current_user.id) if current_user.is_authenticated else None
    return render_template('index.html', page='index', title='Clouds', profile=profile)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            user_obj = User(email)
            login_user(user_obj)
            return redirect(url_for('index'))
        flash('Неверный email или пароль!', 'error')
    return render_template('index.html', page='login', title='Вход')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email')
        login = request.form.get('login')
        password = request.form.get('password')
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (email, login, password) VALUES (?, ?, ?)", (email, login, hashed))
            conn.commit()
            user_obj = User(email)
            login_user(user_obj)
            return redirect(url_for('create_profile'))
        except sqlite3.IntegrityError:
            flash('Email или логин уже занят!', 'error')
        finally:
            conn.close()
    return render_template('index.html', page='register', title='Регистрация')

@app.route('/create_profile', methods=['GET', 'POST'])
@login_required
def create_profile():
    if request.method == 'POST':
        nickname = request.form.get('nickname')
        username = request.form.get('username')
        description = request.form.get('description')
        avatar = request.files.get('avatar')
        avatar_path = None
        if avatar and avatar.filename.split('.')[-1].lower() in app.config['ALLOWED_EXTENSIONS']:
            filename = f"{current_user.id}_{avatar.filename}"
            avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            avatar_path = f"/static/uploads/{filename}"
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO profiles (email, nickname, username, avatar, description) VALUES (?, ?, ?, ?, ?)",
                      (current_user.id, nickname, username, avatar_path, description))
            conn.commit()
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash('Username уже занят!', 'error')
        finally:
            conn.close()
    return render_template('index.html', page='profile', title='Создать профиль')

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
        avatar = request.files.get('avatar')
        avatar_path = profile['avatar']
        if avatar and avatar.filename.split('.')[-1].lower() in app.config['ALLOWED_EXTENSIONS']:
            filename = f"{current_user.id}_{avatar.filename}"
            avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            avatar_path = f"/static/uploads/{filename}"
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("UPDATE profiles SET nickname = ?, username = ?, avatar = ?, description = ? WHERE email = ?",
                      (nickname, username, avatar_path, description, current_user.id))
            conn.commit()
            return redirect(url_for('profile_view', username=username))
        except sqlite3.IntegrityError:
            flash('Username уже занят!', 'error')
        finally:
            conn.close()
    return render_template('index.html', page='edit_profile', title='Редактировать профиль', profile=profile)

@app.route('/profile')
@login_required
def profile():
    profile = get_profile(current_user.id)
    if not profile:
        flash('Пожалуйста, создайте профиль!', 'error')
        return redirect(url_for('create_profile'))
    return redirect(url_for('profile_view', username=profile['username']))

@app.route('/profile/<username>')
def profile_view(username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT email, nickname, username, avatar, description, has_nft, nft_username FROM profiles WHERE username = ?",
        (username,))
    profile = c.fetchone()
    if not profile:
        conn.close()
        flash('Профиль не найден!', 'error')
        return redirect(url_for('index'))
    c.execute("SELECT content, created_at FROM posts WHERE user_email = ? ORDER BY created_at DESC",
              (profile['email'],))
    posts = c.fetchall()
    is_own_profile = current_user.is_authenticated and current_user.id == profile['email']
    friend_status = None
    if current_user.is_authenticated and not is_own_profile:
        c.execute(
            "SELECT status FROM friends WHERE (user_email = ? AND friend_email = ?) OR (user_email = ? AND friend_email = ?)",
            (current_user.id, profile['email'], profile['email'], current_user.id))
        status = c.fetchone()
        friend_status = status['status'] if status else None
    conn.close()
    return render_template('index.html', page='profile_view', title=f'Профиль @{username}', profile=profile,
                           posts=posts,
                           is_own_profile=is_own_profile, friend_status=friend_status)

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
        friend_email = friend['email']
        if friend_email == current_user.id:
            conn.close()
            flash("Нельзя добавить себя в друзья!", "error")
            return redirect(url_for('friends'))
        c.execute(
            "SELECT status FROM friends WHERE (user_email = ? AND friend_email = ?) OR (user_email = ? AND friend_email = ?)",
            (current_user.id, friend_email, friend_email, current_user.id))
        existing = c.fetchone()
        if existing:
            conn.close()
            flash("Запрос уже отправлен или пользователь в друзьях!", "error")
            return redirect(url_for('friends'))
        c.execute("INSERT INTO friends (user_email, friend_email, status) VALUES (?, ?, ?)",
                  (current_user.id, friend_email, 'pending'))
        conn.commit()
        conn.close()
        flash("Запрос дружбы отправлен!", "success")
        return redirect(url_for('friends'))

    c.execute("""
        SELECT p.nickname, p.username, p.avatar 
        FROM friends f 
        JOIN profiles p ON f.friend_email = p.email 
        WHERE f.user_email = ? AND f.status = 'accepted'
        UNION
        SELECT p.nickname, p.username, p.avatar 
        FROM friends f 
        JOIN profiles p ON f.user_email = p.email 
        WHERE f.friend_email = ? AND f.status = 'accepted'
    """, (current_user.id, current_user.id))
    friends = c.fetchall()

    c.execute("""
        SELECT p.nickname, p.username, p.avatar 
        FROM friends f 
        JOIN profiles p ON f.user_email = p.email 
        WHERE f.friend_email = ? AND f.status = 'pending'
    """, (current_user.id,))
    friend_requests = c.fetchall()

    conn.close()
    return render_template('index.html', page='friends', title='Друзья', profile=profile, friends=friends,
                           friend_requests=friend_requests)

@app.route('/accept_friend/<username>', methods=['POST'])
@login_required
def accept_friend(username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT email FROM profiles WHERE username = ?", (username,))
    friend = c.fetchone()
    if not friend:
        conn.close()
        flash("Пользователь не найден!", "error")
        return redirect(url_for('friends'))
    friend_email = friend['email']
    c.execute("SELECT status FROM friends WHERE user_email = ? AND friend_email = ? AND status = 'pending'",
              (friend_email, current_user.id))
    existing = c.fetchone()
    if not existing:
        conn.close()
        flash("Заявка не найдена!", "error")
        return redirect(url_for('friends'))

    c.execute("UPDATE friends SET status = 'accepted' WHERE user_email = ? AND friend_email = ?",
              (friend_email, current_user.id))

    c.execute("INSERT OR IGNORE INTO friends (user_email, friend_email, status) VALUES (?, ?, ?)",
              (current_user.id, friend_email, 'accepted'))

    conn.commit()
    conn.close()
    flash("Друг успешно добавлен!", "success")
    return redirect(url_for('friends'))

@app.route('/feed', methods=['GET', 'POST'])
@login_required
def feed():
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'POST':
        content = request.form.get('content')
        c.execute("INSERT INTO posts (user_email, content) VALUES (?, ?)", (current_user.id, content))
        conn.commit()
    c.execute("""
        SELECT p.content, pr.nickname, p.created_at 
        FROM posts p 
        JOIN profiles pr ON p.user_email = pr.email 
        WHERE p.user_email IN (
            SELECT friend_email FROM friends WHERE user_email = ? AND status = 'accepted'
            UNION SELECT user_email FROM friends WHERE friend_email = ? AND status = 'accepted'
            UNION SELECT ? 
        ) 
        ORDER BY p.created_at DESC
    """, (current_user.id, current_user.id, current_user.id))
    posts = c.fetchall()
    conn.close()
    return render_template('index.html', page='feed', title='Лента', profile=profile, posts=posts)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE email = ?", (current_user.id,))
        user = c.fetchone()
        if not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
            flash('Текущий пароль неверный!', 'error')
        elif new_password != confirm_password:
            flash('Пароли не совпадают!', 'error')
        else:
            hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            c.execute("UPDATE users SET password = ? WHERE email = ?", (hashed, current_user.id))
            conn.commit()
            flash('Пароль успешно изменён!', 'success')
        conn.close()
    return render_template('index.html', page='settings', title='Настройки', profile=profile)

@app.route('/store', methods=['GET', 'POST'])
@login_required
def store():
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE email = ?", (current_user.id,))
    balance = c.fetchone()['balance']
    c.execute("SELECT id, username, price FROM nft_usernames WHERE owner_email IS NULL")
    items = c.fetchall()
    is_ceo = current_user.id == 'ceo@example.com'  # Замените на реальную проверку
    if request.method == 'POST':
        item_id = request.form.get('item_id')
        c.execute("SELECT price FROM nft_usernames WHERE id = ? AND owner_email IS NULL", (item_id,))
        item = c.fetchone()
        if item and balance >= item['price']:
            c.execute("UPDATE users SET balance = balance - ? WHERE email = ?", (item['price'], current_user.id))
            c.execute("UPDATE nft_usernames SET owner_email = ? WHERE id = ?", (current_user.id, item_id))
            c.execute(
                "UPDATE profiles SET has_nft = 1, nft_username = (SELECT username FROM nft_usernames WHERE id = ?) WHERE email = ?",
                (item_id, current_user.id))
            conn.commit()
            flash('NFT-username успешно куплен!', 'success')
        else:
            flash('Недостаточно монет или товар недоступен!', 'error')
        return redirect(url_for('store'))
    conn.close()
    return render_template('index.html', page='store', title='Магазин', balance=balance, items=items, is_ceo=is_ceo,
                           profile=profile)

@app.route('/add_nft_username', methods=['GET', 'POST'])
@login_required
def add_nft_username():
    if current_user.id != 'ceo@example.com':  # Замените на реальную проверку
        flash('Доступ запрещён!', 'error')
        return redirect(url_for('index'))
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))
    if request.method == 'POST':
        username = request.form.get('username')
        price = request.form.get('price')
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO nft_usernames (username, price) VALUES (?, ?)", (username, price))
            conn.commit()
            flash('NFT-username добавлен!', 'success')
            return redirect(url_for('store'))
        except sqlite3.IntegrityError:
            flash('Username уже существует!', 'error')
        finally:
            conn.close()
    return render_template('index.html', page='add_nft_username', title='Добавить NFT-username', profile=profile)

@app.route('/issue_coins', methods=['GET', 'POST'])
@login_required
def issue_coins():
    if current_user.id != 'ceo@example.com':  # Замените на реальную проверку
        flash('Доступ запрещён!', 'error')
        return redirect(url_for('index'))
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))
    if request.method == 'POST':
        recipient = request.form.get('recipient')
        coins = request.form.get('coins')
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email FROM users WHERE email = ? OR login = ?", (recipient, recipient))
        user = c.fetchone()
        if user:
            c.execute("UPDATE users SET balance = balance + ? WHERE email = ?", (coins, user['email']))
            conn.commit()
            flash('Монеты выданы!', 'success')
        else:
            flash('Пользователь не найден!', 'error')
        conn.close()
        return redirect(url_for('issue_coins'))
    return render_template('index.html', page='issue_coins', title='Выдать монеты', profile=profile)

@app.route('/messages', methods=['GET', 'POST'])
@app.route('/messages/<username>')
@login_required
def messages(username=None):
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'POST':
        receiver_username = request.form.get('receiver_username')
        content = request.form.get('content')
        c.execute("SELECT email FROM profiles WHERE username = ?", (receiver_username,))
        receiver = c.fetchone()
        if not receiver:
            flash('Пользователь не найден!', 'error')
        else:
            c.execute("INSERT INTO messages (sender_email, receiver_email, content) VALUES (?, ?, ?)",
                      (current_user.id, receiver['email'], content))
            conn.commit()
            flash('Сообщение отправлено!', 'success')
        return redirect(url_for('messages'))

    # Получение диалогов
    c.execute("""
        SELECT DISTINCT p.username, p.nickname 
        FROM messages m 
        JOIN profiles p ON p.email = CASE WHEN m.sender_email = ? THEN m.receiver_email ELSE m.sender_email END
        WHERE m.sender_email = ? OR m.receiver_email = ?
    """, (current_user.id, current_user.id, current_user.id))
    conversations = c.fetchall()

    # Получение групповых чатов
    c.execute("""
        SELECT gc.id, gc.name 
        FROM group_chats gc 
        JOIN group_chat_members gcm ON gc.id = gcm.chat_id 
        WHERE gcm.user_email = ?
    """, (current_user.id,))
    group_chats = c.fetchall()

    selected_conversation = None
    messages = []
    if username:
        c.execute("SELECT email FROM profiles WHERE username = ?", (username,))
        receiver = c.fetchone()
        if receiver:
            selected_conversation = username
            c.execute("""
                SELECT m.content, m.created_at, p.nickname 
                FROM messages m 
                JOIN profiles p ON p.email = m.sender_email 
                WHERE (m.sender_email = ? AND m.receiver_email = ?) OR (m.sender_email = ? AND m.receiver_email = ?)
                ORDER BY m.created_at
            """, (current_user.id, receiver['email'], receiver['email'], current_user.id))
            messages = c.fetchall()

    conn.close()
    return render_template('index.html', page='messages', title='Сообщения', profile=profile,
                           conversations=conversations,
                           selected_conversation=selected_conversation, messages=messages,
                           group_chats=group_chats)

@app.route('/communities', methods=['GET', 'POST'])
@app.route('/communities/<int:community_id>')
@login_required
def communities(community_id=None):
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
            c.execute("INSERT INTO communities (name, description, creator_email) VALUES (?, ?, ?)",
                      (name, description, current_user.id))
            conn.commit()
            flash('Сообщество создано!', 'success')
        elif action == 'join':
            community_id = request.form.get('community_id')
            c.execute("INSERT OR IGNORE INTO community_members (community_id, user_email) VALUES (?, ?)",
                      (community_id, current_user.id))
            conn.commit()
            flash('Вы вступили в сообщество!', 'success')
        elif action == 'post':
            community_id = request.form.get('community_id')
            content = request.form.get('content')
            c.execute("INSERT INTO community_posts (community_id, user_email, content) VALUES (?, ?, ?)",
                      (community_id, current_user.id, content))
            conn.commit()
            flash('Пост опубликован!', 'success')
        return redirect(url_for('communities'))

    c.execute(
        "SELECT id, name, description, (SELECT nickname FROM profiles WHERE email = creator_email) FROM communities")
    all_communities = c.fetchall()
    c.execute(
        "SELECT c.id, c.name, c.description FROM communities c JOIN community_members cm ON c.id = cm.community_id WHERE cm.user_email = ?",
        (current_user.id,))
    my_communities = c.fetchall()

    selected_community = None
    community_posts = []
    if community_id:
        c.execute("SELECT name FROM communities WHERE id = ?", (community_id,))
        community = c.fetchone()
        if community:
            selected_community = community['name']
            c.execute("""
                SELECT cp.content, cp.created_at, p.nickname 
                FROM community_posts cp 
                JOIN profiles p ON p.email = cp.user_email 
                WHERE cp.community_id = ? 
                ORDER BY cp.created_at DESC
            """, (community_id,))
            community_posts = c.fetchall()

    conn.close()
    return render_template('index.html', page='communities', title='Сообщества', profile=profile,
                           all_communities=all_communities,
                           my_communities=my_communities, selected_community=selected_community,
                           community_posts=community_posts,
                           selected_community_id=community_id)

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
            c.execute("INSERT INTO clans (name, description, leader_email) VALUES (?, ?, ?)",
                      (name, description, current_user.id))
            conn.commit()
            flash('Клан создан!', 'success')
        elif action == 'join':
            invite_code = request.form.get('invite_code')
            c.execute("SELECT clan_id FROM clan_invites WHERE code = ?", (invite_code,))
            clan = c.fetchone()
            if clan:
                c.execute("INSERT OR IGNORE INTO clan_members (clan_id, user_email) VALUES (?, ?)",
                          (clan['clan_id'], current_user.id))
                conn.commit()
                flash('Вы вступили в клан!', 'success')
            else:
                flash('Неверный инвайт-код!', 'error')
        elif action == 'create_invite':
            clan_id = request.form.get('clan_id')
            c.execute("SELECT leader_email FROM clans WHERE id = ?", (clan_id,))
            clan = c.fetchone()
            if clan and clan['leader_email'] == current_user.id:
                import uuid
                code = str(uuid.uuid4())
                c.execute("INSERT INTO clan_invites (clan_id, code) VALUES (?, ?)", (clan_id, code))
                conn.commit()
                flash(f'Инвайт-код: {code}', 'success')
            else:
                flash('Вы не лидер этого клана!', 'error')
        return redirect(url_for('clans'))

    c.execute(
        "SELECT c.id, c.name, c.description FROM clans c JOIN clan_members cm ON c.id = cm.clan_id WHERE cm.user_email = ?",
        (current_user.id,))
    my_clans = c.fetchall()
    c.execute("SELECT id, name, description FROM clans WHERE leader_email = ?", (current_user.id,))
    my_led_clans = c.fetchall()

    conn.close()
    return render_template('index.html', page='clans', title='Кланы', profile=profile, my_clans=my_clans,
                           my_led_clans=my_led_clans)

@app.route('/create_nft_username', methods=['GET', 'POST'])
@login_required
def create_nft_username():
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE email = ?", (current_user.id,))
    balance = c.fetchone()['balance']
    if request.method == 'POST':
        username = request.form.get('username')
        if balance >= 500:
            c.execute("INSERT INTO nft_usernames (username, price, owner_email) VALUES (?, ?, ?)",
                      (username, 500, current_user.id))
            c.execute("UPDATE users SET balance = balance - 500 WHERE email = ?", (current_user.id,))
            c.execute("UPDATE profiles SET has_nft = 1, nft_username = ? WHERE email = ?", (username, current_user.id))
            conn.commit()
            flash('NFT-username создан!', 'success')
            return redirect(url_for('profile_view', username=profile['username']))
        else:
            flash('Недостаточно монет!', 'error')
    conn.close()
    return render_template('index.html', page='create_nft_username', title='Создать NFT-username', balance=balance,
                           profile=profile)

@app.route('/create_group_chat', methods=['POST'])
@login_required
def create_group_chat():
    chat_name = request.form.get('chat_name')
    members_raw = request.form.get('members')

    if not chat_name or not members_raw:
        flash('Заполните все поля', 'error')
        return redirect(url_for('messages'))

    members = [username.strip() for username in members_raw.split(',') if username.strip()]
    conn = get_db_connection()
    c = conn.cursor()

    # Создание чата
    c.execute("INSERT INTO group_chats (name, creator_email) VALUES (?, ?)", (chat_name, current_user.id))
    chat_id = c.lastrowid

    # Добавить создателя в участники
    c.execute("INSERT INTO group_chat_members (chat_id, user_email) VALUES (?, ?)", (chat_id, current_user.id))

    # Добавить остальных участников
    for username in members:
        c.execute("SELECT email FROM profiles WHERE username = ?", (username,))
        user = c.fetchone()
        if user:
            c.execute("INSERT INTO group_chat_members (chat_id, user_email) VALUES (?, ?)", (chat_id, user['email']))

    conn.commit()
    conn.close()

    flash('Групповой чат создан!', 'success')
    return redirect(url_for('messages'))

@app.route('/group_chat/<int:chat_id>', methods=['GET', 'POST'])
@login_required
def group_chat(chat_id):
    profile = get_profile(current_user.id)
    if not profile:
        return redirect(url_for('create_profile'))
    conn = get_db_connection()
    c = conn.cursor()

    # Проверка, является ли пользователь участником чата
    c.execute("SELECT 1 FROM group_chat_members WHERE chat_id = ? AND user_email = ?", (chat_id, current_user.id))
    if not c.fetchone():
        conn.close()
        flash('У вас нет доступа к этому чату!', 'error')
        return redirect(url_for('messages'))

    # Получение имени чата
    c.execute("SELECT name FROM group_chats WHERE id = ?", (chat_id,))
    chat = c.fetchone()
    if not chat:
        conn.close()
        flash('Чат не найден!', 'error')
        return redirect(url_for('messages'))
    chat_name = chat['name']

    # Обработка отправки сообщения
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            c.execute("INSERT INTO group_chat_messages (chat_id, user_email, content) VALUES (?, ?, ?)",
                      (chat_id, current_user.id, content))
            conn.commit()
            flash('Сообщение отправлено!', 'success')
        return redirect(url_for('group_chat', chat_id=chat_id))

    # Получение сообщений чата
    c.execute("""
        SELECT gcm.content, gcm.created_at, p.nickname 
        FROM group_chat_messages gcm 
        JOIN profiles p ON p.email = gcm.user_email 
        WHERE gcm.chat_id = ? 
        ORDER BY gcm.created_at ASC
    """, (chat_id,))
    group_messages = c.fetchall()

    conn.close()
    return render_template('index.html', page='group_chat', title=f'Групповой чат: {chat_name}', profile=profile,
                           chat_name=chat_name, group_messages=group_messages, selected_chat_id=chat_id)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
else:
    application = app

def get_balance(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT coins FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else 0


@app.route('/set_role', methods=['POST'])
@login_required
def set_role():
    if current_user.role != 'admin' and current_user.role != 'ceo':
        flash('Недостаточно прав', 'error')
        return redirect('/')
    target_username = request.form['username']
    new_role = request.form['role']
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET role = ? WHERE username = ?", (new_role, target_username))
    conn.commit()
    conn.close()
    flash(f'Роль пользователя @{target_username} изменена на [{new_role}]', 'success')
    return redirect('/')
