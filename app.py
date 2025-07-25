from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3, os

app = Flask(__name__)
app.secret_key = 'super-rahasia'

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Buat folder jika belum ada
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ─────────────────────────────────────────────
# Buat DB jika belum ada
def init_db():
    if not os.path.exists('users.db'):
        conn = sqlite3.connect('users.db')
        conn.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                npm TEXT UNIQUE NOT NULL,
                jurusan TEXT NOT NULL,
                fakultas TEXT NOT NULL,
                password TEXT NOT NULL,
                foto TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                npm TEXT,
                aktivitas TEXT,
                waktu TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

init_db()

# Log aktivitas
def log(npm, aktivitas):
    conn = sqlite3.connect('users.db')
    conn.execute("INSERT INTO logs (npm, aktivitas) VALUES (?, ?)", (npm, aktivitas))
    conn.commit()
    conn.close()

# Validasi ekstensi file
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ─────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('auth.html')

# ─────────────────────────────────────────────
@app.route('/signup', methods=['POST'])
def signup():
    name = request.form['name']
    npm = request.form['npm']
    jurusan = request.form['jurusan']
    fakultas = request.form['fakultas']
    password = request.form['password']
    hashed_pw = generate_password_hash(password)

    try:
        conn = sqlite3.connect('users.db')
        conn.execute("INSERT INTO users (name, npm, jurusan, fakultas, password, foto) VALUES (?, ?, ?, ?, ?, ?)",
                     (name, npm, jurusan, fakultas, hashed_pw, 'default.png'))
        conn.commit()
        conn.close()
        flash("Akun berhasil dibuat.")
        log(npm, "Sign Up")
    except sqlite3.IntegrityError:
        flash("NPM sudah digunakan.")
    return redirect(url_for('index'))

# ─────────────────────────────────────────────
@app.route('/login', methods=['POST'])
def login():
    npm = request.form['npm']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE npm = ?", (npm,))
    user = cur.fetchone()
    conn.close()

    if user and check_password_hash(user[5], password):
        session['username'] = user[1]
        session['npm'] = user[2]
        flash("Login berhasil.")
        log(npm, "Login")
        return redirect(url_for('dashboard'))
    else:
        flash("NPM atau password salah.")
        return redirect(url_for('index'))

# ─────────────────────────────────────────────
@app.route('/dashboard')
def dashboard():
    if 'npm' not in session:
        return redirect(url_for('index'))

    npm = session['npm']
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE npm = ?", (npm,)).fetchone()
    logs = conn.execute("SELECT * FROM logs WHERE npm = ? ORDER BY waktu DESC", (npm,)).fetchall()
    conn.close()
    return render_template('dashboard.html', user=user, logs=logs)

# ─────────────────────────────────────────────
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'npm' not in session:
        return redirect(url_for('index'))

    npm = session['npm']
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE npm = ?", (npm,)).fetchone()

    if request.method == 'POST':
        name = request.form['name']
        jurusan = request.form['jurusan']
        fakultas = request.form['fakultas']

        foto = user['foto']
        if 'foto' in request.files:
            file = request.files['foto']
            if file and file.filename != '':
                if not allowed_file(file.filename):
                    flash("Format file tidak didukung.")
                    return redirect(url_for('edit_profile'))

                file.seek(0, os.SEEK_END)
                size = file.tell()
                file.seek(0)

                if size > MAX_FILE_SIZE:
                    flash("Ukuran file terlalu besar (maksimal 2 MB).")
                    return redirect(url_for('edit_profile'))

                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                foto = filename

        conn.execute("UPDATE users SET name=?, jurusan=?, fakultas=?, foto=? WHERE npm=?",
                     (name, jurusan, fakultas, foto, npm))
        conn.commit()
        conn.close()
        flash("Profil berhasil diperbarui.")
        log(npm, "Edit Profil")
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('edit_profile.html', user=user)

# ─────────────────────────────────────────────
@app.route('/change_password', methods=['POST'])
def change_password():
    if 'npm' not in session:
        return redirect(url_for('index'))

    npm = session['npm']
    old_pw = request.form['old_pw']
    new_pw = request.form['new_pw']

    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE npm = ?", (npm,))
    row = cur.fetchone()

    if row and check_password_hash(row[0], old_pw):
        new_hash = generate_password_hash(new_pw)
        conn.execute("UPDATE users SET password=? WHERE npm=?", (new_hash, npm))
        conn.commit()
        conn.close()
        flash("Password berhasil diganti.")
        log(npm, "Ganti Password")
    else:
        conn.close()
        flash("Password lama salah.")

    return redirect(url_for('edit_profile'))

# ─────────────────────────────────────────────
@app.route('/logout')
def logout():
    if 'npm' in session:
        log(session['npm'], "Logout")
    session.clear()
    flash("Logout berhasil.")
    return redirect(url_for('index'))

# ─────────────────────────────────────────────
if __name__ == '__main__':
    app.run()
