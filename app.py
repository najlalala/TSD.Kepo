from flask import Flask, render_template, request, redirect, url_for, flash, session
import re
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  

def init_sqlite_db():
    try:
        conn = sqlite3.connect('users.db')
        print("Opened database successfully")

        # Tabel pengguna untuk autentikasi
        conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, email TEXT, password TEXT)')
        
        # Tabel daftar nama anak, NIM, dan kolom angkatan
        conn.execute('CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, nim TEXT, batch INTEGER)')
        
        print("Tables created successfully")
        conn.close()
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")


# Inisialisasi database dan tambahkan data siswa
init_sqlite_db()

# Route halaman home
@app.route('/')
def home():
    if session.get('logged_in'):
        return render_template('index1.html')
    else:
        return render_template('index.html')

# Route halaman signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        # Validasi email dan password menggunakan RegEx yang baru
        if not re.match(r'^[a-zA-Z]+(\.[a-zA-Z]+){0,2}-[0-9]{4}@[a-zA-Z]{2,5}\.unair\.ac\.id$', email):
            flash('Email tidak valid! Pastikan menggunakan email UNAIR', 'danger')
            return redirect(url_for('signup'))
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', password):
            flash('Password harus minimal 8 karakter, mengandung huruf dan angka!', 'danger')
            return redirect(url_for('signup'))

        # Menggunakan metode hash yang benar 'pbkdf2:sha256'
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            with sqlite3.connect('users.db') as con:
                cur = con.cursor()
                # Memeriksa apakah email sudah terdaftar
                cur.execute("SELECT * FROM users WHERE email = ?", (email,))
                existing_user = cur.fetchone()
                if existing_user:
                    flash('Email sudah terdaftar, silakan gunakan email lain atau login.', 'warning')
                    return redirect(url_for('signup'))
                
                cur.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_password))
                con.commit()
                flash('Registrasi berhasil! Silakan login.', 'success')
                return redirect(url_for('login'))
        except sqlite3.Error as e:
            print(f"An error occurred: {e}")
            flash('Terjadi kesalahan saat mendaftar. Silakan coba lagi.', 'danger')

    return render_template('signup.html')

# Route halaman login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            with sqlite3.connect('users.db') as con:
                cur = con.cursor()
                cur.execute("SELECT * FROM users WHERE email = ?", (email,))
                user = cur.fetchone()
                if user and check_password_hash(user[3], password):
                    session['logged_in'] = True
                    session['username'] = user[1]
                    flash('Login berhasil!', 'success')
                    return redirect(url_for('search'))  # Redirect to the search page
                else:
                    flash('Email atau password salah!', 'danger')
        except sqlite3.Error as e:
            print(f"An error occurred: {e}")
            flash('Terjadi kesalahan saat login. Silakan coba lagi.', 'danger')

    return render_template('login.html')

# Route untuk pencarian data siswa setelah login
@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'logged_in' in session and session['logged_in']:
        if request.method == 'POST':
            search_query = request.form['search_query']

            try:
                with sqlite3.connect('users.db') as con:
                    cur = con.cursor()
                    # Mencari semua data siswa
                    cur.execute("SELECT * FROM students")
                    all_students = cur.fetchall()
                    
                # Filter hasil menggunakan regex
                pattern = re.compile(search_query, re.IGNORECASE)
                results = [student for student in all_students if pattern.search(student[1]) or pattern.search(student[2])]

                return render_template('search.html', results=results)
            except sqlite3.Error as e:
                print(f"An error occurred: {e}")
                flash('Terjadi kesalahan saat mencari data. Silakan coba lagi.', 'danger')
                return redirect(url_for('search'))
        
        return render_template('search.html', results=None)

    else:
        flash('Anda harus login terlebih dahulu.', 'danger')
        return redirect(url_for('login'))

# Route untuk logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Anda telah logout!', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
