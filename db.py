import sqlite3

DB_PATH = "db/users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # جدول کاربران
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        role TEXT NOT NULL DEFAULT 'guest',
        public_key TEXT NOT NULL
    )
    ''')
    
    conn.commit()
    conn.close()

def add_user(username, public_key, role="guest"):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO users (username, public_key, role) VALUES (?, ?, ?)',
              (username, public_key, role))
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    return user

def update_role(username, new_role):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE users SET role = ? WHERE username = ?', (new_role, username))
    conn.commit()
    conn.close()

def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT username, role FROM users')
    users = c.fetchall()
    conn.close()
    return users

if __name__ == "__main__":
    init_db()
    print("✅ Database initialized!")

