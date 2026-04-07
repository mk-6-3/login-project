from flask import Flask, request, jsonify
import mysql.connector
import bcrypt

from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Credentials from the original app.py
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "root",
    "database": "flask_app"
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

def init_db():
    # FIX: wrapped in try/except so startup doesn't crash if DB is temporarily unreachable
    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users_auth (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL
            )
        """)
        db.commit()
        cursor.close()
        db.close()
    except mysql.connector.Error as err:
        print(f"Warning: Could not initialize DB on startup: {err}")

init_db()

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Please provide both username and password"}), 400

    # FIX: strip whitespace from username
    username = data['username'].strip()
    password = data['password']

    # FIX: basic server-side password length validation
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    if not username:
        return jsonify({"error": "Username cannot be blank"}), 400

    # FIX: hash the password before storing (never store plaintext passwords)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    db = get_db_connection()
    cursor = db.cursor()
    try:
        sql = "INSERT INTO users_auth (username, password) VALUES (%s, %s)"
        val = (username, hashed_password)
        cursor.execute(sql, val)
        db.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except mysql.connector.Error as err:
        if err.errno == 1062:  # Duplicate entry
            return jsonify({"error": "Username already exists"}), 409
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Please provide both username and password"}), 400

    # FIX: strip whitespace from username
    username = data['username'].strip()
    password = data['password']

    db = get_db_connection()
    # FIX: fetch by username only, then verify password with bcrypt
    # (avoids timing attacks from comparing plaintext passwords in SQL)
    cursor = db.cursor(dictionary=True)
    try:
        sql = "SELECT * FROM users_auth WHERE username = %s"
        cursor.execute(sql, (username,))
        user = cursor.fetchone()

        # FIX: use bcrypt to verify; return proper JSON response (not a raw string)
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return jsonify({"message": "Login successful"}), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        db.close()

if __name__ == '__main__':
    app.run(debug=True, port=5001)
