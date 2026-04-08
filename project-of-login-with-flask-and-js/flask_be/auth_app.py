from flask import Flask, request, jsonify
import mysql.connector

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

init_db()

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Please provide both username and password"}), 400

    username = data['username']
    password = data['password']

    db = get_db_connection()
    cursor = db.cursor()
    try:
        sql = "INSERT INTO users_auth (username, password) VALUES (%s, %s)"
        val = (username, password)
        cursor.execute(sql, val)
        db.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except mysql.connector.Error as err:
        if err.errno == 1062: # Duplicate entry
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

    username = data['username']
    password = data['password']

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        sql = "SELECT * FROM users_auth WHERE username = %s AND password = %s"
        val = (username, password)
        cursor.execute(sql, val)
        user = cursor.fetchone()
        
        if user:
            return "200 OK", 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        db.close()

if __name__ == '__main__':
    app.run(debug=True, port=5001)
