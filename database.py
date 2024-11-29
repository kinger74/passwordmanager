import sqlite3
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify
import bcrypt


app = Flask(__name__)

# Generate and save the key (only need to do this once)
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Load the encryption key
def load_key():
    return open("secret.key", "rb").read()

# Initialize the database
def create_db():
    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')

    # Create passwords table (to store encrypted passwords)
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            service_name TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()

def encrypt_password(password: str) -> str:
    fernet = Fernet(load_key())
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password.decode()

# Decrypt password
def decrypt_password(encrypted_password: str) -> str:
    fernet = Fernet(load_key())
    decrypted_password = fernet.decrypt(encrypted_password.encode())
    return decrypted_password.decode()

# Hash password for user authentication
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

# Check password for user authentication
def check_password(hashed_password: str, password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# Register user route
@app.route('/register', methods=['POST'])
def register_user():
    username = request.json.get('username')
    password = request.json.get('password')

    print(f"Received request to register: {username}, {password}")

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    hashed_password = hash_password(password)

    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()

    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        print("User registered successfully")
        return jsonify({'message': 'User registered successfully'}), 201
    except sqlite3.IntegrityError:
        print("Username already exists")
        return jsonify({'message': 'Username already exists'}), 400
    finally:
        conn.close()


# Login user route
@app.route('/login', methods=['POST'])
def login_user():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()

    c.execute("SELECT id, password FROM users WHERE username=?", (username,))
    user = c.fetchone()

    if user and check_password(user[1], password):
        return jsonify({'message': 'Login successful', 'user_id': user[0]}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# Store password route (requires authentication)
@app.route('/store_password', methods=['POST'])
def store_password():
    try:
        data = request.get_json()  # Get the data sent in the request
        user_id = data.get('user_id')
        service_name = data.get('service_name')
        password = data.get('password')

        if not all([user_id, service_name, password]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Encrypt the password
        encrypted_password = encrypt_password(password)  # Proper encryption

        # Connect to the database and insert the password
        conn = sqlite3.connect('password_server.db')
        c = conn.cursor()
        c.execute("INSERT INTO user_passwords (user_id, service_name, encrypted_password) VALUES (?, ?, ?)",
                  (user_id, service_name, encrypted_password))
        conn.commit()
        conn.close()

        return jsonify({'message': 'Password stored successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# View stored passwords route (requires authentication)
@app.route('/view_passwords', methods=['GET'])
def view_passwords():
    user_id = request.args.get('user_id')  # Get user_id from query params
    
    if not user_id:
        return jsonify({"error": "User ID is required"}), 400
    
    # Connect to the database and fetch stored passwords
    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()
    c.execute("SELECT service_name, encrypted_password FROM user_passwords WHERE user_id=?", (user_id,))
    passwords = c.fetchall()
    conn.close()

    if passwords:
        return jsonify([{'service_name': service, 'encrypted_password': encrypted_password} for service, encrypted_password in passwords]), 200
    else:
        return jsonify({"message": "No passwords found for this user"}), 404


# Update password route (requires authentication)
@app.route('/update_password', methods=['PUT'])
def update_password():
    user_id = request.json.get('user_id')
    service_name = request.json.get('service_name')
    new_password = request.json.get('new_password')

    if not user_id or not service_name or not new_password:
        return jsonify({'message': 'User ID, service name, and new password are required'}), 400

    encrypted_password = encrypt_password(new_password)

    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()

    c.execute("UPDATE user_passwords SET encrypted_password=? WHERE user_id=? AND service_name=?",
              (encrypted_password, user_id, service_name))
    conn.commit()

    if c.rowcount == 0:
        return jsonify({'message': 'No matching password found to update'}), 404

    conn.close()

    return jsonify({'message': 'Password updated successfully'}), 200

# Delete password route (requires authentication)
@app.route('/delete_password', methods=['DELETE'])
def delete_password():
    user_id = request.json.get('user_id')
    service_name = request.json.get('service_name')

    if not user_id or not service_name:
        return jsonify({'message': 'User ID and service name are required'}), 400

    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()

    c.execute("DELETE FROM user_passwords WHERE user_id=? AND service_name=?", (user_id, service_name))
    conn.commit()

    if c.rowcount == 0:
        return jsonify({'message': 'No matching password found to delete'}), 404

    conn.close()

    return jsonify({'message': 'Password deleted successfully'}), 200

if __name__ == '__main__':
    create_db()  # Ensure the database and tables are created
    app.run(debug=True)
