import sqlite3
import socket
import threading
from cryptography.fernet import Fernet #type:ignore
import bcrypt #type:ignore 
import re  # For regex-based password strength validation

# Generates and loads encryption keys
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

# Password strength validation function
def is_secure_password(password):
    # Password must be at least 8 characters long, include uppercase, lowercase, and numbers/special characters
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):  # At least one uppercase letter
        return False
    if not re.search(r"[a-z]", password):  # At least one lowercase letter
        return False
    if not re.search(r"\d", password):  # At least one number
        return False
    return True

# Database functions
def create_db():
    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
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

# Encrypt and decrypt passwords using Fernet
def encrypt_password(password: str) -> str:
    fernet = Fernet(load_key())
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password.decode()

def decrypt_password(encrypted_password: str) -> str:
    fernet = Fernet(load_key())
    decrypted_password = fernet.decrypt(encrypted_password.encode())
    return decrypted_password.decode()

# Hash and check passwords using bcrypt
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def check_password(hashed_password: str, password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# Function to handle client requests
def handle_client(client_socket):
    try:
        # Receive the data sent by the client
        request = client_socket.recv(1024).decode('utf-8')
        
        if request.startswith('REGISTER'):
            username, password = request.split(":")[1], request.split(":")[2]
            response = register_user(username, password)
        
        elif request.startswith('LOGIN'):
            username, password = request.split(":")[1], request.split(":")[2]
            response = login_user(username, password)
        
        elif request.startswith('SAVE_PASSWORD'):
            username, service, password = request.split(":")[1], request.split(":")[2], request.split(":")[3]
            response = save_password(username, service, password)
        
        elif request.startswith('GET_PASSWORD'):
            username, service = request.split(":")[1], request.split(":")[2]
            response = get_password(username, service)
        
        elif request.startswith('GET_ALL_PASSWORDS'):
            username = request.split(":")[1]
            response = get_all_passwords(username)
        
        elif request.startswith('DELETE_PASSWORD'):
            username, service = request.split(":")[1], request.split(":")[2]
            response = delete_password(username, service)
        
        else:
            response = "Invalid request"
        
        # Send the response back to the client
        client_socket.send(response.encode('utf-8'))
    
    finally:
        client_socket.close()

# Functions to register, login, save, and retrieve passwords
def register_user(username, password):
    # Ensure the password is secure
    if not is_secure_password(password):
        #(להוריד את זה עם ההשטג בגרסה הסופית)return "Password is not secure. Please ensure it's at least 8 characters long, with upper and lower case letters, and numbers."
        vruu=1 # גם את זה
     # Hash the password before saving
    hashed_password = hash_password(password)
    
    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()
    
    try:
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        return "Registration successful"
    except sqlite3.IntegrityError:
        return "Username already exists"
    finally:
        conn.close()

def login_user(username, password):
    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()
    
    c.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    
    if result and check_password(result[0], password):
        return "Login successful"
    else:
        return "Invalid credentials"
    
def save_password(username, service, password):
    # Ensure the password is secure
    #   להוריד את זה +השטגif not is_secure_password(password): return "Password is not secure. Please ensure it's at least 8 characters long, with upper and lower case letters, and numbers."

    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()
    
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    
    if user:
        encrypted_password = encrypt_password(password)
        c.execute('INSERT INTO user_passwords (user_id, service_name, encrypted_password) VALUES (?, ?, ?)',
                  (user[0], service, encrypted_password))
        conn.commit()
        return "Password saved successfully"
    else:
        return "User not found"
    
def get_password(username, service):
    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()
    
    c.execute('''
        SELECT user_passwords.encrypted_password
        FROM user_passwords
        JOIN users ON users.id = user_passwords.user_id
        WHERE users.username = ? AND user_passwords.service_name = ?
    ''', (username, service))
    
    result = c.fetchone()
    
    if result:
        decrypted_password = decrypt_password(result[0])
        return f"Password for {service}: {decrypted_password}"
    else:
        return "Service not found for user"
    
def delete_password(username, service):
    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()
    
    # Find the user by username
    c.execute("SELECT id FROM users WHERE username=?", (username,))
    user = c.fetchone()
    
    if not user:
        return "User not found"
    
    user_id = user[0]
    
    # Delete the password for the given service
    c.execute("DELETE FROM user_passwords WHERE user_id=? AND service_name=?", (user_id, service))
    conn.commit()
    
    if c.rowcount > 0:
        return f"Password for service '{service}' deleted successfully."
    else:
        return f"No password found for service '{service}' to delete."


#retrieve all passwords for a user
def get_all_passwords(username):
    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()
    
    c.execute("SELECT id FROM users WHERE username=?", (username,))
    user = c.fetchone()
    
    if not user:
        return "User not found"
    
    user_id = user[0]
    
    # Query for all passwords associated with this user
    c.execute("SELECT service_name, encrypted_password FROM user_passwords WHERE user_id=?", (user_id,))
    passwords = c.fetchall()
    
    if not passwords:
        return "No passwords found for this user."
    
    # Decrypt and return the list of all passwords
    password_list = "\n".join([f"{service}: {decrypt_password(encrypted_password)}" for service, encrypted_password in passwords])
    
    return password_list

# New function to delete a password for a user
def delete_password(username, service):
    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()
    
    c.execute("SELECT id FROM users WHERE username=?", (username,))
    user = c.fetchone()
    
    if not user:
        return "User not found"
    
    user_id = user[0]
    
    # Delete the password for the given service
    c.execute("DELETE FROM user_passwords WHERE user_id=? AND service_name=?", (user_id, service))
    conn.commit()
    
    if c.rowcount > 0:
        return f"Password for service '{service}' deleted successfully."
    else:
        return f"No password found for service '{service}' to delete."

# Function to start the server and listen for incoming connections
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9999))  # Bind to all interfaces, port 9999
    server.listen(5)
    print("Server listening on port 9999...")
    
    while True:
        client_socket, addr = server.accept()
        print(f"Connection from {addr}")
        
        # Handle client request in a separate thread
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

if __name__ == "__main__":
    # Initialize the database and encryption keys
    create_db()
    generate_key()  # Uncomment this line once to generate a new key
    
    # Start the server
    start_server()
