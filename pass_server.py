import sqlite3
import socket
import threading
from cryptography.fernet import Fernet #type:ignore
import bcrypt #type:ignore 
import re 

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

def is_secure_password(password):
    #if len(password) < 8:
      #  return False
   # if not re.search(r"[A-Z]", password):  # At least one uppercase letter
    #    return False
 #   if not re.search(r"[a-z]", password):  # At least one lowercase letter
  #      return False
   # if not re.search(r"\d", password):  # At least one number
    #    return False
    return True

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
            service_username TEXT NOT NULL,
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

def handle_client(client_socket):
    try:
        request = client_socket.recv(1024).decode('utf-8')
        print(f"Received request: {request}")
        parts = request.split(":")

        if len(parts) < 2:
            client_socket.send("Error: Invalid request format".encode('utf-8'))
            return

        command = parts[0]

        if command == "REGISTER":
            if len(parts) == 3:
                username, password = parts[1], parts[2]
                response = register_user(username, password)
                client_socket.send(response.encode('utf-8'))
            else:
                client_socket.send("Error: Invalid registration request".encode('utf-8'))

        elif command == "LOGIN":
            if len(parts) == 3:
                username, password = parts[1], parts[2]
                response = login_user(username, password)
                client_socket.send(response.encode('utf-8'))
            else:
                client_socket.send("Error: Invalid login request".encode('utf-8'))

        elif command == "SAVE_PASSWORD":
            if len(parts) == 5:
                username, service, service_username, password = parts[1], parts[2], parts[3], parts[4]
                response = save_password(username, service, service_username, password)
                client_socket.send(response.encode('utf-8'))
            else:
                client_socket.send("Error: Invalid SAVE_PASSWORD request".encode('utf-8'))

        elif command == "GET_ALL_PASSWORDS":
            if len(parts) == 2:
                username = parts[1]
                response = get_all_passwords(username)
                client_socket.send(response.encode('utf-8'))
            else:
                client_socket.send("Error: Invalid GET_ALL_PASSWORDS request".encode('utf-8'))

        elif command == "DELETE_PASSWORD":
            if len(parts) == 3:
                username, service = parts[1], parts[2]
                response = delete_password(username, service)
                client_socket.send(response.encode('utf-8'))
            else:
                client_socket.send("Error: Invalid DELETE_PASSWORD request".encode('utf-8'))

        else:
            client_socket.send(f"Error: Unknown command {command}".encode('utf-8'))

    except Exception as e:
        print(f"Error handling request: {e}")
        client_socket.send(f"Error: {e}".encode('utf-8'))
    
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
    
def save_password(username, service, service_username, password):
    # Ensure the password is secure
    if not is_secure_password(password):
        return "Password is not secure. Please ensure it's at least 8 characters long, with upper and lower case letters, and numbers."
    
    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()
    
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    
    if user:
        # Encrypt the password before storing
        encrypted_password = encrypt_password(password)
        
        # Inserting the password into the database with service and service username
        c.execute('''
            INSERT INTO user_passwords (user_id, service_name, service_username, encrypted_password)
            VALUES (?, ?, ?, ?)
        ''', (user[0], service, service_username, encrypted_password))
        
        conn.commit()
        return "Password saved successfully"
    else:
        return "User not found"

    
def get_password(username, service, service_username): #retrieve a password for a user
    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()
    
    # Fix SQL syntax - add comma between selected columns
    c.execute('''
        SELECT user_passwords.encrypted_password, user_passwords.service_username
        FROM user_passwords
        JOIN users ON users.id = user_passwords.user_id   
        WHERE users.username = ? AND user_passwords.service_name = ? AND user_passwords.service_username = ?
    ''', (username, service, service_username))
    
    result = c.fetchone()
    conn.close()
    
    if result:
        try:
            decrypted_password = decrypt_password(result[0])
            return f"service: {service}, service username: {service_username}, service password: {decrypted_password}"
        except Exception as e:
            print(f"Error decrypting password: {e}")
            return "Error decrypting password"
    else:
        return "Service not found for user"

def get_all_passwords(username): #retrieve all passwords for a user
    conn = None
    try:
        conn = sqlite3.connect('password_server.db')
        c = conn.cursor()
        
        # First check if user exists
        c.execute("SELECT id FROM users WHERE username=?", (username,))
        user = c.fetchone()
        
        if not user:
            return "User not found"
        
        # Get all passwords for user
        c.execute("""
            SELECT service_name, service_username, encrypted_password 
            FROM user_passwords 
            WHERE user_id=?
        """, (user[0],))
        
        passwords = c.fetchall()
        
        if not passwords:
            return "No passwords found for this user."
            
        # Format each password entry
        formatted_passwords = []
        for service, service_username, encrypted_pass in passwords:
            try:
                decrypted = decrypt_password(encrypted_pass)
                formatted_passwords.append(f"{service}:{service_username}:{decrypted}")
            except Exception as e:
                print(f"Error decrypting password for {service}: {e}")
                continue
        
        return "\n".join(formatted_passwords)
        
    except Exception as e:
        print(f"Database error: {e}")
        return f"Error retrieving passwords: {str(e)}"
    finally:
        if conn:
            conn.close()
    
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

def delete_password(username, service):
    conn = sqlite3.connect('password_server.db')
    c = conn.cursor()
    
    c.execute("SELECT id FROM users WHERE username=?", (username,))
    user = c.fetchone()
    
    if not user:
        return "User not found"
    
    user_id = user[0]
    
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
