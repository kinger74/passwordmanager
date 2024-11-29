import sqlite3

def create_table():
    conn = sqlite3.connect('password_manager.db')  # Your database file path
    c = conn.cursor()
    
    # Create table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            service_name TEXT NOT NULL,
            encrypted_password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print("Table created successfully (if it didn't already exist).")

# Call the function to create the table
create_table()
