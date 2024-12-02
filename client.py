import socket
import tkinter as tk
from tkinter import messagebox

# Function to send requests to the server and get responses
def send_request(request):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", 9999))  # Connect to the server at localhost, port 9999
        
        # Send the request to the server
        client.send(request.encode('utf-8'))
        
        # Receive and return the response from the server
        response = client.recv(1024).decode('utf-8')
        client.close()
        return response
    except Exception as e:
        return f"Error: {e}"

# Function to handle user registration
def register_user():
    username = username_entry.get()
    password = password_entry.get()
    
    if not username or not password:
        messagebox.showwarning("Input Error", "Both username and password are required.")
        return
    
    request = f"REGISTER:{username}:{password}"
    response = send_request(request)
    messagebox.showinfo("Response", response)

# Function to handle user login
def login_user():
    global logged_in_user
    username = username_entry.get()
    password = password_entry.get()
    
    if not username or not password:
        messagebox.showwarning("Input Error", "Both username and password are required.")
        return
    
    request = f"LOGIN:{username}:{password}"
    response = send_request(request)
    messagebox.showinfo("Response", response)
    
    if response == "Login successful":
        logged_in_user = username
        show_password_management_frame()

# Function to save a password for a service
def save_password():
    service = service_name_entry.get()
    password = service_password_entry.get()
    
    if not service or not password:
        messagebox.showwarning("Input Error", "Both service name and password are required.")
        return
    
    request = f"SAVE_PASSWORD:{logged_in_user}:{service}:{password}"
    response = send_request(request)
    messagebox.showinfo("Response", response)

# Function to get all passwords for the logged-in user
def get_all_passwords():
    # Request all passwords for the logged-in user
    request = f"GET_ALL_PASSWORDS:{logged_in_user}"
    response = send_request(request)
    
    if response.startswith("Error"):
        messagebox.showerror("Error", response)
    else:
        # Clear the text box before inserting the new passwords
        password_text.delete(1.0, tk.END)
        
        # Display all passwords in the text widget
        password_text.insert(tk.END, response)

# Function to show the password management frame after login
def show_password_management_frame():
    # Hide the login frame
    login_frame.pack_forget()
    
    # Show the password management frame
    password_management_frame.pack(padx=10, pady=10)

# Function to show the login frame when the user logs out
def show_login_frame():
    # Hide the password management frame
    password_management_frame.pack_forget()
    
    # Show the login frame
    login_frame.pack(padx=10, pady=10)

# Creating the main window (GUI)
window = tk.Tk()
window.title("Password Manager Client")

# Global variable to store logged-in user
logged_in_user = None

# -------------- Login / Register Frame --------------
login_frame = tk.Frame(window)

# Username and Password Entry Fields for Login/Register
tk.Label(login_frame, text="Username").grid(row=0, column=0, padx=5, pady=5)
username_entry = tk.Entry(login_frame)
username_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(login_frame, text="Password").grid(row=1, column=0, padx=5, pady=5)
password_entry = tk.Entry(login_frame, show="*")
password_entry.grid(row=1, column=1, padx=5, pady=5)

# Register and Login Buttons
register_button = tk.Button(login_frame, text="Register", command=register_user)
register_button.grid(row=2, column=0, padx=5, pady=5)

login_button = tk.Button(login_frame, text="Login", command=login_user)
login_button.grid(row=2, column=1, padx=5, pady=5)

login_frame.pack(padx=10, pady=10)  # Show the login frame initially

# -------------- Password Management Frame --------------
password_management_frame = tk.Frame(window)

# Service Name and Service Password Entry Fields
tk.Label(password_management_frame, text="Service Name").grid(row=0, column=0, padx=5, pady=5)
service_name_entry = tk.Entry(password_management_frame)
service_name_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(password_management_frame, text="Service Password").grid(row=1, column=0, padx=5, pady=5)
service_password_entry = tk.Entry(password_management_frame, show="*")
service_password_entry.grid(row=1, column=1, padx=5, pady=5)

# Save Password and Get All Passwords Buttons
save_button = tk.Button(password_management_frame, text="Save Password", command=save_password)
save_button.grid(row=2, column=0, padx=5, pady=5)

# Get All Passwords Button (Displays all stored passwords for the logged-in user)
get_all_button = tk.Button(password_management_frame, text="Get All Passwords", command=get_all_passwords)
get_all_button.grid(row=2, column=1, padx=5, pady=5)

# Text widget to display all passwords
password_text = tk.Text(password_management_frame, width=50, height=10)
password_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

# Logout Button
logout_button = tk.Button(password_management_frame, text="Logout", command=show_login_frame)
logout_button.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

# Start the GUI event loop
window.mainloop()
