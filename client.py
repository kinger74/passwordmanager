import socket
import tkinter as tk
from tkinter import messagebox, ttk
import re

# Improved error handling and input validation
def validate_input(username=None, password=None, service=None):
    """Validate input fields with basic security checks."""
    if username and not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return False, "Username must be 3-20 alphanumeric characters or underscore"
    
    if password and len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if service and not re.match(r'^[a-zA-Z0-9_\- ]+$', service):
        return False, "Invalid service name"
    
    return True, "Valid input"

# Function to send requests to the server and get responses
def send_request(request):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect(("127.0.0.1", 9999))
            client.send(request.encode('utf-8'))
            response = client.recv(1024).decode('utf-8')
        return response
    except ConnectionRefusedError:
        return "Error: Could not connect to server"
    except Exception as e:
        return f"Error: {e}"

# Function to handle user registration
def register_user():
    username = username_entry.get().strip()
    password = password_entry.get()
    
    valid, message = validate_input(username=username, password=password)
    if not valid:
        messagebox.showwarning("Input Error", message)
        return
    
    request = f"REGISTER:{username}:{password}"
    response = send_request(request)
    messagebox.showinfo("Registration", response)

# Function to handle user login
def login_user():
    global logged_in_user
    username = username_entry.get().strip()
    password = password_entry.get()
    
    valid, message = validate_input(username=username, password=password)
    if not valid:
        messagebox.showwarning("Input Error", message)
        return
    
    request = f"LOGIN:{username}:{password}"
    response = send_request(request)
    
    if response == "Login successful":
        logged_in_user = username
        show_password_management_frame()
    else:
        messagebox.showerror("Login Failed", response)

# Function to save a password for a service
def save_password():
    service = service_name_entry.get().strip()
    password = service_password_entry.get()
    
    valid, message = validate_input(service=service, password=password)
    if not valid:
        messagebox.showwarning("Input Error", message)
        return
    
    if not logged_in_user:
        messagebox.showwarning("Error", "Please log in first")
        return
    
    request = f"SAVE_PASSWORD:{logged_in_user}:{service}:{password}"
    response = send_request(request)
    messagebox.showinfo("Save Password", response)
    
    # Clear password entry after saving
    service_password_entry.delete(0, tk.END)

def get_all_passwords():
    if not logged_in_user:
        messagebox.showwarning("Error", "Please log in first")
        return
    
    request = f"GET_ALL_PASSWORDS:{logged_in_user}"
    response = send_request(request)
    
    if response.startswith("Error"):
        messagebox.showerror("Error", response)
    else:
        # Clear the text box before inserting new passwords
        password_text.delete(1.0, tk.END)
        password_text.insert(tk.END, response)
        
        # Populate delete dropdown
        populate_delete_options(response)

def populate_delete_options(password_list):
    # Clear existing options
    delete_menu['menu'].delete(0, 'end')
    
    # Split the response into lines and extract service names
    services = [service.strip() for service in password_list.split('\n') if service.strip()]
    for service in services:
        delete_menu['menu'].add_command(label=service, command=tk._setit(delete_var, service))

def delete_password():
    if not logged_in_user:
        messagebox.showwarning("Error", "Please log in first")
        return
    
    selected_service = delete_var.get()
    
    if not selected_service:
        messagebox.showwarning("Input Error", "Please select a service to delete.")
        return
    
    request = f"DELETE_PASSWORD:{logged_in_user}:{selected_service}"
    response = send_request(request)
    messagebox.showinfo("Delete Password", response)
    
    # After deletion, refresh the list of passwords
    if response.startswith("Password"):
        get_all_passwords()

# Function to logout and reset state
def logout():
    global logged_in_user
    logged_in_user = None
    
    # Clear entry fields
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    service_name_entry.delete(0, tk.END)
    service_password_entry.delete(0, tk.END)
    password_text.delete(1.0, tk.END)
    
    # Reset delete dropdown
    delete_var.set('')
    
    # Show login frame
    show_login_frame()

# Frame switching functions
def show_password_management_frame():
    login_frame.pack_forget()
    password_management_frame.pack(padx=10, pady=10)

def show_login_frame():
    password_management_frame.pack_forget()
    login_frame.pack(padx=10, pady=10)

# Creating the main window
window = tk.Tk()
window.title("Secure Password Manager")
window.geometry("400x500")  # Set a default window size

# Global variable to store logged-in user
logged_in_user = None

# -------------- Login / Register Frame --------------
login_frame = tk.Frame(window)

tk.Label(login_frame, text="Username").grid(row=0, column=0, padx=5, pady=5)
username_entry = tk.Entry(login_frame, width=30)
username_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(login_frame, text="Password").grid(row=1, column=0, padx=5, pady=5)
password_entry = tk.Entry(login_frame, show="*", width=30)
password_entry.grid(row=1, column=1, padx=5, pady=5)

register_button = tk.Button(login_frame, text="Register", command=register_user)
register_button.grid(row=3, column=1, padx=5, pady=5)

login_button = tk.Button(login_frame, text="Login", command=login_user)
login_button.grid(row=4, column=1, padx=5, pady=5)

login_frame.pack(padx=10, pady=10)

# -------------- Password Management Frame --------------
password_management_frame = tk.Frame(window)

tk.Label(password_management_frame, text="Service Name").grid(row=0, column=0, padx=5, pady=5)
service_name_entry = tk.Entry(password_management_frame, width=30)
service_name_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(password_management_frame, text="Service Password").grid(row=1, column=0, padx=5, pady=5)
service_password_entry = tk.Entry(password_management_frame, show="*", width=30)
service_password_entry.grid(row=1, column=1, padx=5, pady=5)

save_button = tk.Button(password_management_frame, text="Save Password", command=save_password)
save_button.grid(row=2, column=0, padx=5, pady=5)

get_all_button = tk.Button(password_management_frame, text="Get All Passwords", command=get_all_passwords)
get_all_button.grid(row=2, column=1, padx=5, pady=5)

# Text widget to display all passwords
password_text = tk.Text(password_management_frame, width=50, height=10, wrap=tk.WORD)
password_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

# Delete Password Dropdown
delete_var = tk.StringVar()
delete_label = tk.Label(password_management_frame, text="Select Service to Delete:")
delete_label.grid(row=4, column=0, padx=5, pady=5)
delete_menu = tk.OptionMenu(password_management_frame, delete_var, '')
delete_menu.grid(row=4, column=1, padx=5, pady=5)

delete_button = tk.Button(password_management_frame, text="Delete Password", command=delete_password)
delete_button.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

logout_button = tk.Button(password_management_frame, text="Logout", command=logout)
logout_button.grid(row=6, column=0, columnspan=2, padx=5, pady=5)

# Start the GUI event loop
window.mainloop()