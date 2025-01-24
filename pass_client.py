import socket
import tkinter as tk
from tkinter import messagebox
import time  
import re
from selenium import webdriver  # type: ignore
from selenium.webdriver.common.keys import Keys  # type: ignore
from selenium.webdriver.chrome.options import Options # type: ignore
from webdriver_manager.chrome import ChromeDriverManager  # type: ignore

def validate_input(username=None, password=None, service=None, service_username=None): #להוריד השתגים בגרסה אמיתית
    """Validate input fields with basic security checks."""
    #if username and not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
      #  return False, "Username must be 3-20 alphanumeric characters or underscore"
  #  if password and len(password) < 8:
      #  return False, "Password must be at least 8 characters long"
  #  if service and not re.match(r'^[a-zA-Z0-9_\- ]+$', service):
        #return False, "Invalid service name"
    
    return True, "Valid input"

def send_request(request):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect(("127.0.0.1", 9999))  # Ensure server is running at this address
            client.send(request.encode('utf-8'))
            response = client.recv(1024).decode('utf-8')
        return response
    except ConnectionRefusedError:
        return "Error: Could not connect to server"
    except Exception as e:
        return f"Error: {e}"

def register_user():
    username = username_entry.get().strip()
    password = password_entry.get()
    
    valid, message = validate_input(username=username, password=password)
    if not valid:
        messagebox.showwarning("Input Error", message)
        return
    
    request = f"REGISTER:{username}:{password}"  # Ensure correct format
    response = send_request(request)
    messagebox.showinfo("Registration", response)

def login_user():
    global logged_in_user
    username = username_entry.get().strip()
    password = password_entry.get()
    
    valid, message = validate_input(username=username, password=password)
    if not valid:
        messagebox.showwarning("Input Error", message)
        return
    
    request = f"LOGIN:{username}:{password}"  # Ensure correct format
    response = send_request(request)
    
    if response == "Login successful":
        logged_in_user = username
        show_password_management_frame()
    else:
        messagebox.showerror("Login Failed", response)

def save_password():
    service = service_name_entry.get().strip()
    service_username = service_username_entry.get().strip()
    password = service_password_entry.get()

    valid, message = validate_input(service=service, password=password)
    if not valid:
        messagebox.showwarning("Input Error", message)
        return
    
    if not logged_in_user:
        messagebox.showwarning("Error", "Please log in first")
        return

    request = f"SAVE_PASSWORD:{logged_in_user}:{service}:{service_username}:{password}"
    response = send_request(request)
    messagebox.showinfo("Save Password", response)

    service_password_entry.delete(0, tk.END)

def get_all_passwords():
    if not logged_in_user:
        messagebox.showwarning("Error", "Please log in first")
        return
    
    request = f"GET_ALL_PASSWORDS:{logged_in_user}"
    response = send_request(request)

    password_text.delete(1.0, tk.END)

    if response.startswith("Error") or response == "No passwords found":
        password_text.insert(tk.END, response)
        return
        
    for line in response.split("\n"):
        if line.strip():
            service, username, password = line.split(":", 2)
            display_text = f"Service: {service}\nUsername: {username}\nPassword: {password}\n{'-'*30}\n"
            password_text.insert(tk.END, display_text)
            
    populate_delete_options(response)

def populate_delete_options(password_list):
    delete_menu['menu'].delete(0, 'end')
    
    for line in password_list.split('\n'):
        if line.strip():
            service, _, _ = line.split(":", 2)  # Split only first 2 colons
            delete_menu['menu'].add_command(
                label=service, 
                command=tk._setit(delete_var, service)
            )
def delete_password():
    if not logged_in_user:
        messagebox.showwarning("Error", "Please log in first")
        return
    
    selected_service = delete_var.get()  # Remove service_name_entry parameter
    
    if not selected_service:
        messagebox.showwarning("Input Error", "Please select a service to delete.")
        return
    
    request = f"DELETE_PASSWORD:{logged_in_user}:{selected_service}"
    response = send_request(request)
    messagebox.showinfo("Delete Password", response)
    
    if response.startswith("Password"):
        get_all_passwords()

def logout():
    global logged_in_user
    logged_in_user = None
    
    username_entry.delete(0, tk.END)
    service_username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    service_name_entry.delete(0, tk.END)
    service_password_entry.delete(0, tk.END)
    password_text.delete(1.0, tk.END)
    
    delete_var.set('')
    
    show_login_frame()

def auto_fill_credentials():
    if not logged_in_user:
        messagebox.showwarning("Error", "Please log in first")
        return
    
    selected_service = delete_var.get()
    if not selected_service:
        messagebox.showwarning("Input Error", "Please select a service.")
        return

    request = f"GET_ALL_PASSWORDS:{logged_in_user}"
    response = send_request(request)
    
    if response.startswith("Error") or response == "No passwords found":
        messagebox.showwarning("Error", response)
        return

    username, password = None, None
    for line in response.split("\n"):
        if line.strip():
            service, service_username, service_password = line.split(":", 2)
            if service == selected_service:
                username = service_username
                password = service_password
                break

    if not username or not password:
        messagebox.showwarning("Error", "Credentials not found for the selected service.")
        return

    try:
        chrome_options = Options()
        chrome_options.add_experimental_option("detach", True)
        chrome_options.add_experimental_option("excludeSwitches", ['enable-automation'])
        driver = webdriver.Chrome(options=chrome_options)
        
        if selected_service.startswith("spotify"):
            driver.get("https://accounts.spotify.com/en/login")
            time.sleep(3)
            username_field = driver.find_element("id", "login-username")
            password_field = driver.find_element("id", "login-password")
            password_field.send_keys(Keys.ENTER)

            
        elif selected_service.startswith("wikipedia"):
            driver.get("https://en.wikipedia.org/w/index.php?title=Special:UserLogin")
            time.sleep(3)
            username_field = driver.find_element("id", "wpName1")
            password_field = driver.find_element("id", "wpPassword1")
            password_field.send_keys(Keys.ENTER)

            
        elif selected_service.startswith("google"):
            driver.get("https://accounts.google.com/signin")
            time.sleep(3)
            username_field = driver.find_element("name", "identifier")
            username_field.send_keys(username + Keys.ENTER)
            time.sleep(3)
            password_field = driver.find_element("name", "password")
            password_field.send_keys(Keys.ENTER)

            
        elif selected_service.startswith("facebook"):
            driver.get("https://www.facebook.com/login")
            time.sleep(3)
            username_field = driver.find_element("id", "email")
            password_field = driver.find_element("id", "pass")
            password_field.send_keys(Keys.ENTER)

            
        elif selected_service.startswith("amazon"):
            driver.get("https://www.amazon.com/log/s?k=log+in")
            time.sleep(3)
            username_field = driver.find_element("id", "ap_email")
            username_field.send_keys(username + Keys.ENTER)
            time.sleep(3)
            password_field = driver.find_element("id", "ap_password")
            password_field.send_keys(Keys.ENTER)

        
        username_field.send_keys(username)
        password_field.send_keys(password)

        password_field.send_keys(Keys.ENTER)

        
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to auto-fill: {str(e)}")
        driver.quit()

def show_password_management_frame():
    login_frame.pack_forget()
    password_management_frame.pack(padx=10, pady=10)

def show_login_frame():
    password_management_frame.pack_forget()
    login_frame.pack(padx=10, pady=10)

window = tk.Tk()
window.title("Secure Password Manager")
window.geometry("400x500")  # Set a default window size

# Global variable to store logged-in user
logged_in_user = None

# Login / Register Frame
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

# Password Management Frame
password_management_frame = tk.Frame(window)

# Existing elements...
tk.Label(password_management_frame, text="Service Name").grid(row=0, column=0, padx=5, pady=5)
service_name_entry = tk.Entry(password_management_frame, width=30)
service_name_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(password_management_frame, text="Service userName").grid(row=1, column=0, padx=5, pady=5)
service_username_entry = tk.Entry(password_management_frame, width=30)
service_username_entry.grid(row=1, column=1, padx=5, pady=5)

tk.Label(password_management_frame, text="Service Password").grid(row=2, column=0, padx=5, pady=5)
service_password_entry = tk.Entry(password_management_frame, show="*", width=30)
service_password_entry.grid(row=2, column=1, padx=5, pady=5)

save_button = tk.Button(password_management_frame, text="Save Password", command=save_password)
save_button.grid(row=3, column=0, padx=2, pady=5)

get_all_button = tk.Button(password_management_frame, text="Get All Passwords", command=get_all_passwords)
get_all_button.grid(row=3, column=1, padx=5, pady=5)

password_text = tk.Text(password_management_frame, width=50, height=10, wrap=tk.WORD)
password_text.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

# Choose password dropdown
delete_var = tk.StringVar()
delete_label = tk.Label(password_management_frame, text="Select Service")
delete_label.grid(row=5, column=0, padx=5, pady=5)
delete_menu = tk.OptionMenu(password_management_frame, delete_var, '')
delete_menu.grid(row=5, column=1, padx=5, pady=5)

delete_button = tk.Button(password_management_frame, text="Delete Password", command=delete_password)
delete_button.grid(row=6, column=0, columnspan=3, padx=5, pady=5)

autofill_button = tk.Button(password_management_frame, text="Autofill Password", command=auto_fill_credentials)
autofill_button.grid(row=6, column=0, columnspan=1, padx=5, pady=5)

logout_button = tk.Button(password_management_frame, text="Logout", command=logout)
logout_button.grid(row=7, column=0, columnspan=2, padx=2, pady=5)

window.mainloop()