import requests
import json
import sqlite3

BASE_URL = "http://localhost:5000"  # Adjust if needed

def register_user(username, password):
    url = f"{BASE_URL}/register"
    payload = {"username": username, "password": password}
    headers = {"Content-Type": "application/json"}

    response = requests.post(url, data=json.dumps(payload), headers=headers)

    print("Response status code:", response.status_code)  # Print status code for debugging
    if response.status_code == 200 or response.status_code == 201:
        print(f"Registration successful: {response.json()['message']}")
    else:
        try:
            print(f"Error: {response.json()['message']}")
        except ValueError:
            print(f"Error: {response.text}")  # Print raw response text in case it's not JSON


def login_user(username, password):
    url = f"{BASE_URL}/login"
    payload = {"username": username, "password": password}
    headers = {"Content-Type": "application/json"}

    response = requests.post(url, data=json.dumps(payload), headers=headers)

    if response.status_code == 200:
        print("Login successful!")
        return response.json()['user_id']
    else:
        print(f"Error: {response.json()['message']}")
        return None

def store_password(user_id, service_name, password):
    url = 'http://localhost:5000/store_password'  # Define the URL for the store_password endpoint
    
    # Define the data dictionary with the parameters you want to send
    data = {
        'user_id': user_id,
        'service_name': service_name,
        'password': password
    }

    # Send the POST request with the data
    response = requests.post(url, json=data)

    # Check the server response
    if response.status_code == 200:
        print("Password stored successfully.")
    else:
        print(f"Error: {response.status_code} - {response.text}")

import requests

def view_passwords(user_id):
    url = 'http://localhost:5000/view_passwords'  # Correct endpoint

    # Send the GET request with the user_id as a query parameter
    response = requests.get(url, params={'user_id': user_id})

    if response.status_code == 200:
        passwords = response.json()  # Assuming the server returns a JSON with the passwords

        # Iterate over the returned passwords
        for password_info in passwords:
            service_name = password_info['service_name']
            encrypted_password = password_info['encrypted_password']
            print(f"Service: {service_name}, Encrypted Password: {encrypted_password}")
    else:
        print(f"Error: {response.status_code} - {response.text}")

def main():
    user_id = 1  # Example user_id
    view_passwords(user_id)


    # Display the results
    if rows:
        for row in rows:
            print(f"Service: {row[0]}, Encrypted Password: {row[1]}")
    else:
        print("No passwords found for this user.")
    
    conn.close()

# Sample function call
url = 'http://localhost:5000/store_password'  # Define the URL of your server's store_password endpoint
store_password(1, "example_service", "example_password")

def update_password(user_id, service_name, new_password):
    url = f"{BASE_URL}/update_password"
    payload = {"user_id": user_id, "service_name": service_name, "new_password": new_password}
    headers = {"Content-Type": "application/json"}

    response = requests.put(url, data=json.dumps(payload), headers=headers)

    if response.status_code == 200:
        print("Password updated successfully!")
    else:
        print(f"Error: {response.json()['message']}")

def delete_password(user_id, service_name):
    url = f"{BASE_URL}/delete_password"
    payload = {"user_id": user_id, "service_name": service_name}
    headers = {"Content-Type": "application/json"}

    response = requests.delete(url, data=json.dumps(payload), headers=headers)

    if response.status_code == 200:
        print("Password deleted successfully!")
    else:
        print(f"Error: {response.json()['message']}")

def main():
    print("Welcome to the password client!")
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Store Password")
        print("4. View Stored Passwords")
        print("5. Update Password")
        print("6. Delete Password")
        print("7. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            register_user(username, password)
        elif choice == '2':
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            user_id = login_user(username, password)
        elif choice == '3':
            if user_id:
                service_name = input("Enter service name: ")
                password = input("Enter password for the service: ")
                store_password(user_id, service_name, password)
            else:
                print("You need to log in first!")
        elif choice == '4':
            if user_id:
                view_passwords(user_id)
            else:
                print("You need to log in first!")
        elif choice == '5':
            if user_id:
                service_name = input("Enter service name: ")
                new_password = input("Enter new password: ")
                update_password(user_id, service_name, new_password)
            else:
                print("You need to log in first!")
        elif choice == '6':
            if user_id:
                service_name = input("Enter service name: ")
                delete_password(user_id, service_name)
            else:
                print("You need to log in first!")
        elif choice == '7':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
