import json
import os

USERS_FILE = 'users.json'
PASSWORDS_FILE = 'passwords.json'


def load_users():
    if not os.path.exists(USERS_FILE):
        save_users({})  # Create the file if it doesn't exist
    with open(USERS_FILE, 'r') as f:
        users = json.load(f)
        if not users:
            users = {'ADMIN': {'password': 'admin', 'role': 'admin'}}
            save_users(users)
        return users

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)


def load_passwords():
    if not os.path.exists(PASSWORDS_FILE):
        save_passwords({})  # Create the file if it doesn't exist
    with open(PASSWORDS_FILE, 'r') as f:
        return json.load(f)
    

def save_passwords(passwords):
    with open(PASSWORDS_FILE, 'w') as f:
        json.dump(passwords, f)