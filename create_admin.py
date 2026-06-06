import os
import sys
from datetime import datetime
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

import certifi

def create_admin_user():
    mongo_uri = os.environ.get("MONGO_URI")
    if not mongo_uri:
        print("ERROR: MONGO_URI environment variable is missing!")
        sys.exit(1)

    try:
        client = MongoClient(mongo_uri, tlsCAFile=certifi.where())
        db_name = mongo_uri.split('/')[-1].split('?')[0] or 'RoohPMS'
        db = client[db_name]
        
        username = "admin"
        password = "admin123"
        email = "admin@roohrehab.com"
        
        # Check if user exists
        user = db.users.find_one({"username": username})
        if user:
            print(f"User '{username}' already exists. Updating password...")
            db.users.update_one(
                {"username": username},
                {"$set": {"password": generate_password_hash(password)}}
            )
            print(f"Password updated for user '{username}' to '{password}'")
            return

        admin_user = {
            'username': username,
            'password': generate_password_hash(password),
            'role': 'Admin',
            'name': 'Admin User',
            'email': email,
            'created_at': datetime.now()
        }
        
        db.users.insert_one(admin_user)
        print(f"Successfully created admin user:")
        print(f"Username: {username}")
        print(f"Password: {password}")
        
    except Exception as e:
        print(f"Error creating user: {e}")

if __name__ == "__main__":
    create_admin_user()
