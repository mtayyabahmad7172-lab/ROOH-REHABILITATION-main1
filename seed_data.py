from pymongo import MongoClient
import os
from datetime import datetime, timedelta
import random
from werkzeug.security import generate_password_hash
from bson.objectid import ObjectId
from dotenv import load_dotenv

load_dotenv()

import certifi

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/rooh_pms")
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db_name = MONGO_URI.split('/')[-1].split('?')[0] or 'RoohPMS'
db = client[db_name]

def seed_users():
    print("Seeding Users...")
    users = [
        {"username": "doctor1", "role": "Doctor", "name": "Dr. Sarah Khan"},
        {"username": "psych1", "role": "Psychologist", "name": "Dr. Ali Raza"},
        {"username": "canteen1", "role": "Canteen", "name": "Bilal Ahmed"},
        {"username": "staff1", "role": "General Staff", "name": "Noman"}
    ]
    
    for u in users:
        if not db.users.find_one({"username": u['username']}):
            u['password'] = generate_password_hash("password123")
            u['email'] = f"{u['username']}@roohrehab.com"
            u['created_at'] = datetime.now()
            db.users.insert_one(u)
            print(f"Created user: {u['username']}")

def seed_patients():
    print("Seeding Patients...")
    names = ["Ahmed Khan", "Mohammad Ali", "Fatima Bibi", "Zainab Noor", "Usman Ghani", "Hassan Raza", "Ayesha Siddiqa", "Bilal Ahmed", "Omar Farooq", "Khadija Tul Kubra"]
    
    # Check if we already have patients
    if db.patients.count_documents({}) > 5:
        print("Patients already exist, skipping...")
        return

    for i, name in enumerate(names):
        is_discharged = random.choice([True, False]) if i > 6 else False
        admission_date = datetime.now() - timedelta(days=random.randint(5, 120))
        
        patient = {
            "name": name,
            "fatherName": f"Father of {name.split()[0]}",
            "age": str(random.randint(18, 65)),
            "cnic": f"35202-{random.randint(1000000,9999999)}-{random.randint(1,9)}",
            "contactNo": f"0300{random.randint(1000000,9999999)}",
            "address": f"House {random.randint(1,100)}, Street {random.randint(1,20)}, Lahore",
            "monthlyFee": str(random.choice([30000, 45000, 60000, 25000])),
            "admissionDate": admission_date.isoformat(),
            "drug": random.choice(["Heroin", "Ice", "Alcohol", "Cannabis", "Tablets"]),
            "receivedAmount": str(random.randint(5000, 20000)),
            "laundryStatus": random.choice([True, False]),
            "laundryAmount": 3500,
            "isDischarged": is_discharged,
            "created_at": admission_date
        }
        
        if is_discharged:
            discharge_date = admission_date + timedelta(days=random.randint(10, 60))
            if discharge_date > datetime.now(): discharge_date = datetime.now()
            patient["dischargeDate"] = discharge_date.isoformat()
            
        result = db.patients.insert_one(patient)
        pid = result.inserted_id
        
        # Add some canteen sales for this patient
        seed_canteen_sales(pid)
        print(f"Created patient: {name}")

def seed_canteen_sales(patient_id):
    items = [
        {"item": "Tea", "amount": 50},
        {"item": "Biscuits", "amount": 30},
        {"item": "Juice", "amount": 40},
        {"item": "Cigarettes", "amount": 500},
        {"item": "Soap", "amount": 120},
        {"item": "Shampoo", "amount": 10},
        {"item": "Meal", "amount": 250}
    ]
    
    num_sales = random.randint(3, 10)
    for _ in range(num_sales):
        sale_item = random.choice(items)
        sale_date = datetime.now() - timedelta(days=random.randint(0, 30))
        sale = {
            "patient_id": patient_id,
            "item": sale_item["item"],
            "amount": sale_item["amount"],
            "date": sale_date,
            "recorded_by": "admin"
        }
        db.canteen_sales.insert_one(sale)

def seed_expenses():
    print("Seeding Expenses...")
    categories = ["Kitchen", "Electricity", "Staff Salary", "Maintenance", "Medical Supplies"]
    
    # Check if we have expenses
    if db.expenses.count_documents({}) > 10:
        print("Expenses already exist, skipping...")
        return

    for _ in range(15):
        is_incoming = random.choice([True, False, False]) # More outgoing
        amount = random.randint(500, 15000)
        date = datetime.now() - timedelta(days=random.randint(0, 60))
        
        expense = {
            "type": "incoming" if is_incoming else "outgoing",
            "amount": amount,
            "category": "Donation" if is_incoming else random.choice(categories),
            "note": "Auto generated seed data",
            "date": date,
            "recorded_by": "admin",
            "auto": False
        }
        db.expenses.insert_one(expense)
    print("Expenses seeded.")

if __name__ == "__main__":
    print("Starting database seed...")
    seed_users()
    seed_patients()
    seed_expenses()
    print("Database seeding completed!")
