from pymongo import MongoClient

def check_local():
    print("Checking LOCAL database (mongodb://localhost:27017)...")
    try:
        client = MongoClient("mongodb://localhost:27017/")
        db = client["rooh_pms"]
        
        users = db.users.count_documents({})
        patients = db.patients.count_documents({})
        
        print(f"LOCAL Users: {users}")
        print(f"LOCAL Patients: {patients}")
        
        if users > 0:
            print("FOUND YOUR OLD DATA!")
    except Exception as e:
        print(f"Could not connect to local DB: {e}")

if __name__ == "__main__":
    check_local()
