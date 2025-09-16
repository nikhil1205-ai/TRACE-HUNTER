import firebase_admin
from firebase_admin import credentials
from firebase_admin import db

# Path to your downloaded service account key
cred = credentials.Certificate("serviceAccountKey.json")

# Initialize the Firebase app with database URL
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://tracehunter-78e86-default-rtdb.firebaseio.com'  # Replace with your DB URL
})

# Reference to a path in your database
ref = db.reference('test/hello')

# Write data to Firebase
ref.set({
    'message': 'Hello from Python!'
})

print("✅ Data written successfully.")

# Read data from Firebase
data = ref.get()
print("📥 Read from Firebase:", data)
