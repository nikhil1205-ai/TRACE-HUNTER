from flask import Flask, render_template, redirect, url_for, request, jsonify
import firebase_admin
from firebase_admin import credentials, db
import re
import os
from src.predict_Model import *
import src.Prediction_network_analysis as network
import pandas as pd
import base64
import chardet
from google import genai
import requests
import ipaddress
import os
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

app = Flask(__name__)

# ========== DATABASE ==========
cred_path = os.path.join(os.getcwd(),'..','database', "serviceAccountKey.json")
cred = credentials.Certificate(cred_path)
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://tracehunter-78e86-default-rtdb.firebaseio.com' })
user_ref = db.reference('users')

# ========== GENAI/check_url ==========
client = genai.Client(api_key="AIzaSyDeixX-hHO3pXLNORhMjbKNMwsAPBcE3rs")
API_KEY = "23f983874e0f6d01d84bdfc89c808b364a5b5af1746e37e659f67d9c619a6135"  # Replace with your key
def get_gemini_response(question):
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=question
        )
        return response.text
    except Exception as e:
        return f"Error from Gemini: {e}"

def base64url_encode(url):
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.rstrip("=")

def check_url(url):
    headers = {"x-apikey": API_KEY}
    scan_response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )
    if scan_response.status_code != 200:
        return {"error": "Error submitting URL"}
    encoded_url_id = base64url_encode(url)
    result_response = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{encoded_url_id}",
        headers=headers
    )
    if result_response.status_code != 200:
        return {"error": "Error fetching scan result"}
    result = result_response.json()
    stats = result['data']['attributes']['last_analysis_stats']
    return {
        "malicious": stats.get('malicious', 0),
        "suspicious": stats.get('suspicious', 0),
        "harmless": stats.get('harmless', 0),
        "undetected": stats.get('undetected', 0)
    }



# ========== HasH/IP Address==========

hash_patterns = {
    "MD5": r"^[a-fA-F0-9]{32}$",
    "SHA1": r"^[a-fA-F0-9]{40}$",
    "SHA256": r"^[a-fA-F0-9]{64}$",
}

def check_input(value):
    try:
        ipaddress.ip_address(value)
        return {"type": "IP Address", "valid": True,"value":value}
    except ValueError:
        pass
    # Hash check
    for htype, pattern in hash_patterns.items():
        if re.match(pattern, value):
            return {"type": f"{htype} Hash", "valid": True,"value":value}

    return {"type": "Unknown", "valid": False ,"value":"No value"}


# ========== Image Forensics==========
def get_file_info(image_path):
    try:
        file_info = {}
        file_info["File Name"] = os.path.basename(image_path)
        file_info["File Size (KB)"] = round(os.path.getsize(image_path) / 1024, 2)

        with Image.open(image_path) as img:
            file_info["File Type"] = os.path.splitext(image_path)[1].replace(".", "").upper()
            file_info["Format"] = img.format
            file_info["Mode"] = img.mode
            file_info["Width"] = img.width
            file_info["Height"] = img.height

        return file_info
    except Exception as e:
        print("Error reading file info:", e)
        return {}
    
def get_exif_data(image_path):
    try:
        image = Image.open(image_path)
        exif_data = {}
        info = image._getexif()

        required_tags = [
            "ImageWidth", "ImageLength", "Software", "DateTime",
            "Make", "Model", "Orientation", "YCbCrPositioning",
            "XResolution", "YResolution"
        ]

        if info:
            for tag, value in info.items():
                tag_name = TAGS.get(tag, tag)
                if tag_name in required_tags:
                    exif_data[tag_name] = value
        return exif_data
    except Exception as e:
        print("Error reading EXIF data:", e)
        return {}
def get_gps_info(image_path):
    try:
        image = Image.open(image_path)
        exif_data = image._getexif()
        if not exif_data:
            return None

        gps_info = {}
        for tag, value in exif_data.items():
            tag_name = TAGS.get(tag)
            if tag_name == "GPSInfo":
                for t in value:
                    sub_tag = GPSTAGS.get(t, t)
                    gps_info[sub_tag] = value[t]

        if not gps_info:
            return None

        # Convert IFDRational to float
        def rational_to_float(r):
            try:
                return float(r.numerator) / float(r.denominator)
            except:
                return float(r)

        # Convert coordinates to decimal degrees
        def convert_to_degrees(coord):
            d = rational_to_float(coord[0])
            m = rational_to_float(coord[1])
            s = rational_to_float(coord[2])
            return d + (m / 60.0) + (s / 3600.0)

        lat = convert_to_degrees(gps_info["GPSLatitude"])
        if gps_info["GPSLatitudeRef"] != "N":
            lat = -lat

        lon = convert_to_degrees(gps_info["GPSLongitude"])
        if gps_info["GPSLongitudeRef"] != "E":
            lon = -lon

        return {"Latitude": lat, "Longitude": lon,
                "Google Maps": f"https://maps.google.com/?q={lat},{lon}"}

    except Exception as e:
        print("❌ Error reading GPS info:", e)
        return None

# ========== ROUTES ==========

@app.route('/')
def get_started():
    return render_template('GetStarted3d.html',active_tab="file")

@app.route('/log')
def log():
    return render_template('log.html')

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'success': False, 'message': 'Missing fields'})

    if user_ref.child(username).get():
        return jsonify({'success': False, 'message': 'Username already exists'})

    user_ref.child(username).set({
        'email': email,
        'password': password 
    })

    return jsonify({'success': True, 'message': 'Signup successful'})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user_data = user_ref.child(username).get()
    if not user_data:
        return jsonify({'success': False, 'message': 'User not found'})

    if user_data['password'] != password:
        return jsonify({'success': False, 'message': 'Incorrect password'})

    return jsonify({'success': True, 'message': 'Login successful'})



@app.route('/Main_page')
def main_page():
    return render_template('Main_page.html',active_tab="file")


@app.route('/mal', methods=['GET', 'POST'])
def mal():
    try:
        m=None
        if request.method == 'POST':
            file = request.files['csvFile']
            if not file or file.filename == "":
                return "❌ No file uploaded."
            try:
                if file.filename.endswith(".csv"):
                    try:
                        data = pd.read_csv(file)
                    except UnicodeDecodeError:
                        file.seek(0)
                        data = pd.read_csv(file, encoding="latin1")

                elif file.filename.endswith(".xlsx"):
                    data = pd.read_excel(file)
                else:
                    return "❌ Unsupported file type. Please upload .csv or .xlsx"
            except Exception as e:
                return f"⚠️ Error reading file: {str(e)}"
            
            (m,p)=full_prediction(load_and_clean_csv(data))
            save_prediction_bar(p)
            # feature_importances()
        return render_template('mal.html',result=m,active_tab="file")
    except:
        return render_template('Main_page.html',active_tab="file")

# NEW---------

@app.route("/ask", methods=["POST"])
def ask():
    try:
        data = request.get_json()
        question = data.get("question", "")
        gemini_answer = get_gemini_response(question)
        return jsonify({"gemini": gemini_answer})
    except:
        return render_template('Main_page.html',active_tab="file")

@app.route("/scan_url", methods=["POST"])
def scan_url():
    try:
        url = request.form.get("url")
        if not url:
            return render_template("mal.html", url_result=None, active_tab="url")

        url_result = check_url(url)
        return render_template("mal.html", url_result=url_result, scanned_url=url, active_tab="url")
    except:
        return render_template('Main_page.html',active_tab="file")



@app.route("/check_hash", methods=["GET", "POST"])
def check_hash():
    try:
        hash_result = None
        if request.method == "POST":
            value = request.form.get("search", "").strip()
            if value:
                hash_result = check_input(value)
        return render_template("mal.html", hash_result=hash_result,active_tab="search")
    except:
        return render_template('Main_page.html',active_tab="file")


# ========== Part 2 ==========

@app.route('/net', methods=['GET', 'POST'])
def net():
    try:
        result = None
        if request.method == 'POST':
            file = request.files['csvFile']
            if not file or file.filename == "":
                return "❌ No file uploaded."
            try:
                if file.filename.endswith(".csv"):
                    try:
                        data = pd.read_csv(file)
                    except UnicodeDecodeError:
                        file.seek(0)
                        data = pd.read_csv(file, encoding="latin1")
                elif file.filename.endswith(".xlsx"):
                    data = pd.read_excel(file)
                else:
                    return "❌ Unsupported file type. Please upload .csv or .xlsx"
            except Exception as e:
                return f"⚠️ Error reading file: {str(e)}"

            # ✅ Make prediction
            prediction, probas = network.predict_attack(data.iloc[0, :])
            network.visualize_results(prediction, probas)

            # ✅ Pass prediction to template
            result = prediction  

        return render_template('Net.html', result=result, active_tab="file")
    except:
        return render_template('Net.html', active_tab="url")

    
    


ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/scan_image", methods=['POST'])
def scan_image():
    try:
        if "image" not in request.files:
            return "No file part",400

        file = request.files["image"]

        if file.filename == "":
            return "No selected file",400

        if file and allowed_file(file.filename):
            file.save(r"static/image_forensic.jpg")
            file_info = get_file_info(r"static/image_forensic.jpg")
            exif_data = get_exif_data(r"static/image_forensic.jpg")
            gps_data = get_gps_info(r"static/image_forensic.jpg")
            print(file_info)
            return render_template('Net.html',scanned=True, file_info=file_info,exif_data=exif_data,gps_data=gps_data,filename=file.filename, active_tab="url")
    except:
          return render_template('Net.html', active_tab="url")
         
 

if __name__ == '__main__':
    app.run(debug=True)




