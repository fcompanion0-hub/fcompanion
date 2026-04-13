from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
import random
import smtplib
import certifi
import uuid
import os

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps

from google.cloud import dialogflow_v2 as dialogflow

app = Flask(__name__)

CORS(app, origins=[
    "http://127.0.0.1:5501",
    "http://localhost:5501",
    "https://fcompanion.netlify.app"
], supports_credentials=True)

@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        res = Response()
        res.headers["Access-Control-Allow-Origin"]  = request.headers.get("Origin", "*")
        res.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        res.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        return res, 200

SECRET_KEY = os.environ.get("SECRET_KEY")

import json
import os
from google.oauth2 import service_account
from google.cloud import dialogflow_v2 as dialogflow

PROJECT_ID = "nubot-lnsc"

credentials_info = json.loads(os.environ["GOOGLE_CREDENTIALS"])
credentials = service_account.Credentials.from_service_account_info(credentials_info)

session_client = dialogflow.SessionsClient(credentials=credentials)

SMTP_EMAIL = os.environ.get("SMTP_EMAIL")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")

MONGO_URI = os.environ.get("MONGO_URI")
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client["nile_university"]

hods_collection      = db["hods"]
timetable_collection = db["timetables"]
users_collection     = db["users"]
otp_collection       = db["otps"]
chats_collection     = db["chats"] 


def send_otp_email(to_email, otp, purpose="verification"):
    subject = "FCOMPANION - Email Verification Code" if purpose == "verification" \
              else "FCOMPANION - Password Reset Code"
    body = f"<h3>Your code is:</h3><h1>{otp}</h1><p>Expires in 10 minutes.</p>"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_EMAIL
    msg["To"]      = to_email
    msg.attach(MIMEText(body, "html"))
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, to_email, msg.as_string())

def generate_otp():
    return str(random.randint(100000, 999999))


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "Token missing"}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user = users_collection.find_one({"email": payload["email"]})
            if not user:
                return jsonify({"error": "User not found"}), 404
        except Exception:
            return jsonify({"error": "Invalid or expired token"}), 401
        return f(user, *args, **kwargs)
    return decorated


@app.route("/signup", methods=["POST"])
def signup():
    data  = request.get_json()
    email = data.get("email")

    if users_collection.find_one({"email": email}):
        return jsonify({"message": "User already exists"}), 400

    otp = generate_otp()
    otp_collection.delete_many({"email": email, "purpose": "verification"})
    otp_collection.insert_one({
        "email":      email,
        "otp":        otp,
        "purpose":    "verification",
        "expires_at": datetime.utcnow() + timedelta(minutes=10),
        "userData": {
            "firstName": data.get("firstName"),
            "lastName":  data.get("lastName"),
            "email":     email,
            "level":     data.get("level"),
            "department":data.get("department"),
            "password":  generate_password_hash(data.get("password"))
        }
    })
    send_otp_email(email, otp)
    return jsonify({"message": "OTP sent", "email": email})



@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data.get("email")
    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"message": "User not found"}), 404

    otp_collection.delete_many({"email": email, "purpose": "reset"})
    otp = generate_otp()
    otp_collection.insert_one({
        "email": email,
        "otp": otp,
        "purpose": "reset",
        "expires_at": datetime.utcnow() + timedelta(minutes=10)
    })
    send_otp_email(email, otp, purpose="reset")
    return jsonify({"message": "Reset OTP sent"})


@app.route("/verify-reset-otp", methods=["POST"])
def verify_reset_otp():
    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")

    record = otp_collection.find_one({"email": email, "purpose": "reset"})
    if not record:
        return jsonify({"message": "OTP not found"}), 404
    if datetime.utcnow() > record["expires_at"]:
        otp_collection.delete_one({"_id": record["_id"]})
        return jsonify({"message": "OTP expired"}), 400
    if record["otp"] != otp:
        return jsonify({"message": "Incorrect OTP"}), 400

    return jsonify({"message": "OTP verified"})


@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")
    new_password = data.get("newPassword")

    record = otp_collection.find_one({"email": email, "purpose": "reset"})
    if not record or record["otp"] != otp:
        return jsonify({"message": "Invalid OTP"}), 400

    users_collection.update_one(
        {"email": email},
        {"$set": {"password": generate_password_hash(new_password)}}
    )

    otp_collection.delete_one({"_id": record["_id"]})
    return jsonify({"message": "Password reset successful"})

@app.route("/verify-signup-otp", methods=["POST"])
def verify_signup_otp():
    data   = request.get_json()
    email  = data.get("email")
    otp    = data.get("otp")
    record = otp_collection.find_one({"email": email, "purpose": "verification"})

    if not record:
        return jsonify({"message": "OTP not found. Please sign up again."}), 404
    if datetime.utcnow() > record["expires_at"]:
        otp_collection.delete_one({"_id": record["_id"]})
        return jsonify({"message": "OTP expired. Please sign up again."}), 400
    if record["otp"] != otp:
        return jsonify({"message": "Incorrect OTP."}), 400

    user_data = record["userData"]
    users_collection.insert_one({**user_data, "created_at": datetime.utcnow()})
    otp_collection.delete_one({"_id": record["_id"]})

    token = jwt.encode(
        {"email": email, "exp": datetime.utcnow() + timedelta(days=7)},
        SECRET_KEY, algorithm="HS256"
    )
    return jsonify({
        "message": "User created successfully",
        "token": token,
        "user": {
            "firstName":  user_data["firstName"],
            "lastName":   user_data["lastName"],
            "email":      user_data["email"],
            "level":      user_data["level"],
            "department": user_data["department"]
        }
    }), 201


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    data    = request.get_json()
    email   = data.get("email")
    purpose = data.get("purpose", "verification")
    record  = otp_collection.find_one({"email": email, "purpose": purpose})

    if not record:
        return jsonify({"message": "No pending OTP found."}), 404

    new_otp = generate_otp()
    otp_collection.update_one(
        {"_id": record["_id"]},
        {"$set": {"otp": new_otp, "expires_at": datetime.utcnow() + timedelta(minutes=10)}}
    )
    send_otp_email(email, new_otp, purpose=purpose)
    return jsonify({"message": "OTP resent"})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = users_collection.find_one({"email": data.get("email")})

    if not user or not check_password_hash(user["password"], data.get("password")):
        return jsonify({"message": "Invalid credentials"}), 401

    token = jwt.encode(
        {"email": user["email"], "exp": datetime.utcnow() + timedelta(days=7)},
        SECRET_KEY, algorithm="HS256"
    )
    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "firstName":  user.get("firstName"),
            "lastName":   user.get("lastName"),
            "email":      user.get("email"),
            "level":      user.get("level"),
            "department": user.get("department")
        }
    })


@app.route("/profile", methods=["GET"])
@token_required
def get_profile(current_user):
    return jsonify({
        "firstName":      current_user.get("firstName"),
        "lastName":       current_user.get("lastName"),
        "email":          current_user.get("email"),
        "level":          current_user.get("level"),
        "department":     current_user.get("department"),
        "profilePicture": current_user.get("profilePicture", "")
    })


@app.route("/profile", methods=["PUT"])
@token_required
def update_profile(current_user):
    data    = request.get_json()
    fields  = ["firstName", "lastName", "level", "department", "profilePicture"]
    updates = {k: v for k, v in data.items() if k in fields}

    if not updates:
        return jsonify({"error": "No valid fields to update"}), 400

    users_collection.update_one({"email": current_user["email"]}, {"$set": updates})
    return jsonify({"success": True, "message": "Profile updated"})


@app.route("/chat/history", methods=["GET"])
@token_required
def get_chat_history(current_user):
    record = chats_collection.find_one({"email": current_user["email"]})
    messages = record["messages"] if record else []
    return jsonify({"messages": messages})


@app.route("/chat/save", methods=["POST"])
@token_required
def save_message(current_user):
    data = request.get_json()
    message = {
        "role":      data.get("role"),    
        "text":      data.get("text"),
        "timestamp": datetime.utcnow().isoformat()
    }
    chats_collection.update_one(
        {"email": current_user["email"]},
        {"$push": {"messages": message}},
        upsert=True
    )
    return jsonify({"success": True})


@app.route("/chat/clear", methods=["DELETE"])
@token_required
def clear_chat_history(current_user):
    chats_collection.update_one(
        {"email": current_user["email"]},
        {"$set": {"messages": []}},
        upsert=True
    )
    return jsonify({"success": True, "message": "Chat history cleared"})



@app.route("/webhook", methods=["POST"])
def webhook():
    data       = request.get_json()
    message    = data.get("message")
    session_id = data.get("sessionId") or str(uuid.uuid4())

    if not message:
        return jsonify({"reply": "Please type a message.", "sessionId": session_id})

    session = session_client.session_path(PROJECT_ID, session_id)

    try:
        text_input  = dialogflow.TextInput(text=message, language_code="en-US")
        query_input = dialogflow.QueryInput(text=text_input)
        response    = session_client.detect_intent(
            request={"session": session, "query_input": query_input}
        )

        result     = response.query_result
        intent     = result.intent.display_name.lower()
        params     = result.parameters
        department = params.get("departments")
        hod_name   = params.get("names")
        reply      = result.fulfillment_text

        hod = None
        if hod_name:
            hod = hods_collection.find_one({"name": {"$regex": hod_name, "$options": "i"}})
        if not hod and department:
            hod = hods_collection.find_one({"department": {"$regex": department, "$options": "i"}})

        if intent == "hod_name":
            reply = hod["name"] if hod else "HOD not found."
        elif intent == "hod_office":
            reply = hod["office"] if hod else "Office not found."
        elif intent == "hod_contact":
            reply = hod["email"] if hod else "Contact not found."
        elif intent == "department_timetable":
            if department:
                timetable = timetable_collection.find_one({"department": {"$regex": department, "$options": "i"}})
                reply = f"Here's the URL link for the timetable: {timetable['timetable_link']}" if timetable else "Timetable not found."
            else:
                reply = "Please specify a department."

        return jsonify({"reply": reply, "sessionId": session_id})

    except Exception as e:
        print("ERROR:", str(e))
        return jsonify({"reply": "Something went wrong.", "error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)