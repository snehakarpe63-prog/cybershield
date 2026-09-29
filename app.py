import os

from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    request,
    send_from_directory,
    session,
)

from database.db import (
    create_user,
    get_scan_history,
    get_user_by_email,
    save_scan,
)

from services.auth import (
    hash_password,
    verify_password,
)

from services.security_scanner import scan_domain


load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")


@app.route("/")
def home():
    return send_from_directory("frontend", "index.html")


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not name or not email or not password:
        return jsonify({
            "success": False,
            "error": "Name, email and password are required."
        }), 400

    if len(password) < 8:
        return jsonify({
            "success": False,
            "error": "Password must contain at least 8 characters."
        }), 400

    if "@" not in email:
        return jsonify({
            "success": False,
            "error": "Please enter a valid email address."
        }), 400

    try:
        existing_user = get_user_by_email(email)

        if existing_user:
            return jsonify({
                "success": False,
                "error": "An account with this email already exists."
            }), 409

        password_hash = hash_password(password)

        create_user(
            name,
            email,
            password_hash
        )

        return jsonify({
            "success": True,
            "message": "Registration successful. Please log in."
        }), 201

    except Exception as error:
        print("Registration error:", error)

        return jsonify({
            "success": False,
            "error": "Registration failed."
        }), 500


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({
            "success": False,
            "error": "Email and password are required."
        }), 400

    try:
        user = get_user_by_email(email)

        if not user:
            return jsonify({
                "success": False,
                "error": "Invalid email or password."
            }), 401

        if not verify_password(
            password,
            user["password_hash"]
        ):
            return jsonify({
                "success": False,
                "error": "Invalid email or password."
            }), 401

        session["user_id"] = user["id"]
        session["user_name"] = user["name"]
        session["user_email"] = user["email"]

        return jsonify({
            "success": True,
            "message": "Login successful.",
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"]
            }
        })

    except Exception as error:
        print("Login error:", error)

        return jsonify({
            "success": False,
            "error": "Login failed."
        }), 500


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()

    return jsonify({
        "success": True,
        "message": "Logged out successfully."
    })


@app.route("/api/me", methods=["GET"])
def current_user():
    if "user_id" not in session:
        return jsonify({
            "logged_in": False
        })

    return jsonify({
        "logged_in": True,
        "user": {
            "id": session["user_id"],
            "name": session["user_name"],
            "email": session["user_email"]
        }
    })


@app.route("/api/scan", methods=["POST"])
def scan():
    if "user_id" not in session:
        return jsonify({
            "success": False,
            "error": "Please log in before starting a scan."
        }), 401

    data = request.get_json(silent=True) or {}

    domain = data.get("domain")

    if not domain:
        return jsonify({
            "success": False,
            "error": "Please provide a domain."
        }), 400

    try:
        result = scan_domain(domain)

        risk_score = result["risk"]["score"]
        risk_level = result["risk"]["level"]

        save_scan(
            session["user_id"],
            result["domain"],
            risk_score,
            risk_level
        )

        return jsonify({
            "success": True,
            "result": result,
            "message": "Scan completed and saved successfully."
        })

    except ValueError as error:
        return jsonify({
            "success": False,
            "error": str(error)
        }), 400

    except Exception as error:
        print("Scan error:", error)

        return jsonify({
            "success": False,
            "error": "An unexpected error occurred."
        }), 500


@app.route("/api/scans", methods=["GET"])
def get_scans():
    if "user_id" not in session:
        return jsonify({
            "success": False,
            "error": "Please log in."
        }), 401

    try:
        scans = get_scan_history(session["user_id"])

        return jsonify({
            "success": True,
            "scans": scans
        })

    except Exception as error:
        print("History error:", error)

        return jsonify({
            "success": False,
            "error": "Could not load scan history."
        }), 500


if __name__ == "__main__":
    app.run(debug=True)