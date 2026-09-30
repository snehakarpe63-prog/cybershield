from flask import (
    Flask,
    jsonify,
    request,
    session,
    send_from_directory,
)
from dotenv import load_dotenv
import os

from database.db import (
    create_user,
    get_user_by_email,
    save_scan,
    get_scan_history,
    get_scan_by_id,
    delete_scan,
)

from services.auth import (
    hash_password,
    verify_password,
)

from services.security_scanner import (
    scan_domain,
)

from services.recommendations import (
    build_recommendations,
)


load_dotenv()


app = Flask(
    __name__,
    static_folder="frontend",
    static_url_path=""
)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "cybershield-development-secret"
)


# ---------------------------------------------------------
# HOME
# ---------------------------------------------------------

@app.route("/")
def home():
    return send_from_directory(
        "frontend",
        "index.html"
    )


# ---------------------------------------------------------
# REGISTER
# ---------------------------------------------------------

@app.route("/api/register", methods=["POST"])
def register():

    data = request.get_json(silent=True) or {}

    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not name or not email or not password:
        return jsonify({
            "error": "Name, email and password are required."
        }), 400

    existing_user = get_user_by_email(email)

    if existing_user:
        return jsonify({
            "error": "An account with this email already exists."
        }), 409

    password_hash = hash_password(password)

    user_id = create_user(
        name,
        email,
        password_hash
    )

    return jsonify({
        "message": "Registration successful.",
        "user_id": user_id
    }), 201


# ---------------------------------------------------------
# LOGIN
# ---------------------------------------------------------

@app.route("/api/login", methods=["POST"])
def login():

    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return jsonify({
            "error": "Email and password are required."
        }), 400

    user = get_user_by_email(email)

    if not user:
        return jsonify({
            "error": "Invalid email or password."
        }), 401

    if not verify_password(
        password,
        user["password_hash"]
    ):
        return jsonify({
            "error": "Invalid email or password."
        }), 401

    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["user_email"] = user["email"]

    return jsonify({
        "message": "Login successful.",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"]
        }
    }), 200


# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------

@app.route("/api/logout", methods=["POST"])
def logout():

    session.clear()

    return jsonify({
        "message": "Logged out successfully."
    }), 200


# ---------------------------------------------------------
# CURRENT USER
# ---------------------------------------------------------

@app.route("/api/me", methods=["GET"])
def current_user():

    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "logged_in": False
        }), 200

    return jsonify({
        "logged_in": True,
        "user": {
            "id": user_id,
            "name": session.get("user_name"),
            "email": session.get("user_email")
        }
    }), 200


# ---------------------------------------------------------
# SECURITY SCAN
# ---------------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def scan():

    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "error": "Please login before starting a scan."
        }), 401

    data = request.get_json(silent=True) or {}

    domain = str(
        data.get("domain", "")
    ).strip()

    if not domain:
        return jsonify({
            "error": "Domain is required."
        }), 400

    try:

        result = scan_domain(domain)

        recommendations = build_recommendations(
            result
        )

        risk = result.get(
            "risk",
            {}
        )

        risk_score = risk.get(
            "score",
            0
        )

        risk_level = risk.get(
            "level",
            "Unverified"
        )

        complete_report = {
            "result": result,
            "recommendations": recommendations
        }

        scan_id = save_scan(
            user_id=user_id,
            domain=result.get(
                "domain",
                domain
            ),
            risk_score=risk_score,
            risk_level=risk_level,
            scan_data=complete_report
        )

        return jsonify({
            "message": "Scan completed successfully.",
            "scan_id": scan_id,
            "result": result,
            "recommendations": recommendations
        }), 200

    except Exception as error:

        print(
            "Scan error:",
            error
        )

        return jsonify({
            "error": "Unable to complete the scan.",
            "details": str(error)
        }), 500


# ---------------------------------------------------------
# SCAN HISTORY
# ---------------------------------------------------------

@app.route("/api/scans", methods=["GET"])
def scan_history():

    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "error": "Unauthorized"
        }), 401

    try:

        scans = get_scan_history(
            user_id
        )

        return jsonify(
            scans
        ), 200

    except Exception as error:

        print(
            "History error:",
            error
        )

        return jsonify({
            "error": "Unable to load scan history."
        }), 500


# ---------------------------------------------------------
# VIEW ONE SAVED REPORT
# DELETE ONE SAVED SCAN
# ---------------------------------------------------------

@app.route(
    "/api/scans/<int:scan_id>",
    methods=["GET", "DELETE"]
)
def saved_scan(scan_id):

    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "error": "Unauthorized"
        }), 401

    # ---------------------------------------------
    # VIEW REPORT
    # ---------------------------------------------

    if request.method == "GET":

        scan = get_scan_by_id(
            user_id,
            scan_id
        )

        if not scan:
            return jsonify({
                "error": "Scan not found."
            }), 404

        return jsonify(
            scan
        ), 200

    # ---------------------------------------------
    # DELETE SCAN
    # ---------------------------------------------

    if request.method == "DELETE":

        deleted = delete_scan(
            user_id,
            scan_id
        )

        if not deleted:
            return jsonify({
                "error": "Scan not found."
            }), 404

        return jsonify({
            "message": "Scan deleted successfully."
        }), 200


# ---------------------------------------------------------
# RUN APPLICATION
# ---------------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )