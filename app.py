from flask import Flask, jsonify, request, send_from_directory

from services.security_scanner import scan_domain

app = Flask(__name__)


@app.route("/")
def home():
    return send_from_directory("frontend", "index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}

    domain = data.get("domain")

    if not domain:
        return jsonify({
            "success": False,
            "error": "Please provide a domain."
        }), 400

    try:
        result = scan_domain(domain)

        return jsonify({
            "success": True,
            "result": result
        })

    except ValueError as error:
        return jsonify({
            "success": False,
            "error": str(error)
        }), 400

    except Exception:
        return jsonify({
            "success": False,
            "error": "An unexpected error occurred."
        }), 500


if __name__ == "__main__":
    app.run(debug=True)