import json
import os

import mysql.connector
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    use_ssl = os.getenv("DB_SSL", "false").lower() == "true"

    connection_config = {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": int(os.getenv("DB_PORT", "3306")),
        "user": os.getenv("DB_USER", "root"),
        "password": os.getenv("DB_PASSWORD", ""),
        "database": os.getenv("DB_NAME", "cybershield_db"),
    }

    if use_ssl:
        connection_config["ssl_disabled"] = False
        connection_config["ssl_verify_cert"] = False
        connection_config["ssl_verify_identity"] = False

    return mysql.connector.connect(**connection_config)


def create_user(name, email, password_hash):
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        query = """
            INSERT INTO users (name, email, password_hash)
            VALUES (%s, %s, %s)
        """

        cursor.execute(
            query,
            (name, email, password_hash)
        )

        connection.commit()

        return cursor.lastrowid

    finally:
        cursor.close()
        connection.close()


def get_user_by_email(email):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        query = """
            SELECT id, name, email, password_hash, created_at
            FROM users
            WHERE email = %s
            LIMIT 1
        """

        cursor.execute(query, (email,))

        return cursor.fetchone()

    finally:
        cursor.close()
        connection.close()


def save_scan(
    user_id,
    domain,
    risk_score,
    risk_level,
    scan_data
):
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        query = """
            INSERT INTO scans
            (
                user_id,
                domain,
                risk_score,
                risk_level,
                scan_data
            )
            VALUES (%s, %s, %s, %s, %s)
        """

        cursor.execute(
            query,
            (
                user_id,
                domain,
                risk_score,
                risk_level,
                json.dumps(scan_data)
            )
        )

        connection.commit()

        return cursor.lastrowid

    finally:
        cursor.close()
        connection.close()


def get_scan_history(user_id):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        query = """
            SELECT
                id,
                domain,
                risk_score,
                risk_level,
                scanned_at
            FROM scans
            WHERE user_id = %s
            ORDER BY scanned_at DESC
        """

        cursor.execute(query, (user_id,))

        return cursor.fetchall()

    finally:
        cursor.close()
        connection.close()


def get_scan_by_id(user_id, scan_id):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        query = """
            SELECT
                id,
                domain,
                risk_score,
                risk_level,
                scanned_at,
                scan_data
            FROM scans
            WHERE id = %s
            AND user_id = %s
            LIMIT 1
        """

        cursor.execute(
            query,
            (scan_id, user_id)
        )

        scan = cursor.fetchone()

        if scan and scan.get("scan_data"):
            if isinstance(scan["scan_data"], str):
                scan["scan_data"] = json.loads(
                    scan["scan_data"]
                )

        return scan

    finally:
        cursor.close()
        connection.close()


def delete_scan(user_id, scan_id):
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        query = """
            DELETE FROM scans
            WHERE id = %s
            AND user_id = %s
        """

        cursor.execute(
            query,
            (scan_id, user_id)
        )

        connection.commit()

        return cursor.rowcount > 0

    finally:
        cursor.close()
        connection.close()