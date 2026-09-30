import json
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import os

load_dotenv()


def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "cybershield_db"),
    )


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


def save_scan(user_id, domain, risk_score, risk_level, scan_data):
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

        cursor.execute(query, (scan_id, user_id))

        scan = cursor.fetchone()

        if scan and scan.get("scan_data"):
            if isinstance(scan["scan_data"], str):
                scan["scan_data"] = json.loads(scan["scan_data"])

        return scan

    finally:
        cursor.close()
        connection.close()


def delete_scan(user_id, scan_id):
    """
    Delete only a scan belonging to the logged-in user.
    Returns True when a scan was deleted.
    Returns False when no matching scan exists.
    """

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