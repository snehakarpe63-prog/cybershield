import json
import os

import mysql.connector
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    """
    Create and return a MySQL database connection.

    The connection details are read from environment variables:
    DB_HOST
    DB_PORT
    DB_USER
    DB_PASSWORD
    DB_NAME
    DB_SSL
    """

    db_host = os.getenv("DB_HOST")
    db_port = os.getenv("DB_PORT")
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASSWORD")
    db_name = os.getenv("DB_NAME")
    db_ssl = os.getenv("DB_SSL", "false").lower() == "true"

    # Do not silently use localhost in production.
    required_variables = {
        "DB_HOST": db_host,
        "DB_PORT": db_port,
        "DB_USER": db_user,
        "DB_PASSWORD": db_password,
        "DB_NAME": db_name,
    }

    missing_variables = [
        key for key, value in required_variables.items()
        if not value
    ]

    if missing_variables:
        raise RuntimeError(
            "Missing database environment variables: "
            + ", ".join(missing_variables)
        )

    connection_config = {
        "host": db_host,
        "port": int(db_port),
        "user": db_user,
        "password": db_password,
        "database": db_name,
        "connection_timeout": 15,
    }

    # Aiven MySQL requires SSL.
    if db_ssl:
        connection_config.update(
            {
                "ssl_disabled": False,
                "ssl_verify_cert": False,
                "ssl_verify_identity": False,
            }
        )

    return mysql.connector.connect(**connection_config)


def create_user(name, email, password_hash):
    """
    Create a new user.
    Returns the inserted user ID.
    """
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
    """
    Find a user by email address.
    Returns a dictionary or None.
    """
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        query = """
            SELECT
                id,
                name,
                email,
                password_hash,
                created_at
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
    """
    Save a completed security scan.
    Returns the inserted scan ID.
    """

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        # Convert Python dictionary to JSON string.
        if isinstance(scan_data, str):
            scan_json = scan_data
        else:
            scan_json = json.dumps(scan_data)

        query = """
            INSERT INTO scans (
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
                scan_json,
            )
        )

        connection.commit()

        return cursor.lastrowid

    finally:
        cursor.close()
        connection.close()


def get_scan_history(user_id):
    """
    Get all scans belonging to a specific user.
    Newest scans are returned first.
    """

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        query = """
            SELECT
                id,
                user_id,
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
    """
    Get one scan belonging to the specified user.

    Using both user_id and scan_id prevents one user from
    accessing another user's scan.
    """

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        query = """
            SELECT
                id,
                user_id,
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
            try:
                scan["scan_data"] = json.loads(scan["scan_data"])
            except (json.JSONDecodeError, TypeError):
                pass

        return scan

    finally:
        cursor.close()
        connection.close()


def delete_scan(user_id, scan_id):
    """
    Delete a scan only when it belongs to the logged-in user.

    Returns True when a scan was deleted,
    otherwise False.
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