import os

import mysql.connector
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
    )


def create_user(name, email, password_hash):
    connection = get_db_connection()

    try:
        cursor = connection.cursor()

        query = """
            INSERT INTO users (name, email, password_hash)
            VALUES (%s, %s, %s)
        """

        cursor.execute(query, (name, email, password_hash))
        connection.commit()

        return cursor.lastrowid

    finally:
        cursor.close()
        connection.close()


def get_user_by_email(email):
    connection = get_db_connection()

    try:
        cursor = connection.cursor(dictionary=True)

        query = """
            SELECT id, name, email, password_hash
            FROM users
            WHERE email = %s
        """

        cursor.execute(query, (email,))

        return cursor.fetchone()

    finally:
        cursor.close()
        connection.close()


def save_scan(user_id, domain, risk_score, risk_level):
    connection = get_db_connection()

    try:
        cursor = connection.cursor()

        query = """
            INSERT INTO scans
            (user_id, domain, risk_score, risk_level)
            VALUES (%s, %s, %s, %s)
        """

        cursor.execute(
            query,
            (user_id, domain, risk_score, risk_level)
        )

        connection.commit()

    finally:
        cursor.close()
        connection.close()


def get_scan_history(user_id):
    connection = get_db_connection()

    try:
        cursor = connection.cursor(dictionary=True)

        query = """
            SELECT id, domain, risk_score, risk_level, scanned_at
            FROM scans
            WHERE user_id = %s
            ORDER BY scanned_at DESC
        """

        cursor.execute(query, (user_id,))

        scans = cursor.fetchall()

        for scan in scans:
            if scan["scanned_at"]:
                scan["scanned_at"] = scan["scanned_at"].strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

        return scans

    finally:
        cursor.close()
        connection.close()