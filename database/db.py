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


def save_scan(domain, risk_score, risk_level):
    connection = get_db_connection()

    try:
        cursor = connection.cursor()

        query = """
            INSERT INTO scans (domain, risk_score, risk_level)
            VALUES (%s, %s, %s)
        """

        values = (domain, risk_score, risk_level)

        cursor.execute(query, values)
        connection.commit()

    finally:
        cursor.close()
        connection.close()