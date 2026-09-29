from app import app
from database.db import get_db_connection


def get_first_user():
    connection = get_db_connection()

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, name, email
            FROM users
            ORDER BY id
            LIMIT 1
            """
        )

        return cursor.fetchone()

    finally:
        cursor.close()
        connection.close()


user = get_first_user()

if not user:
    print("No user found in the database.")
    raise SystemExit


print("Testing Flask API...")
print("Using user:", user["email"])


app.config["TESTING"] = True

with app.test_client() as client:

    with client.session_transaction() as session:

        session["user_id"] = user["id"]
        session["user_name"] = user["name"]
        session["user_email"] = user["email"]


    response = client.post(
        "/api/scan",
        json={
            "domain": "example.com"
        }
    )


    print("\nHTTP status:", response.status_code)

    data = response.get_json()

    print("\nResponse keys:")
    print(data.keys())


    print("\n===== RECOMMENDATIONS FROM FLASK API =====")

    recommendations = data.get(
        "recommendations"
    )


    if recommendations is None:

        print("NO recommendations field returned.")

    else:

        print(
            "Number of recommendations:",
            len(recommendations)
        )

        for item in recommendations:

            print("\nTitle:")
            print(item["title"])

            print("\nWhy:")
            print(item["why"])

            print("\nAction:")
            print(item["action"])

            print("---------------------------")