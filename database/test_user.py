from database.db import create_user, get_user_by_email
from services.auth import hash_password, verify_password


name = "Test User"
email = "test@cybershield.local"
password = "TestPassword123"


try:
    password_hash = hash_password(password)

    create_user(
        name,
        email,
        password_hash
    )

    user = get_user_by_email(email)

    if user and verify_password(password, user["password_hash"]):
        print("User creation and password verification successful!")
    else:
        print("User verification failed.")

except Exception as error:
    print("User test failed:")
    print(error)