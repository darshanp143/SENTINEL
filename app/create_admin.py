
from getpass import getpass

from sqlalchemy import select

from .database import Base, SessionLocal, engine
from .models import User
from .auth import hash_password


def main():
    Base.metadata.create_all(bind=engine)

    username = input("Admin username (3-50 characters): ").strip()
    if not 3 <= len(username) <= 50:
        raise SystemExit("Username must be 3-50 characters.")

    password = getpass("Admin password (12+ characters): ")
    confirmation = getpass("Confirm password: ")

    if len(password) < 12:
        raise SystemExit("Password must contain at least 12 characters.")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    with SessionLocal() as db:
        existing = db.scalar(
            select(User).where(User.username == username)
        )

        if existing:
            raise SystemExit(
                "That username already exists. No account was changed."
            )

        user = User(
            username=username,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
        )
        db.add(user)
        db.commit()

    print(f"Administrator '{username}' created successfully.")


if __name__ == "__main__":
    main()
