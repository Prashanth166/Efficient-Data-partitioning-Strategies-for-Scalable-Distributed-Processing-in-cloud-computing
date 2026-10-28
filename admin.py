
from getpass import getpass
from app import app, db, User

username = input("Enter admin username: ").strip()
password = getpass("Enter admin password: ")

if len(username) < 3 or len(password) < 8:
    print("Username must be at least 3 characters and password at least 8.")
else:
    with app.app_context():
        user = User.query.filter_by(username=username).first()

        if user is None:
            user = User(username=username)
            db.session.add(user)

        user.is_admin = True
        user.set_password(password)
        db.session.commit()

        print(f"Admin account '{username}' is ready.")
