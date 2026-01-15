import sys
import getpass
from app import app, db, User

def add_user():
    print("--- Create New Operator ---")
    username = input("Username: ").strip()
    if not username:
        return

    with app.app_context():
        if User.query.filter_by(username=username).first():
            print("Error: User already exists.")
            return

        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm Password: ")

        if password != confirm:
            print("Error: Passwords do not match.")
            return

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        print(f"User '{username}' created successfully.")

def remove_user():
    print("--- Remove Operator ---")
    username = input("Username to delete: ").strip()
    
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            print("Error: User not found.")
            return

        confirm = input(f"Are you sure you want to delete '{username}'? (y/n): ")
        if confirm.lower() == 'y':
            db.session.delete(user)
            db.session.commit()
            print("User removed.")

def list_users():
    print("--- Registered Operators ---")
    with app.app_context():
        users = User.query.all()
        for u in users:
            print(f"- {u.username}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python manage_users.py [add|remove|list]")
    else:
        action = sys.argv[1]
        if action == "add":
            add_user()
        elif action == "remove":
            remove_user()
        elif action == "list":
            list_users()