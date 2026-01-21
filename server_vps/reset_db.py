import os
from app import app, db, User

db_file = "aegis_core.db"

if os.path.exists(db_file):
    os.remove(db_file)

with app.app_context():
    db.create_all()
    
    if not User.query.filter_by(username='admin').first():
        u = User(username='admin')
        u.set_password('admin123')
        db.session.add(u)
        db.session.commit()
        print("Admin user created.")