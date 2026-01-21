import os
from app import app, db, User

db_file = "aegis_core.db"

if os.path.exists(db_file):
    os.remove(db_file)
    print(f"[-] Banco antigo removido.")

with app.app_context():
    db.create_all()
    print("[+] Tabelas recriadas com novas colunas (Geo, Startup, Drives).")
    
    if not User.query.filter_by(username='admin').first():
        u = User(username='admin')
        u.set_password('admin123')
        db.session.add(u)
        db.session.commit()
        print("[+] Admin criado: admin / admin123")

print("\n>>> SISTEMA PRONTO (v4.0) <<<")