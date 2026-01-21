import os
from app import app, db, User

db_file = "aegis_core.db"

if os.path.exists(db_file):
    os.remove(db_file)
    print(f"[-] Banco de dados antigo '{db_file}' removido.")

with app.app_context():
    db.create_all()
    print("[+] Novas tabelas criadas com sucesso.")
    
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("[+] Usuario Admin criado: admin / admin123")

print("\n>>> SISTEMA PRONTO PARA INICIAR <<<")