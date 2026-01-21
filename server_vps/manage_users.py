import sys
import os
import getpass
from app import app, db, User

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def init_db():
    print("\n[!!!] ATENÇÃO: ISSO APAGARÁ TODO O BANCO DE DADOS (LOGS, AGENTES, CHATS).")
    confirm = input("Digite 'CONFIRMAR' para continuar: ")
    
    if confirm == "CONFIRMAR":
        try:
            db_file = "aegis_core.db"
            if os.path.exists(db_file):
                os.remove(db_file)
                print(f"[-] Banco antigo removido.")
            
            db.create_all()
            print("[+] Tabelas recriadas.")
            
            # Cria admin padrão
            if not User.query.filter_by(username='admin').first():
                u = User(username='admin')
                u.set_password('admin123')
                db.session.add(u)
                db.session.commit()
                print("[+] Usuário padrão criado: admin / admin123")
            
            print("\n>>> Banco de dados resetado com sucesso! <<<")
        except Exception as e:
            print(f"Erro: {e}")
    else:
        print("Operação cancelada.")

def list_users():
    print("\n--- Usuários Cadastrados ---")
    users = User.query.all()
    if not users:
        print("Nenhum usuário encontrado.")
    for u in users:
        print(f"ID: {u.id} | Username: {u.username}")
    print("----------------------------")

def add_user():
    print("\n--- Adicionar Novo Operador ---")
    username = input("Username: ").strip()
    if not username: return

    if User.query.filter_by(username=username).first():
        print("Erro: Usuário já existe.")
        return

    password = getpass.getpass("Senha: ")
    confirm = getpass.getpass("Confirme a Senha: ")

    if password != confirm:
        print("Erro: As senhas não coincidem.")
        return

    new_user = User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    print(f"Usuário '{username}' criado com sucesso.")

def delete_user():
    list_users()
    print("\n--- Remover Operador ---")
    username = input("Digite o Username para deletar: ").strip()
    
    user = User.query.filter_by(username=username).first()
    if not user:
        print("Erro: Usuário não encontrado.")
        return

    if user.username == 'admin':
        print("Erro: Não é recomendado deletar o admin principal via script.")
        return

    confirm = input(f"Tem certeza que deseja deletar '{username}'? (s/n): ")
    if confirm.lower() == 's':
        db.session.delete(user)
        db.session.commit()
        print("Usuário removido.")

def main_menu():
    while True:
        print("\n=== GERENCIADOR AEGIS EDR ===")
        print("1. Listar Usuários")
        print("2. Adicionar Usuário")
        print("3. Remover Usuário")
        print("4. [PERIGO] Resetar/Criar Banco de Dados")
        print("5. Sair")
        
        choice = input("\nEscolha uma opção: ")

        with app.app_context():
            if choice == '1':
                list_users()
            elif choice == '2':
                add_user()
            elif choice == '3':
                delete_user()
            elif choice == '4':
                init_db()
            elif choice == '5':
                sys.exit()
            else:
                print("Opção inválida.")

if __name__ == "__main__":
    with app.app_context():
        # Garante que o banco existe antes de listar, para não dar erro
        if not os.path.exists("aegis_core.db"):
            print("Banco de dados não encontrado. Executando criação inicial...")
            db.create_all()
    
    main_menu()