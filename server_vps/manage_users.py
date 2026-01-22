import os
from app import app, db, User
from getpass import getpass

def clear(): os.system('cls' if os.name == 'nt' else 'clear')

def list_users():
    with app.app_context():
        users = User.query.all()
        print("\n--- Usuários Cadastrados ---")
        if not users:
            print("Nenhum usuário encontrado.")
        for u in users:
            role = " [★ PRIORITÁRIO]" if u.is_priority else ""
            print(f"ID: {u.id} | User: {u.username}{role}")
        print("----------------------------")

def add_user():
    print("\n--- Adicionar Novo Operador ---")
    username = input("Username: ")
    pwd = getpass("Senha: ")
    pwd2 = getpass("Confirme a Senha: ")
    
    if pwd != pwd2:
        print("Erro: As senhas não conferem.")
        return

    with app.app_context():
        if User.query.filter_by(username=username).first():
            print("Erro: Usuário já existe.")
            return
        
        new_user = User(username=username)
        new_user.set_password(pwd)
        db.session.add(new_user)
        db.session.commit()
        print(f"Usuário '{username}' criado com sucesso.")

def del_user():
    list_users()
    username = input("Digite o username para deletar: ")
    with app.app_context():
        u = User.query.filter_by(username=username).first()
        if u:
            db.session.delete(u)
            db.session.commit()
            print("Usuário removido.")
        else:
            print("Usuário não encontrado.")

def toggle_priority():
    list_users()
    username = input("Digite o usuário para alterar prioridade: ")
    with app.app_context():
        u = User.query.filter_by(username=username).first()
        if u:
            u.is_priority = not u.is_priority
            db.session.commit()
            status = "ATIVADA" if u.is_priority else "REMOVIDA"
            print(f"Prioridade de {username}: {status}")
        else:
            print("Usuário não encontrado.")

def reset_db():
    confirm = input("ATENÇÃO: Isso apaga TUDO (agentes, logs, usuários). Confirmar? (s/n): ")
    if confirm.lower() == 's':
        try:
            if os.path.exists("aegis_core.db"):
                os.remove("aegis_core.db")
            if os.path.exists("instance"):
                import shutil
                shutil.rmtree("instance")
            print("Banco de dados deletado. Reinicie o servidor para recriar.")
        except Exception as e:
            print(f"Erro: {e}")

def main():
    while True:
        print("\n=== GERENCIADOR AEGIS EDR ===")
        print("1. Listar Usuários")
        print("2. Adicionar Usuário")
        print("3. Remover Usuário")
        print("4. [PERIGO] Resetar/Criar Banco de Dados")
        print("5. Alterar Prioridade (VIP)")
        print("6. Sair")
        
        opt = input("\nEscolha uma opção: ")
        
        if opt == '1': list_users()
        elif opt == '2': add_user()
        elif opt == '3': del_user()
        elif opt == '4': reset_db()
        elif opt == '5': toggle_priority()
        elif opt == '6': break
        else: print("Opção inválida.")

if __name__ == "__main__":
    if not os.path.exists("aegis_core.db") and not os.path.exists("instance/aegis_core.db"):
        print("Banco de dados não encontrado. Executando criação inicial...")
        with app.app_context():
            db.create_all()
    main()