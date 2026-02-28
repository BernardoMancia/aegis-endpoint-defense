import sqlite3
import os

db_path = "server/data/aegis.db"
if not os.path.exists(db_path):
    print("Banco de dados não encontrado em:", db_path)
else:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    print("Tabelas:", tables)
    
    if "soc_user" in tables:
        cur.execute("SELECT id, username, password_hash, role, status FROM soc_user")
        users = cur.fetchall()
        print("Usuários:")
        for u in users:
            print(u)
    else:
        print("Tabela soc_user não existe.")
    conn.close()
