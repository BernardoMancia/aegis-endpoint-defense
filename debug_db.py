import os
import sys

# Path to the 'server' directory
server_dir = os.path.join(os.getcwd(), 'server')
sys.path.append(server_dir)

try:
    from app import create_app
    from extensions import db
    from app.models.agent import Agent
    
    app = create_app()
    with app.app_context():
        agents = Agent.query.all()
        print("=== AGENTS IN DATABASE ===")
        for a in agents:
            print(f"ID: {a.id} | Original Hostname: {a.original_hostname} | Name: {a.hostname} | Last Seen: {a.last_seen}")
        print("==========================")
except ImportError as e:
    print(f"Import Error: {e}")
    # Try alternative
    print("Trying alternative import...")
    try:
        from extensions import db
        from app.models.agent import Agent
        from app import create_app
        # if this fails, we are in trouble
    except Exception as e2:
        print(f"Second try failed: {e2}")
