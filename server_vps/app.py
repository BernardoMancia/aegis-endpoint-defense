import os
import json
import time
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import openai
from sqlalchemy import event
from sqlalchemy.engine import Engine

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

app = Flask(__name__)

server_port = int(os.getenv('SERVER_PORT', 7070))
secret_key = os.getenv('FLASK_SECRET_KEY', 'default_key')
api_token = os.getenv('API_TOKEN', 'default_token')
openai.api_key = os.getenv('OPENAI_API_KEY')

app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aegis_core.db?timeout=30'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- MODELOS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_priority = db.Column(db.Boolean, default=False)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_hostname = db.Column(db.String(100)) # ID Real (Fixo)
    hostname = db.Column(db.String(100), nullable=False) # Apelido (Editável)
    device_type = db.Column(db.String(20), default="desktop")
    ip_address = db.Column(db.String(50))
    public_ip = db.Column(db.String(50))
    geolocation = db.Column(db.String(100), default="Unknown")
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    os_version = db.Column(db.String(100))
    status = db.Column(db.String(20), default='offline')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    battery_level = db.Column(db.Integer, default=100)
    
    # Dados extras
    software_list = db.Column(db.Text, default="[]")
    clipboard_content = db.Column(db.Text, default="")
    pending_command = db.Column(db.String(500), default=None)
    last_screenshot = db.Column(db.Text, default=None)
    ai_summary = db.Column(db.Text, default="Aguardando...")
    
    logs = db.relationship('AgentLog', backref='agent', lazy=True)
    messages = db.relationship('ChatMessage', backref='agent', lazy=True)

class AgentLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    log_type = db.Column(db.String(50))
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    sender = db.Column(db.String(10), nullable=False) # 'admin' ou 'client'
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

def log_event(agent_id, type, msg):
    try: db.session.add(AgentLog(agent_id=agent_id, log_type=type, message=msg))
    except: pass

@login_manager.user_loader
def load_user(uid): return db.session.get(User, int(uid))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user); return redirect(url_for('dashboard'))
        flash('Login failed.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout(): logout_user(); return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    agents = Agent.query.all()
    return render_template('dashboard.html', mode='dashboard', agents=agents)

@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    try:
        data = request.json
        if data.get('token') != api_token: return jsonify({'status': '403'}), 403

        orig_host = data.get('hostname')
        agent = Agent.query.filter_by(original_hostname=orig_host).first()
        
        # Registro inicial
        if not agent:
            agent = Agent(original_hostname=orig_host, hostname=orig_host)
            db.session.add(agent)
            try:
                db.session.commit()
                log_event(agent.id, "SYSTEM", f"Novo: {orig_host}")
            except:
                db.session.rollback(); return jsonify({'status': 'retry'}), 200

        # Atualiza status
        agent.last_seen = datetime.utcnow()
        agent.status = 'online'
        agent.ip_address = data.get('ip')
        agent.public_ip = request.remote_addr
        agent.device_type = data.get('device_type', 'desktop')
        agent.os_version = data.get('os_version')
        agent.battery_level = data.get('battery', 100)
        
        if data.get('gps'):
            agent.latitude = data['gps'].get('lat')
            agent.longitude = data['gps'].get('lng')
        
        # Salva softwares se enviado
        if data.get('software'): agent.software_list = json.dumps(data.get('software'))
        
        # Recebe Chat do Cliente
        if data.get('client_message'):
            db.session.add(ChatMessage(agent_id=agent.id, sender='client', content=data.get('client_message')))

        # Recebe Resultado do Shell
        if data.get('cmd_output'):
            # Limita tamanho do log para não explodir o banco
            output_clean = data.get('cmd_output')[:2000]
            log_event(agent.id, "SHELL_RESULT", output_clean)

        # Entrega comandos pendentes
        cmd = agent.pending_command
        agent.pending_command = None

        # Entrega mensagens de chat pendentes (Admin -> Cliente)
        unread = ChatMessage.query.filter_by(agent_id=agent.id, sender='admin', read=False).all()
        chat_out = []
        for m in unread:
            chat_out.append(m.content)
            m.read = True

        for _ in range(5):
            try: db.session.commit(); break
            except: db.session.rollback(); time.sleep(0.2)

        return jsonify({'command': cmd, 'chat_messages': chat_out, 'status': 'ok'})

    except Exception as e:
        return jsonify({'status': 'error', 'msg': str(e)}), 500

@app.route('/control/command', methods=['POST'])
@login_required
def control_command():
    agent_id = request.form.get('agent_id')
    cmd = request.form.get('command')
    agent = db.session.get(Agent, agent_id)
    
    if not agent: return jsonify({'status': 'err'}), 404

    if cmd == 'rename': # Renomear Apelido (DB)
        agent.hostname = request.form.get('new_name')
        log_event(agent.id, "SYSTEM", f"Apelido alterado: {agent.hostname}")
        
    elif cmd == 'rename_system': # Renomear Máquina Real
        new_sys = request.form.get('new_host')
        agent.pending_command = f"set_hostname:{new_sys}"
        log_event(agent.id, "SYSTEM", f"Comando Rename PC: {new_sys}")
        
    elif cmd == 'chat_send':
        db.session.add(ChatMessage(agent_id=agent.id, sender='admin', content=request.form.get('message')))
        
    elif cmd == 'analyze_full':
        generate_analysis(agent)
        
    elif cmd == 'ask_ai': # Pergunta Específica
        ask_openai(agent, request.form.get('question'))
        
    elif cmd == 'shell':
        shell_c = request.form.get('shell_cmd')
        agent.pending_command = f"shell:{shell_c}"
        log_event(agent.id, "SHELL_CMD", f"> {shell_c}")
        
    else:
        agent.pending_command = cmd
        log_event(agent.id, "COMMAND", cmd)
    
    try: db.session.commit()
    except: db.session.rollback()
    return jsonify({'status': 'ok'})

@app.route('/api/upload_screenshot', methods=['POST'])
def upload_screenshot():
    data = request.json
    agent = Agent.query.filter_by(original_hostname=data.get('hostname')).first()
    if agent:
        # Recebe base64 pronto
        agent.last_screenshot = data.get('image_data')
        log_event(agent.id, "INFO", "Print atualizado")
        try: db.session.commit()
        except: db.session.rollback()
    return jsonify({'status': 'ok'})

@app.route('/get_agent_details/<int:id>')
@login_required
def details(id):
    a = db.session.get(Agent, id)
    if not a: return jsonify({'error': 'Not found'}), 404

    logs = AgentLog.query.filter_by(agent_id=a.id).order_by(AgentLog.timestamp.desc()).limit(30).all()
    chats = ChatMessage.query.filter_by(agent_id=a.id).order_by(ChatMessage.timestamp.asc()).all()
    
    soft = []
    if a.software_list:
        try: soft = json.loads(a.software_list)
        except: soft = []

    return jsonify({
        'id': a.id,
        'hostname': a.hostname,
        'original_hostname': a.original_hostname,
        'type': a.device_type,
        'ip': a.ip_address,
        'os': a.os_version,
        'battery': a.battery_level,
        'gps': {'lat': a.latitude, 'lng': a.longitude} if a.latitude else None,
        'software': soft,
        'screenshot': a.last_screenshot,
        'ai': a.ai_summary,
        'logs': [{'time': l.timestamp.strftime('%H:%M:%S'), 'type': l.log_type, 'msg': l.message} for l in logs],
        'chat': [{'sender': c.sender, 'msg': c.content} for c in chats]
    })

def generate_analysis(agent):
    # (Mesma lógica de IA anterior)
    try:
        prompt = f"Analyze security: OS {agent.os_version}. Software count: {len(agent.software_list)}."
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "system", "content": "Security Analyst."}, {"role": "user", "content": prompt}]
        )
        agent.ai_summary = response.choices[0].message['content']
    except: agent.ai_summary = "Erro IA ou Sem API Key"

def ask_openai(agent, question):
    try:
        context = f"OS: {agent.os_version}. Logs Recentes: {str([l.message for l in agent.logs[:5]])}"
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Security Analyst Assistant."},
                {"role": "user", "content": f"Context: {context}\nQuestion: {question}"}
            ]
        )
        agent.ai_summary = response.choices[0].message['content']
        db.session.commit()
    except: pass

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            try:
                u = User(username='admin'); u.set_password('admin123'); u.is_priority=True
                db.session.add(u); db.session.commit()
            except: pass
    app.run(host='0.0.0.0', port=server_port, threaded=True)