import os
import json
import requests
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import openai
import nvdlib

# Carrega .env de múltiplos locais
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

app = Flask(__name__)

secret_key = os.getenv('FLASK_SECRET_KEY')
if not secret_key:
    secret_key = 'chave_de_emergencia_temporaria_12345'

app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aegis_core.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

openai.api_key = os.getenv('OPENAI_API_KEY')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- MODELOS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), unique=True, nullable=False)
    ip_address = db.Column(db.String(50))
    public_ip = db.Column(db.String(50))
    mac_address = db.Column(db.String(50)) 
    geolocation = db.Column(db.String(100), default="Desconhecido") # Nova
    os_version = db.Column(db.String(100))
    status = db.Column(db.String(20), default='offline')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Hardware/Software
    cpu_usage = db.Column(db.Float, default=0.0)
    ram_usage = db.Column(db.Float, default=0.0)
    software_list = db.Column(db.Text, default="")
    startup_programs = db.Column(db.Text, default="") # Nova
    external_drives = db.Column(db.Text, default="")  # Nova
    
    # Controle
    pending_command = db.Column(db.String(500), default=None) # Aumentado para suportar comandos longos
    last_screenshot = db.Column(db.Text, default=None)
    ai_summary = db.Column(db.Text, default="Nenhuma análise gerada ainda.")
    
    # Relacionamentos
    logs = db.relationship('AgentLog', backref='agent', lazy=True)
    messages = db.relationship('ChatMessage', backref='agent', lazy=True)
    cves = db.relationship('AgentCVE', backref='agent', lazy=True)

class AgentLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    log_type = db.Column(db.String(50))
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    sender = db.Column(db.String(10), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

class AgentCVE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    cve_id = db.Column(db.String(20))
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# --- FUNÇÕES AUXILIARES ---
def log_event(agent_id, type, msg):
    try:
        log = AgentLog(agent_id=agent_id, log_type=type, message=msg)
        db.session.add(log)
    except: pass

def get_geo_info(ip):
    try:
        if not ip or ip == '127.0.0.1': return "Localhost"
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = r.json()
        if data['status'] == 'success':
            return f"{data.get('city')}, {data.get('country')}"
    except: pass
    return "Desconhecido"

# --- ROTAS ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Acesso Negado.')
    return render_template('dashboard.html', mode='login')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    agents = Agent.query.all()
    return render_template('dashboard.html', mode='dashboard', agents=agents)

@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    data = request.json
    env_token = os.getenv('API_TOKEN', '')
    
    if data.get('token') != env_token:
        return jsonify({'status': 'forbidden'}), 403

    agent = Agent.query.filter_by(hostname=data.get('hostname')).first()
    if not agent:
        agent = Agent(hostname=data.get('hostname'))
        db.session.add(agent)
        db.session.commit()
        log_event(agent.id, "SYSTEM", "Novo dispositivo registrado")

    # Atualiza dados básicos
    agent.ip_address = data.get('ip')
    agent.public_ip = data.get('public_ip')
    agent.mac_address = data.get('mac')
    agent.os_version = data.get('os_version')
    agent.cpu_usage = data.get('cpu')
    agent.ram_usage = data.get('ram')
    agent.status = 'online'
    agent.last_seen = datetime.utcnow()
    
    # Dados de Hardware/Software
    if data.get('software'): agent.software_list = data.get('software')
    if data.get('startup'): agent.startup_programs = data.get('startup')
    if data.get('drives'): agent.external_drives = data.get('drives')

    # Geolocalização (se mudou o IP ou está vazio)
    if agent.public_ip and (agent.geolocation == "Desconhecido" or "Localhost" in agent.geolocation):
        agent.geolocation = get_geo_info(agent.public_ip)

    if data.get('threats'):
        log_event(agent.id, "SECURITY", f"Ameaça detectada: {data.get('threats')}")

    # Processa retorno de comandos (Shell Output)
    if data.get('cmd_output'):
        log_event(agent.id, "SHELL_OUTPUT", data.get('cmd_output'))

    command = agent.pending_command
    agent.pending_command = None 

    unread_msgs = ChatMessage.query.filter_by(agent_id=agent.id, sender='admin', read=False).all()
    chat_payload = []
    for msg in unread_msgs:
        chat_payload.append(msg.content)
        msg.read = True

    db.session.commit()
    return jsonify({'command': command, 'chat': chat_payload})

@app.route('/api/upload_screenshot', methods=['POST'])
def upload_screenshot():
    data = request.json
    agent = Agent.query.filter_by(hostname=data.get('hostname')).first()
    if agent:
        agent.last_screenshot = data.get('image_data')
        log_event(agent.id, "INFO", "Captura de tela recebida")
        db.session.commit()
    return jsonify({'status': 'ok'})

@app.route('/api/send_chat', methods=['POST'])
def api_send_chat_client():
    data = request.json
    agent = Agent.query.filter_by(hostname=data.get('hostname')).first()
    if agent:
        msg = ChatMessage(agent_id=agent.id, sender='client', content=data.get('message'))
        db.session.add(msg)
        db.session.commit()
    return jsonify({'status': 'ok'})

@app.route('/control/command', methods=['POST'])
@login_required
def control_command():
    agent_id = request.form.get('agent_id')
    cmd_type = request.form.get('command')
    agent = Agent.query.get(agent_id)
    
    if cmd_type == 'chat':
        content = request.form.get('message')
        msg = ChatMessage(agent_id=agent.id, sender='admin', content=content)
        db.session.add(msg)
    elif cmd_type == 'shell':
        # Comando personalizado de terminal
        shell_cmd = request.form.get('shell_cmd')
        if shell_cmd:
            agent.pending_command = f"shell:{shell_cmd}"
            log_event(agent.id, "COMMAND", f"Shell enviado: {shell_cmd}")
    elif cmd_type == 'analyze_full':
        generate_analysis(agent)
    else:
        agent.pending_command = cmd_type
        if cmd_type == 'rename':
            agent.pending_command = f"rename:{request.form.get('new_name')}"
        log_event(agent.id, "COMMAND", f"Comando enviado: {agent.pending_command}")
    
    db.session.commit()
    return jsonify({'status': 'queued'})

@app.route('/get_agent_details/<int:agent_id>')
@login_required
def get_agent_details(agent_id):
    agent = Agent.query.get(agent_id)
    logs = AgentLog.query.filter_by(agent_id=agent.id).order_by(AgentLog.timestamp.desc()).limit(50).all()
    chat = ChatMessage.query.filter_by(agent_id=agent.id).order_by(ChatMessage.timestamp.asc()).all()
    cves = AgentCVE.query.filter_by(agent_id=agent.id).order_by(AgentCVE.timestamp.desc()).all()
    
    log_data = [{'type': l.log_type, 'msg': l.message, 'time': l.timestamp.strftime('%H:%M:%S')} for l in logs]
    chat_data = [{'sender': c.sender, 'msg': c.content, 'time': c.timestamp.strftime('%H:%M')} for c in chat]
    cve_data = [{'id': c.cve_id, 'desc': c.description, 'sev': c.severity} for c in cves]
    
    return jsonify({
        'hostname': agent.hostname,
        'ip': agent.ip_address,
        'public_ip': agent.public_ip,
        'mac': agent.mac_address,
        'geo': agent.geolocation,
        'os': agent.os_version,
        'software': agent.software_list,
        'startup': agent.startup_programs,
        'drives': agent.external_drives,
        'screenshot': agent.last_screenshot,
        'ai_report': agent.ai_summary,
        'logs': log_data,
        'chat': chat_data,
        'cves': cve_data
    })

def generate_analysis(agent):
    try:
        log_event(agent.id, "SCAN", "Consultando banco de dados NIST (CVEs)...")
        keyword = "Windows 11" if "11" in agent.os_version else "Windows 10"
        
        cve_results = nvdlib.searchCVE(keywordSearch=keyword, limit=3)
        AgentCVE.query.filter_by(agent_id=agent.id).delete()
        
        cve_text_list = []
        for cve in cve_results:
            sev = "Alta"
            if hasattr(cve, 'v31score'): sev = f"Score {cve.v31score}"
            new_cve = AgentCVE(agent_id=agent.id, cve_id=cve.id, description=cve.descriptions[0].value, severity=sev)
            db.session.add(new_cve)
            cve_text_list.append(f"- {cve.id} ({sev})")

        log_event(agent.id, "AI", "Gerando relatório OpenAI...")
        
        prompt = f"""
        Relatório de Segurança para: {agent.hostname}
        SO: {agent.os_version}
        Local: {agent.geolocation}
        Apps Startup: {agent.startup_programs[:300]}...
        Discos: {agent.external_drives}
        CVEs Críticos: {chr(10).join(cve_text_list)}
        
        Analise o risco dessa máquina e sugira ações.
        """
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "system", "content": "Seja um perito forense digital."},
                      {"role": "user", "content": prompt}]
        )
        agent.ai_summary = response.choices[0].message['content']
        log_event(agent.id, "SUCCESS", "Análise completa.")
    except Exception as e:
        log_event(agent.id, "ERROR", f"Falha na análise: {str(e)}")
        agent.ai_summary = f"Erro: {str(e)}"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    target_port = int(os.getenv('SERVER_PORT', 7070))
    print(f"AEGIS EDR v4.0 RODANDO NA PORTA {target_port}...")
    app.run(host='0.0.0.0', port=target_port)