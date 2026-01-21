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
from sqlalchemy import event
from sqlalchemy.engine import Engine

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

app = Flask(__name__)

secret_key = os.getenv('FLASK_SECRET_KEY', 'default_unsafe')
api_token = os.getenv('API_TOKEN', '')
openai.api_key = os.getenv('OPENAI_API_KEY')

app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aegis_core.db?timeout=60'
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
    hostname = db.Column(db.String(100), nullable=False)
    device_type = db.Column(db.String(20), default="desktop")
    ip_address = db.Column(db.String(50))
    public_ip = db.Column(db.String(50))
    mac_address = db.Column(db.String(50))
    geolocation = db.Column(db.String(100), default="Unknown")
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    tracking_enabled = db.Column(db.Boolean, default=False)
    os_version = db.Column(db.String(100))
    status = db.Column(db.String(20), default='offline')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    battery_level = db.Column(db.Integer, default=100)
    cpu_usage = db.Column(db.Float, default=0.0)
    ram_usage = db.Column(db.Float, default=0.0)
    software_list = db.Column(db.Text, default="")
    process_list = db.Column(db.Text, default="[]")
    clipboard_content = db.Column(db.Text, default="")
    startup_programs = db.Column(db.Text, default="")
    external_drives = db.Column(db.Text, default="")
    pending_command = db.Column(db.String(500), default=None)
    last_screenshot = db.Column(db.Text, default=None)
    ai_summary = db.Column(db.Text, default="No analysis.")
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

def log_event(agent_id, type, msg):
    try: db.session.add(AgentLog(agent_id=agent_id, log_type=type, message=msg))
    except: pass

def get_geo_ip(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        d = r.json()
        if d['status'] == 'success': return f"{d['city']}, {d['country']}"
    except: pass
    return "Unknown"

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
    alerts = AgentLog.query.filter(AgentLog.log_type.in_(['SECURITY', 'ALERT'])).order_by(AgentLog.timestamp.desc()).limit(20).all()
    return render_template('dashboard.html', mode='dashboard', agents=agents, alerts=alerts)

@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    data = request.json
    if data.get('token') != api_token:
        return jsonify({'status': '403 Forbidden'}), 403

    hostname = data.get('hostname')
    agent = Agent.query.filter_by(hostname=hostname).first()
    
    if not agent:
        agent = Agent(hostname=hostname)
        db.session.add(agent)
        db.session.commit()
        log_event(agent.id, "SYSTEM", "New device registered")

    agent.last_seen = datetime.utcnow()
    agent.status = 'online'
    agent.device_type = data.get('device_type', 'desktop')
    agent.ip_address = data.get('ip')
    agent.public_ip = data.get('public_ip')
    
    if data.get('gps'):
        agent.latitude = data['gps'].get('lat')
        agent.longitude = data['gps'].get('lng')
        agent.tracking_enabled = True
    
    agent.battery_level = data.get('battery', 100)
    agent.cpu_usage = data.get('cpu', 0)
    agent.ram_usage = data.get('ram', 0)
    
    if data.get('software'): agent.software_list = str(data.get('software'))
    if data.get('processes'): agent.process_list = str(data.get('processes'))
    if data.get('clipboard'): agent.clipboard_content = str(data.get('clipboard'))
    if data.get('startup'): agent.startup_programs = str(data.get('startup'))
    if data.get('drives'): agent.external_drives = str(data.get('drives'))

    if not agent.latitude and agent.public_ip and agent.geolocation == "Unknown":
        agent.geolocation = get_geo_ip(agent.public_ip)

    if data.get('threats'): log_event(agent.id, "SECURITY", f"Threat: {data.get('threats')}")
    if data.get('cmd_output'): log_event(agent.id, "SHELL", data.get('cmd_output'))

    cmd = agent.pending_command
    agent.pending_command = None

    unread = ChatMessage.query.filter_by(agent_id=agent.id, sender='admin', read=False).all()
    msgs = [m.content for m in unread]
    for m in unread: m.read = True

    try: db.session.commit()
    except: db.session.rollback()

    return jsonify({'command': cmd, 'chat': msgs})

@app.route('/control/command', methods=['POST'])
@login_required
def control_command():
    agent_id = request.form.get('agent_id')
    cmd = request.form.get('command')
    agent = db.session.get(Agent, agent_id)
    
    if cmd == 'chat':
        db.session.add(ChatMessage(agent_id=agent.id, sender='admin', content=request.form.get('message')))
    elif cmd == 'analyze_full':
        generate_analysis(agent)
    elif cmd == 'shell':
        agent.pending_command = f"shell:{request.form.get('shell_cmd')}"
    elif cmd == 'kill_proc':
        agent.pending_command = f"kill:{request.form.get('pid')}"
    else:
        agent.pending_command = cmd
        if cmd == 'rename': agent.pending_command = f"rename:{request.form.get('new_name')}"
        log_event(agent.id, "COMMAND", f"Sent: {agent.pending_command}")
    
    try: db.session.commit()
    except: db.session.rollback()
    return jsonify({'status': 'ok'})

@app.route('/api/upload_screenshot', methods=['POST'])
def upload_screenshot():
    data = request.json
    agent = Agent.query.filter_by(hostname=data.get('hostname')).first()
    if agent:
        agent.last_screenshot = data.get('image_data')
        log_event(agent.id, "INFO", "Screenshot received")
        try: db.session.commit()
        except: db.session.rollback()
    return jsonify({'status': 'ok'})

@app.route('/api/send_chat', methods=['POST'])
def api_send_chat_client():
    data = request.json
    agent = Agent.query.filter_by(hostname=data.get('hostname')).first()
    if agent:
        db.session.add(ChatMessage(agent_id=agent.id, sender='client', content=data.get('message')))
        try: db.session.commit()
        except: db.session.rollback()
    return jsonify({'status': 'ok'})

@app.route('/get_agent_details/<int:id>')
@login_required
def details(id):
    a = db.session.get(Agent, id)
    logs = AgentLog.query.filter_by(agent_id=a.id).order_by(AgentLog.timestamp.desc()).limit(50).all()
    chat = ChatMessage.query.filter_by(agent_id=a.id).order_by(ChatMessage.timestamp.asc()).all()
    cves = AgentCVE.query.filter_by(agent_id=a.id).all()
    
    return jsonify({
        'hostname': a.hostname,
        'type': a.device_type,
        'ip': a.ip_address,
        'public_ip': a.public_ip,
        'geo': a.geolocation,
        'gps': {'lat': a.latitude, 'lng': a.longitude} if a.latitude else None,
        'battery': a.battery_level,
        'os': a.os_version,
        'processes': a.process_list,
        'clipboard': a.clipboard_content,
        'startup': a.startup_programs,
        'drives': a.external_drives,
        'screenshot': a.last_screenshot,
        'ai': a.ai_summary,
        'logs': [{'time': l.timestamp.strftime('%H:%M'), 'type': l.log_type, 'msg': l.message} for l in logs],
        'chat': [{'sender': c.sender, 'msg': c.content} for c in chat],
        'cves': [{'id': c.cve_id, 'desc': c.description} for c in cves]
    })

def generate_analysis(agent):
    try:
        keyword = "Windows 11" if "11" in str(agent.os_version) else "Windows 10"
        cve_results = nvdlib.searchCVE(keywordSearch=keyword, limit=3)
        AgentCVE.query.filter_by(agent_id=agent.id).delete()
        cve_list = [f"{cve.id}" for cve in cve_results]
        prompt = f"Analyze: {agent.hostname} ({agent.os_version}). Startup: {agent.startup_programs[:200]}. CVEs: {', '.join(cve_list)}."
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "system", "content": "Security Analyst."}, {"role": "user", "content": prompt}]
        )
        agent.ai_summary = response.choices[0].message['content']
    except Exception as e:
        agent.ai_summary = str(e)

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(host='0.0.0.0', port=int(os.getenv('SERVER_PORT', 7070)))