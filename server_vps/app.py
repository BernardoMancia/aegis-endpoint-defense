import os
import logging
from datetime import datetime
from dotenv import load_dotenv
import openai
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///aegis.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

openai.api_key = os.getenv('OPENAI_API_KEY')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100))
    ip_address = db.Column(db.String(50))
    os_info = db.Column(db.String(100))
    antivirus_status = db.Column(db.String(200), default="Unknown")
    status = db.Column(db.String(20), default='Offline')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

class Telemetry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('agent.id'))
    cpu_usage = db.Column(db.Float)
    ram_usage = db.Column(db.Float)
    disk_usage = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('agent.id'))
    severity = db.Column(db.String(20))
    message = db.Column(db.String(500))
    resolved = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def analyze_threat_ai(telemetry_data):
    if not openai.api_key or "sk-" not in openai.api_key:
        return None
    try:
        prompt = (f"Analyze metrics: CPU {telemetry_data['cpu']}%, RAM {telemetry_data['ram']}%. "
                  "Reply 'NORMAL' or 'ALERT: [reason]' if suspicious.")
        response = openai.Completion.create(
            model="gpt-3.5-turbo-instruct",
            prompt=prompt,
            max_tokens=20
        )
        return response.choices[0].text.strip()
    except Exception as e:
        logging.error(f"AI Error: {e}")
        return None

@app.route('/')
@login_required
def dashboard():
    agents = Agent.query.all()
    alerts = Alert.query.filter_by(resolved=False).order_by(Alert.timestamp.desc()).limit(10).all()
    return render_template('dashboard.html', agents=agents, alerts=alerts, user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/telemetry', methods=['POST'])
def receive_telemetry():
    data = request.json
    if not data:
        return jsonify({"error": "No data"}), 400

    hostname = data.get('hostname', 'Unknown')
    ip = request.remote_addr
    
    agent = Agent.query.filter_by(hostname=hostname).first()
    if not agent:
        agent = Agent(hostname=hostname)
        db.session.add(agent)
    
    agent.ip_address = ip
    agent.os_info = data.get('os', 'Unknown')
    agent.antivirus_status = data.get('antivirus', 'Unknown')
    agent.last_seen = datetime.utcnow()
    agent.status = 'Online'
    db.session.commit()

    cpu = data.get('cpu', 0)
    telemetry = Telemetry(
        agent_id=agent.id,
        cpu_usage=cpu,
        ram_usage=data.get('ram', 0),
        disk_usage=data.get('disk', 0)
    )
    db.session.add(telemetry)

    if cpu > 90:
        db.session.add(Alert(agent_id=agent.id, severity="High", message=f"Critical CPU Spike: {cpu}%"))

    db.session.commit()
    return jsonify({"status": "received", "command": "continue"})

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if not User.query.first():
            default_user = User(username='admin')
            default_user.set_password('admin')
            db.session.add(default_user)
            db.session.commit()

    host_env = os.getenv('SERVER_HOST', '0.0.0.0')
    port_env = int(os.getenv('SERVER_PORT', 5000))
    
    print(f"[*] Starting Server on {host_env}:{port_env}")
    app.run(host=host_env, port=port_env, debug=False)