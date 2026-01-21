import openai
import json
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 0000
OPENAI_API_KEY = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
FLASK_SECRET_KEY = "sk_auth_0000000000000000"
DB_URI = 'sqlite:///database.db'

app = Flask(__name__)
app.config['SECRET_KEY'] = FLASK_SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

openai.api_key = OPENAI_API_KEY

db = SQLAlchemy(app)
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
    ip_address = db.Column(db.String(50), nullable=False)
    mac_address = db.Column(db.String(50), nullable=True) 
    cpu_usage = db.Column(db.Float)
    ram_usage = db.Column(db.Float)
    av_status = db.Column(db.String(100))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    pending_command = db.Column(db.String(100), default=None)
    software_inventory = db.Column(db.Text, default="")
    alerts = db.relationship('Alert', backref='agent', lazy=True)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='medium')
    ai_analysis = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
            flash('Invalid credentials. Access denied.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    agents = Agent.query.all()
    alerts = Alert.query.filter_by(resolved=False).order_by(Alert.timestamp.desc()).limit(20).all()
    return render_template('dashboard.html', agents=agents, alerts=alerts)

@app.route('/command/<int:agent_id>/<action>', methods=['POST'])
@login_required
def send_command(agent_id, action):
    agent = Agent.query.get_or_404(agent_id)
    if action == 'restart':
        agent.pending_command = 'restart'
    elif action == 'rename':
        new_name = request.form.get('new_name')
        if new_name:
            agent.pending_command = f'rename:{new_name}'
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/alert/resolve/<int:alert_id>', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.resolved = True
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/api/report', methods=['POST'])
def api_report():
    data = request.json
    agent = Agent.query.filter_by(hostname=data.get('hostname')).first()
    
    if not agent:
        agent = Agent(hostname=data.get('hostname'), ip_address=data.get('ip'))
        db.session.add(agent)
    
    agent.ip_address = data.get('ip')
    agent.cpu_usage = data.get('cpu')
    agent.ram_usage = data.get('ram')
    agent.av_status = data.get('firewall')
    agent.software_inventory = data.get('software', '')
    agent.last_seen = datetime.utcnow()
    
    command = agent.pending_command
    agent.pending_command = None 
    db.session.commit()
    
    return jsonify({'status': 'ok', 'command': command})

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.json
    
    system_prompt = """
    You are a Tier 3 Cybersecurity Analyst. 
    Analyze the telemetry. Return ONLY JSON with keys: 
    "summary", "details" (with CVE references if possible), "remediation".
    """
    
    user_message = f"Telemetry: {json.dumps(data)}"
    
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ]
        )
        ai_text = response.choices[0].message['content']
        
        agent = Agent.query.filter_by(hostname=data['hostname']).first()
        if agent:
            new_alert = Alert(
                agent_id=agent.id,
                alert_type="AI_SECURITY_INCIDENT",
                message=f"Threats: {data.get('threats_found')}",
                severity="high",
                ai_analysis=ai_text
            )
            db.session.add(new_alert)
            db.session.commit()
            
        return jsonify({"status": "analyzed", "data": ai_text})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host=SERVER_HOST, port=SERVER_PORT)