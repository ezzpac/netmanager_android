import secrets
from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, login_manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user') # 'admin' or 'user'
    active = db.Column(db.Boolean, default=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)
    password_reset_requested = db.Column(db.Boolean, default=False)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_token(self, expires_sec=1800):
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiration = datetime.utcnow() + timedelta(seconds=expires_sec)
        return self.reset_token

    @staticmethod
    def verify_reset_token(token):
        user = User.query.filter_by(reset_token=token).first()
        if user is None or user.reset_token_expiration < datetime.utcnow():
            return None
        return user

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome_grupo = db.Column(db.String(100), unique=True, nullable=False)
    devices = db.relationship('Device', backref='group', lazy=True)

    def __repr__(self):
        return f'<Group {self.nome_grupo}>'

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome_local = db.Column(db.String(100), nullable=False)
    modelo = db.Column(db.String(100))
    ip = db.Column(db.String(15), unique=True, nullable=False)
    mac = db.Column(db.String(17))
    grupo_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    tipo = db.Column(db.String(50)) # Celular, Desktop, Notebook, Console, Portable, Sensor, Smart IR, Smart Speaker, Interruptor, Tomada, Tablet, LAN, Storage, Impressoras
    observacoes = db.Column(db.Text)
    status = db.Column(db.Boolean, default=False)
    service_tag = db.Column(db.String(100))
    usuario_atual = db.Column(db.String(150))
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    data_atualizacao = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Device {self.ip} - {self.nome_local}>'

class IPRange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rede = db.Column(db.String(50), nullable=False, default='192.168.0')
    faixa_inicio = db.Column(db.Integer, nullable=False) # Store only the last octet
    faixa_fim = db.Column(db.Integer, nullable=False)
    descricao = db.Column(db.String(200))

    def __repr__(self):
        return f'<IPRange {self.faixa_inicio}-{self.faixa_fim}>'

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='logs')
