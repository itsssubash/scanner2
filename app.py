import sys
import os
import json
import secrets
import string
import threading
from flask import Flask, jsonify, request, redirect, url_for, render_template, flash, session, Response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import datetime
from datetime import timedelta, timezone
from functools import wraps
import click
from pathlib import Path

from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_talisman import Talisman

import boto3
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet
import pyotp
import qrcode
from io import BytesIO
import base64
import re
from weasyprint import HTML
from apscheduler.schedulers.background import BackgroundScheduler
from waitress import serve
from itsdangerous import URLSafeTimedSerializer
import hashlib  # ADDED: Import hashlib

from parallel_scanner import run_parallel_scans_blocking, run_parallel_scans_progress

# --- Flask App Initialization ---
app = Flask(__name__, instance_relative_config=True, static_folder='static', template_folder='templates')

# --- Configuration Loading from Environment Variables ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['ENCRYPTION_KEY'] = os.environ.get('ENCRYPTION_KEY')
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')
app.config['ADMIN_REGISTRATION_KEY'] = os.environ.get('ADMIN_REGISTRATION_KEY')

# Use Heroku's Postgres DATABASE_URL if available, otherwise use local SQLite
if 'DATABASE_URL' in os.environ:
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("://", "ql://", 1)
else:
    APP_DATA_DIR = os.path.join(os.getenv('APPDATA', '.'), 'CloudSecurityScanner')
    os.makedirs(APP_DATA_DIR, exist_ok=True)
    DB_PATH = os.path.join(APP_DATA_DIR, 'app.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Extension Initialization ---
csrf = CSRFProtect(app)
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://cdn.jsdelivr.net', 'https://unpkg.com', '\'unsafe-inline\''],
    'style-src': ['\'self\'', 'https://cdnjs.cloudflare.com', 'https://fonts.googleapis.com', 'https://unpkg.com', 'https://cdn.jsdelivr.net', '\'unsafe-inline\''],
    'font-src': ['\'self\'', 'https://cdnjs.cloudflare.com', 'https://fonts.gstatic.com'],
    'img-src': ['\'self\'', 'data:']
}
Talisman(app, content_security_policy=csp)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'auth'
login_manager.login_message_category = "info"
mail = Mail(app)
CORS(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# --- Global Functions & Context Processors ---
@app.context_processor
def inject_csrf_token(): return dict(csrf_token_value=generate_csrf())

fernet = None
if app.config.get('ENCRYPTION_KEY'):
    fernet = Fernet(app.config['ENCRYPTION_KEY'].encode())

def encrypt_data(data): return fernet.encrypt(data.encode()).decode()
def decrypt_data(encrypted_data): return fernet.decrypt(encrypted_data.encode()).decode()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def check_verified(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.email_verified:
            flash("You must verify your email address to access this page.", "warning")
            return redirect(url_for('unverified'))
        return f(*args, **kwargs)
    return decorated_function

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(120), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    failed_login_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(32))
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    inactivity_timeout = db.Column(db.Integer, default=15, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    backup_email = db.Column(db.String(120), unique=True, nullable=True)
    backup_email_verified = db.Column(db.Boolean, default=False)
    notifications_enabled = db.Column(db.Boolean, nullable=False, default=True)
    report_schedule = db.Column(db.String(20), default='disabled', nullable=False)
    report_day = db.Column(db.String(10), nullable=True)
    report_credential_id = db.Column(db.Integer, nullable=True)
    scans = db.relationship('ScanResult', backref='author', lazy='dynamic', cascade="all, delete-orphan")
    credentials = db.relationship('AWSCredential', backref='owner', lazy='dynamic', cascade="all, delete-orphan")
    
    def set_password(self, password): self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    def check_password(self, password): return bcrypt.check_password_hash(self.password_hash, password)

class AWSCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    profile_name = db.Column(db.String(64), nullable=False)
    access_key_id = db.Column(db.String(128), nullable=False)
    encrypted_secret_access_key = db.Column(db.String(256), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String(64), index=True)
    resource = db.Column(db.String(128))
    status = db.Column(db.String(64))
    issue = db.Column(db.String(256))
    remediation = db.Column(db.String(512), nullable=True)
    doc_url = db.Column(db.String(256), nullable=True)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    ip_address = db.Column(db.String(45))
    action = db.Column(db.String(128))
    details = db.Column(db.String(256), nullable=True)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    user = db.relationship('User')

class SuppressedFinding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    finding_hash = db.Column(db.String(64), nullable=False, index=True)
    reason = db.Column(db.String(256), nullable=True)
    suppress_until = db.Column(db.DateTime, nullable=True)
    service = db.Column(db.String(64))
    resource = db.Column(db.String(128))
    issue = db.Column(db.String(256))
    user = db.relationship('User')

# --- Helper Functions ---
def _generate_finding_hash(finding):
    finding_string = f"{finding.get('service', '')}:{finding.get('resource', '')}:{finding.get('issue', '')}"
    return hashlib.sha256(finding_string.encode()).hexdigest()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def is_password_strong(password):
    if len(password) < 8: return False, "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password): return False, "Password must contain a lowercase letter."
    if not re.search(r"[A-Z]", password): return False, "Password must contain an uppercase letter."
    if not re.search(r"\d", password): return False, "Password must contain a digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): return False, "Password must contain a special character."
    return True, ""

def log_audit(action, details="", user=None):
    try:
        log_entry = AuditLog(action=action, details=details, ip_address=request.remote_addr, user_id=user.id if user else None)
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        print(f"Audit log failed: {e}")
        db.session.rollback()

def send_verification_email(user):
    token = s.dumps(user.email, salt='email-confirm-salt')
    msg = Message('Confirm Your Email for Aegis Scanner', recipients=[user.email])
    confirm_url = url_for('verify_email', token=token, _external=True)
    msg.html = render_template('confirm_email.html', confirm_url=confirm_url)
    try: mail.send(msg)
    except Exception as e: print(f"ERROR: Failed to send verification email: {e}")

def send_new_primary_email_verification(user, new_email):
    token = s.dumps({'user_id': user.id, 'new_email': new_email}, salt='new-primary-email-salt')
    msg = Message('Confirm Your New Primary Email', recipients=[new_email])
    confirm_url = url_for('verify_new_primary_email', token=token, _external=True)
    msg.html = render_template('confirm_new_primary_email.html', confirm_url=confirm_url)
    mail.send(msg)

def send_backup_email_verification(user, backup_email):
    token = s.dumps({'user_id': user.id, 'backup_email': backup_email}, salt='backup-email-salt')
    msg = Message('Confirm Your Backup Email', recipients=[backup_email])
    confirm_url = url_for('verify_backup_email', token=token, _external=True)
    msg.html = render_template('confirm_backup_email.html', confirm_url=confirm_url)
    mail.send(msg)

def _create_pdf_report(results):
    html_string = render_template('report.html', results=results, scan_date=datetime.datetime.now())
    return HTML(string=html_string).write_pdf()

def scheduled_scan_job():
    print(f"--- Running Daily Scheduled Job Check at {datetime.datetime.now()} ---")
    with app.app_context():
        today_weekday = datetime.datetime.now().strftime('%A').lower()
        today_day_of_month = str(datetime.datetime.now().day)
        weekly_users = User.query.filter_by(report_schedule='weekly', report_day=today_weekday).all()
        monthly_users = User.query.filter_by(report_schedule='monthly', report_day=today_day_of_month).all()
        users_to_report = set(weekly_users + monthly_users)
        for user in users_to_report:
            print(f"  -> Generating scheduled report for user: {user.username}")
            if not user.report_credential_id:
                print(f"  -> Skipping {user.username}: No credential selected for reporting.")
                continue
            credential = db.session.get(AWSCredential, user.report_credential_id)
            if not credential or credential.user_id != user.id:
                print(f"  -> Skipping {user.username}: Credential ID {user.report_credential_id} not found.")
                continue
            try:
                secret_key = decrypt_data(credential.encrypted_secret_access_key)
                aws_creds = {"aws_access_key_id": credential.access_key_id, "aws_secret_access_key": secret_key}
                scan_results = run_parallel_scans_blocking(**aws_creds)
                critical_findings = [r for r in scan_results if r.get('status') == 'CRITICAL']
                if user.notifications_enabled and critical_findings:
                    print(f"  -> Found {len(critical_findings)} critical issues. Sending alert to {user.email}")
                    alert_msg = Message("New Critical Security Alert from Aegis", recipients=[user.email])
                    alert_msg.html = render_template('alert_email.html', new_findings=critical_findings)
                    mail.send(alert_msg)
                pdf_bytes = _create_pdf_report(scan_results)
                report_msg = Message(f"Your Scheduled Aegis Cloud Security Report", recipients=[user.email])
                report_msg.body = "Please find your scheduled AWS security report attached."
                report_msg.attach("Aegis_Report.pdf", "application/pdf", pdf_bytes)
                mail.send(report_msg)
                print(f"  -> Successfully sent PDF report to {user.email}")
            except Exception as e:
                print(f"  -> ERROR: Failed to generate or send report for {user.username}: {e}")
    print("--- Scheduled Job Check Finished ---")

# --- Routes ---
@app.before_request
def check_session():
    if current_user.is_authenticated:
        session.permanent = True
        timeout_minutes = current_user.inactivity_timeout if hasattr(current_user, 'inactivity_timeout') else 15
        app.permanent_session_lifetime = timedelta(minutes=timeout_minutes)
        if 'last_activity' in session:
            last_activity_dt = datetime.datetime.fromisoformat(session['last_activity'])
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            if now_utc - last_activity_dt > app.permanent_session_lifetime:
                logout_user()
                flash('Your session has expired due to inactivity. Please log in again.', 'info')
        session['last_activity'] = datetime.datetime.now(datetime.timezone.utc).isoformat()

@app.route('/')
def welcome():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return render_template('welcome.html')

@app.route('/auth')
def auth():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return render_template('auth.html')

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login_post():
    login_identifier = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter(or_(User.username == login_identifier, User.email == login_identifier)).first()
    if user and user.is_locked:
        flash('This account is locked. Please contact an administrator.', 'error')
        return redirect(url_for('auth', _anchor='login'))
    if user and user.check_password(password):
        user.failed_login_attempts = 0
        db.session.commit()
        log_audit("Login Success", user=user)
        login_user(user)
        if not user.email_verified: return redirect(url_for('unverified'))
        if user.is_2fa_enabled:
            session['username_for_2fa'] = user.username
            return redirect(url_for('verify_2fa_login'))
        else:
            flash('For enhanced security, you must set up Two-Factor Authentication.', 'info')
            return redirect(url_for('setup_2fa'))
    else:
        log_audit("Login Failure", details=f"Attempt for user: '{login_identifier}'")
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= 3:
                user.is_locked = True
                log_audit("Account Locked", details=f"Account locked for user: '{user.username}'", user=user)
            db.session.commit()
        flash('Invalid username or password.', 'error')
        return redirect(url_for('auth', _anchor='login'))

@app.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    eula_accepted = request.form.get('eula')
    admin_key = request.form.get('admin_key')
    
    if not eula_accepted:
        flash('You must accept the EULA to register.', 'error')
        return redirect(url_for('auth', _anchor='register'))
    if password != confirm_password:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('auth', _anchor='register'))
    is_strong, message = is_password_strong(password)
    if not is_strong:
        flash(message, 'error')
        return redirect(url_for('auth', _anchor='register'))
    if User.query.filter_by(username=username).first():
        flash('Username already exists. Please choose another.', 'error')
        return redirect(url_for('auth', _anchor='register'))
    if User.query.filter_by(email=email).first():
        flash('Email address is already registered.', 'error')
        return redirect(url_for('auth', _anchor='register'))
        
    user = User(username=username, email=email)
    user.set_password(password)

    if app.config.get('ADMIN_REGISTRATION_KEY') and admin_key == app.config['ADMIN_REGISTRATION_KEY']:
        if User.query.filter_by(is_admin=True).count() < 2:
            user.is_admin = True
            print(f"INFO: Valid admin key provided. Promoting user '{username}' to admin.")
        else:
            print("WARNING: Valid admin key provided, but max admin count reached.")

    db.session.add(user)
    db.session.commit()
    send_verification_email(user)
    login_user(user)
    flash('Registration successful! A verification link has been sent to your email.', 'info')
    return redirect(url_for('unverified'))

@app.route('/verify-email/<token>')
@login_required
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=3600)
    except Exception:
        flash('The confirmation link is invalid or has expired.', 'error')
        return redirect(url_for('unverified'))
    if email != current_user.email:
        flash('Invalid verification link.', 'error')
        return redirect(url_for('unverified'))
    if not current_user.email_verified:
        current_user.email_verified = True
        db.session.commit()
        log_audit("Email Verified", user=current_user)
        flash('Your email has been verified! Please set up 2FA to continue.', 'success')
        return redirect(url_for('setup_2fa'))
    else:
        if not current_user.is_2fa_enabled:
            flash('Account already verified. Please set up 2FA to continue.', 'info')
            return redirect(url_for('setup_2fa'))
        else:
            flash('Account already verified.', 'info')
            return redirect(url_for('dashboard'))

@app.route('/unverified')
@login_required
def unverified():
    if current_user.email_verified: return redirect(url_for('dashboard'))
    return render_template('unverified.html')

@app.route('/resend-verification')
@login_required
def resend_verification():
    if current_user.email_verified: return redirect(url_for('dashboard'))
    send_verification_email(current_user)
    flash('A new verification email has been sent.', 'info')
    return redirect(url_for('unverified'))

@app.route('/eula')
def eula():
    return render_template('eula.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('welcome'))

@app.route('/setup-2fa')
@login_required
@check_verified
def setup_2fa():
    if current_user.is_2fa_enabled:
        flash('2FA is already enabled.', 'info')
        return redirect(url_for('dashboard'))
    current_user.otp_secret = pyotp.random_base32()
    db.session.commit()
    uri = pyotp.totp.TOTP(current_user.otp_secret).provisioning_uri(name=current_user.username, issuer_name="Aegis Cloud Scanner")
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf)
    qr_code = base64.b64encode(buf.getvalue()).decode('utf-8')
    return render_template('2fa_setup.html', qr_code=qr_code)

@app.route('/enable-2fa', methods=['POST'])
@login_required
@check_verified
def enable_2fa():
    otp_code = request.form.get('otp_code')
    totp = pyotp.TOTP(current_user.otp_secret)
    if totp.verify(otp_code, valid_window=1):
        current_user.is_2fa_enabled = True
        db.session.commit()
        flash('2FA has been successfully enabled! Welcome to the dashboard.', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid verification code. Please try again.', 'error')
        return redirect(url_for('setup_2fa'))

@app.route('/verify-2fa-login', methods=['GET', 'POST'])
def verify_2fa_login():
    username = session.get('username_for_2fa')
    if not username: return redirect(url_for('auth'))
    user = User.query.filter_by(username=username).first()
    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(otp_code, valid_window=1):
            login_user(user)
            session.pop('username_for_2fa', None)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA code.', 'error')
    return render_template('2fa_verify.html')

@app.route('/dashboard')
@login_required
@check_verified
def dashboard():
    if not current_user.is_2fa_enabled:
        flash('You must set up Two-Factor Authentication to access the dashboard.', 'info')
        return redirect(url_for('setup_2fa'))
    credentials = current_user.credentials.all()
    return render_template('dashboard.html', credentials=credentials)

@app.route('/api/v1/scan', methods=['GET'])
@login_required
@check_verified
def scan():
    if not current_user.is_2fa_enabled: return jsonify({"error": "2FA setup is required."}), 403
    profile_id = request.args.get('profile_id')
    if not profile_id: return jsonify({"error": "Credential profile ID is required."}), 400
    credential = AWSCredential.query.filter_by(id=profile_id, user_id=current_user.id).first()
    if not credential: return jsonify({"error": "Credential profile not found or access denied."}), 404
    user_id = current_user.id
    suppressed_hashes = {sf.finding_hash for sf in SuppressedFinding.query.filter_by(user_id=user_id).all()}
    try:
        secret_key = decrypt_data(credential.encrypted_secret_access_key)
        aws_creds = {"aws_access_key_id": credential.access_key_id, "aws_secret_access_key": secret_key}
        scan_results = run_parallel_scans_blocking(**aws_creds)
        scan_results = [r for r in scan_results if _generate_finding_hash(r) not in suppressed_hashes]
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        user = db.session.get(User, user_id)
        for result in scan_results:
            if "error" not in result:
                db_result = ScanResult(service=result.get('service'), resource=result.get('resource'), status=result.get('status'), issue=result.get('issue'), remediation=result.get('remediation'), doc_url=result.get('doc_url'), timestamp=scan_time, author=user)
                db.session.add(db_result)
        db.session.commit()
        return jsonify({"scan_results": scan_results, "cached": False})
    except Exception as e:
        print(f"Major scan error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/history', methods=['GET'])
@login_required
@check_verified
def history():
    if not current_user.is_2fa_enabled: return jsonify({"error": "2FA setup is required."}), 403
    page = request.args.get('page', 1, type=int)
    per_page = 50
    pagination = ScanResult.query.filter_by(author=current_user).order_by(ScanResult.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    results = pagination.items
    history_list = [{"id": r.id, "service": r.service, "resource": r.resource, "status": r.status, "issue": r.issue, "timestamp": r.timestamp.isoformat()} for r in results]
    return jsonify({"historical_scans": history_list, "page": pagination.page, "total_pages": pagination.pages, "has_next": pagination.has_next, "has_prev": pagination.has_prev})

@app.route('/api/v1/suppress_finding', methods=['POST'])
@login_required
def suppress_finding():
    data = request.get_json()
    finding = data.get('finding')
    if not finding: return jsonify({"error": "Finding data is required."}), 400
    finding_hash = _generate_finding_hash(finding)
    existing = SuppressedFinding.query.filter_by(user_id=current_user.id, finding_hash=finding_hash).first()
    if existing: return jsonify({"message": "Finding is already suppressed."}), 200
    new_suppression = SuppressedFinding(user_id=current_user.id, finding_hash=finding_hash, reason="Suppressed by user from dashboard.", service=finding.get('service'), resource=finding.get('resource'), issue=finding.get('issue'))
    db.session.add(new_suppression)
    db.session.commit()
    log_audit("Finding Suppressed", details=f"Hash: {finding_hash[:12]}...", user=current_user)
    return jsonify({"message": "Finding suppressed successfully."}), 201

@app.route('/api/v1/unsuppress_finding/<int:suppression_id>', methods=['POST'])
@login_required
def unsuppress_finding(suppression_id):
    suppression = SuppressedFinding.query.filter_by(id=suppression_id, user_id=current_user.id).first()
    if not suppression: return jsonify({"error": "Suppression not found or access denied."}), 404
    db.session.delete(suppression)
    db.session.commit()
    log_audit("Finding Un-suppressed", details=f"ID: {suppression_id}", user=current_user)
    return jsonify({"message": "Finding has been un-suppressed successfully."}), 200

@app.route('/api/v1/history/trends')
@login_required
@check_verified
def history_trends():
    if not current_user.is_2fa_enabled: return jsonify({"error": "2FA setup is required."}), 403
    thirty_days_ago = datetime.datetime.now(datetime.timezone.utc) - timedelta(days=30)
    trend_data = db.session.query(func.date(ScanResult.timestamp).label('scan_date'), func.count(ScanResult.id).label('critical_count')).filter(ScanResult.status == 'CRITICAL', ScanResult.timestamp >= thirty_days_ago, ScanResult.user_id == current_user.id).group_by('scan_date').order_by('scan_date').all()
    labels = [datetime.datetime.strptime(row.scan_date, '%Y-%m-%d').strftime('%b %d') for row in trend_data]
    data = [row.critical_count for row in trend_data]
    return jsonify({"labels": labels, "data": data})

@app.route('/api/v1/delete_history', methods=['POST'])
@login_required
def delete_history():
    try:
        num_deleted = ScanResult.query.filter_by(author=current_user).delete()
        db.session.commit()
        return jsonify({"message": f"Successfully deleted {num_deleted} of your historical scan results."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to delete history."}), 500

@app.route('/report/pdf')
@login_required
@check_verified
def generate_pdf_report():
    if not current_user.is_2fa_enabled:
        flash('You must set up Two-Factor Authentication to generate reports.', 'info')
        return redirect(url_for('setup_2fa'))
    scan_results = ScanResult.query.filter_by(author=current_user).order_by(ScanResult.timestamp.desc()).limit(50).all()
    if not scan_results:
        flash('Please run a scan first to generate a report.', 'info')
        return redirect(url_for('dashboard'))
    pdf_bytes = _create_pdf_report(scan_results)
    return Response(pdf_bytes, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=aegis_cloud_security_report.pdf'})

@app.route('/settings', methods=['GET', 'POST'])
@login_required
@check_verified
def settings():
    if not current_user.is_2fa_enabled:
        flash('You must set up Two-Factor Authentication to access settings.', 'info')
        return redirect(url_for('setup_2fa'))
    if request.method == 'POST':
        form_name = request.form.get('form_name')
        if form_name == 'timeout':
            try:
                timeout = int(request.form.get('inactivity_timeout'))
                if 5 <= timeout <= 120:
                    current_user.inactivity_timeout = timeout
                    db.session.commit()
                    flash(f'Inactivity timeout updated to {timeout} minutes.', 'success')
                else: flash('Timeout must be between 5 and 120 minutes.', 'error')
            except (ValueError, TypeError): flash('Invalid input for timeout.', 'error')
        elif form_name == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            if not current_user.check_password(current_password):
                flash('Your current password was incorrect.', 'error')
            else:
                is_strong, message = is_password_strong(new_password)
                if not is_strong: flash(message, 'error')
                else:
                    current_user.set_password(new_password)
                    db.session.commit()
                    log_audit("User changed password", user=current_user)
                    flash('Your password has been successfully updated.', 'success')
        elif form_name == 'disable_2fa':
            password_2fa = request.form.get('password_2fa')
            if not current_user.check_password(password_2fa):
                flash('Incorrect password. 2FA not disabled.', 'error')
            else:
                current_user.is_2fa_enabled = False
                db.session.commit()
                log_audit("User disabled 2FA", user=current_user)
                flash('Two-Factor Authentication has been disabled.', 'success')
        elif form_name == 'change_primary_email':
            new_email = request.form.get('new_email')
            password = request.form.get('password')
            if not current_user.check_password(password): flash('Incorrect password.', 'error')
            elif User.query.filter_by(email=new_email).first(): flash('That email address is already in use.', 'error')
            else:
                send_new_primary_email_verification(current_user, new_email)
                flash(f'A verification link has been sent to {new_email}.', 'info')
        elif form_name == 'add_backup_email':
            backup_email = request.form.get('backup_email')
            password = request.form.get('password')
            if not current_user.check_password(password): flash('Incorrect password.', 'error')
            elif User.query.filter_by(backup_email=backup_email).first() or User.query.filter_by(email=backup_email).first(): flash('That email address is already in use.', 'error')
            else:
                send_backup_email_verification(current_user, backup_email)
                flash(f'A verification link has been sent to {backup_email}.', 'info')
        elif form_name == 'add_aws_credential':
            profile_name = request.form.get('profile_name')
            access_key_id = request.form.get('access_key_id')
            secret_access_key = request.form.get('secret_access_key')
            if profile_name and access_key_id and secret_access_key:
                encrypted_secret = encrypt_data(secret_access_key)
                new_cred = AWSCredential(profile_name=profile_name, access_key_id=access_key_id, encrypted_secret_access_key=encrypted_secret, owner=current_user)
                db.session.add(new_cred)
                db.session.commit()
                log_audit("Added AWS Credential", details=f"Profile: {profile_name}", user=current_user)
                flash(f"Credential profile '{profile_name}' added successfully.", 'success')
            else:
                flash("All fields are required to add a credential profile.", 'error')
        elif form_name == 'notifications':
            notifications_enabled = request.form.get('notifications_enabled') == 'on'
            current_user.notifications_enabled = notifications_enabled
            db.session.commit()
            status = "enabled" if notifications_enabled else "disabled"
            log_audit(f"User {status} notifications", user=current_user)
            flash(f"Email notifications have been {status}.", 'success')
        elif form_name == 'report_schedule':
            current_user.report_schedule = request.form.get('report_schedule')
            if current_user.report_schedule == 'weekly': current_user.report_day = request.form.get('report_day_weekly')
            elif current_user.report_schedule == 'monthly': current_user.report_day = request.form.get('report_day_monthly')
            else: current_user.report_day = None
            cred_id = request.form.get('report_credential_id')
            current_user.report_credential_id = int(cred_id) if cred_id else None
            db.session.commit()
            log_audit(f"User updated report schedule to {current_user.report_schedule}", user=current_user)
            flash('Report schedule updated successfully.', 'success')
        return redirect(url_for('settings'))
    
    credentials = current_user.credentials.all()
    suppressed_findings = SuppressedFinding.query.filter_by(user_id=current_user.id).order_by(SuppressedFinding.id.desc()).all()
    return render_template('settings.html', credentials=credentials, suppressed_findings=suppressed_findings)

@app.route('/delete_credential/<int:credential_id>', methods=['POST'])
@login_required
def delete_credential(credential_id):
    credential = AWSCredential.query.filter_by(id=credential_id, user_id=current_user.id).first()
    if credential:
        db.session.delete(credential)
        db.session.commit()
        log_audit("Deleted AWS Credential", details=f"Profile: {credential.profile_name}", user=current_user)
        flash(f"Credential profile '{credential.profile_name}' has been deleted.", 'success')
    else:
        flash("Credential not found or you do not have permission to delete it.", 'error')
    return redirect(url_for('settings'))

@app.route('/verify-new-primary-email/<token>')
@login_required
def verify_new_primary_email(token):
    try:
        data = s.loads(token, salt='new-primary-email-salt', max_age=3600)
        user_id = data['user_id']
        new_email = data['new_email']
    except Exception:
        flash('The confirmation link is invalid or has expired.', 'error')
        return redirect(url_for('dashboard'))
    if user_id != current_user.id:
        flash('Invalid verification token.', 'error')
        return redirect(url_for('dashboard'))
    current_user.email = new_email
    current_user.email_verified = True
    db.session.commit()
    log_audit("User changed primary email", details=f"New email: {new_email}", user=current_user)
    flash('Your primary email has been successfully updated!', 'success')
    return redirect(url_for('settings'))

@app.route('/verify-backup-email/<token>')
@login_required
def verify_backup_email(token):
    try:
        data = s.loads(token, salt='backup-email-salt', max_age=3600)
        user_id = data['user_id']
        backup_email = data['backup_email']
    except Exception:
        flash('The confirmation link is invalid or has expired.', 'error')
        return redirect(url_for('settings'))
    if user_id != current_user.id:
        flash('Invalid verification token.', 'error')
        return redirect(url_for('settings'))
    current_user.backup_email = backup_email
    current_user.backup_email_verified = True
    db.session.commit()
    log_audit("User added backup email", details=f"Backup email: {backup_email}", user=current_user)
    flash('Your backup email has been verified and added to your account.', 'success')
    return redirect(url_for('settings'))

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    if not current_user.is_2fa_enabled:
        flash('You must have 2FA enabled to access the admin dashboard.', 'info')
        return redirect(url_for('setup_2fa'))
    all_users = User.query.order_by(User.username).all()
    all_scans = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('admin.html', users=all_users, scans=all_scans, audit_logs=audit_logs)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete:
        flash('User not found.', 'error')
        return redirect(url_for('admin_dashboard'))
    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin_dashboard'))
    log_audit("User Deleted", details=f"Deleted user: '{user_to_delete.username}'", user=current_user)
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f"User '{user_to_delete.username}' and all their scans have been deleted.", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/unlock_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def unlock_user(user_id):
    user_to_unlock = db.session.get(User, user_id)
    if user_to_unlock:
        user_to_unlock.is_locked = False
        user_to_unlock.failed_login_attempts = 0
        db.session.commit()
        log_audit("Account Unlocked", details=f"Unlocked user: '{user_to_unlock.username}'", user=current_user)
        flash(f"User '{user_to_unlock.username}' has been unlocked.", 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/promote_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def promote_user(user_id):
    admin_count = User.query.filter_by(is_admin=True).count()
    user_to_promote = db.session.get(User, user_id)
    if user_to_promote and user_to_promote.is_admin:
        flash(f"User '{user_to_promote.username}' is already an administrator.", 'info')
        return redirect(url_for('admin_dashboard'))
    if admin_count >= 2:
        flash('Cannot promote user. The maximum of 2 administrators has been reached.', 'error')
        return redirect(url_for('admin_dashboard'))
    if user_to_promote:
        user_to_promote.is_admin = True
        db.session.commit()
        log_audit("User Promoted", details=f"Promoted user: '{user_to_promote.username}' to Admin", user=current_user)
        flash(f"User '{user_to_promote.username}' has been promoted to administrator.", 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/request-password-reset', methods=['GET', 'POST'])
def request_password_reset():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and user.email:
            send_reset_email(user)
            log_audit("Password Reset Requested", details=f"For user: '{user.username}'", user=user)
            flash('A password reset link has been sent to the email associated with that account.', 'info')
            return redirect(url_for('auth'))
        else:
            flash('Username not found or no email on file.', 'error')
    return render_template('request_reset.html', title='Reset Password')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        flash('The confirmation link is invalid or has expired.', 'error')
        return redirect(url_for('request_password_reset'))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('auth'))
    if request.method == 'POST':
        password = request.form.get('password')
        is_strong, message = is_password_strong(password)
        if not is_strong:
            flash(message, 'error')
            return render_template('reset_password.html', title='Reset Password', token=token)
        user.set_password(password)
        log_audit("Password Reset Success", user=user)
        db.session.commit()
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('auth'))
    return render_template('reset_password.html', title='Reset Password', token=token)

@app.cli.command("make-admin")
@click.argument("username")
def make_admin(username):
    """Creates an admin user or promotes an existing user."""
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"User '{username}' not found.")
            return
        if user.is_admin:
            print(f"User '{username}' is already an admin.")
            return
        
        admin_count = User.query.filter_by(is_admin=True).count()
        if admin_count >= 2:
            print("Error: Maximum number of administrators (2) already exists. Cannot promote user.")
            return
            
        user.is_admin = True
        db.session.commit()
        print(f"User '{username}' has been granted admin privileges.")

if __name__ == '__main__':
    # This block is now more robust and handles the SETUP_MODE flag correctly.
    SETUP_MODE = os.environ.get('SETUP_MODE', 'False').lower() in ('true', '1', 't')
    if not SETUP_MODE:
        scheduler = BackgroundScheduler(daemon=True)
        scheduler.add_job(func=scheduled_scan_job, trigger='interval', hours=24)
        scheduler.start()
        print("Scheduler started.")
    else:
        print("Application is in SETUP MODE. Scheduler is disabled.")

    print(f"Server running on http://127.0.0.1:5000")
    serve(app, host='0.0.0.0', port=5000)