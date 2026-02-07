from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_mail import Mail, Message
import os
import sqlite3
import json
import random
import string
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
from face_recognition_engine import FaceRecognition
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")

# ── Resume uploads ──────────────────────────────────────────────────
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads", "resumes")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_RESUME_EXTENSIONS = {"pdf", "doc", "docx"}
MAX_RESUME_SIZE = 5 * 1024 * 1024  # 5 MB
app.config["MAX_CONTENT_LENGTH"] = MAX_RESUME_SIZE

# ── Mail configuration ──────────────────────────────────────────────
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', '')
mail = Mail(app)

is_production = (
    os.getenv("FLASK_ENV") == "production"
    or os.getenv("ENV") == "production"
    or os.getenv("RENDER") == "true"
)

frontend_origin = os.getenv("FRONTEND_ORIGIN", "https://hire-spec-frontend.vercel.app/")
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", frontend_origin)
allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]

CORS(app, supports_credentials=True, origins=allowed_origins)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=(
        os.getenv("COOKIE_SECURE", "true" if is_production else "false").lower() == "true"
    ),
    SESSION_COOKIE_SAMESITE=os.getenv(
        "COOKIE_SAMESITE", "None" if is_production else "Lax"
    ),
)

# Database setup
DATABASE = os.getenv("DATABASE_PATH", os.path.join(os.getcwd(), "users.db"))

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  role TEXT NOT NULL DEFAULT 'candidate',
                  face_embedding TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    # Add email column to existing tables that don't have it
    try:
        c.execute("ALTER TABLE users ADD COLUMN email TEXT UNIQUE")
    except sqlite3.OperationalError:
        pass  # column already exists
    # Add role column to existing tables that don't have it
    try:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'candidate'")
    except sqlite3.OperationalError:
        pass  # column already exists
    # Add resume columns
    for col_sql in [
        "ALTER TABLE users ADD COLUMN resume_filename TEXT",
        "ALTER TABLE users ADD COLUMN resume_original_name TEXT",
        "ALTER TABLE users ADD COLUMN resume_uploaded_at TIMESTAMP",
    ]:
        try:
            c.execute(col_sql)
        except sqlite3.OperationalError:
            pass
    c.execute('''CREATE TABLE IF NOT EXISTS otp_codes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT NOT NULL,
                  otp TEXT NOT NULL,
                  purpose TEXT NOT NULL DEFAULT 'register',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  expires_at TIMESTAMP NOT NULL,
                  used INTEGER DEFAULT 0)''')

    # ── Hiring & assessment (basic) ────────────────────────────────
    c.execute('''CREATE TABLE IF NOT EXISTS companies
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT UNIQUE NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    c.execute('''CREATE TABLE IF NOT EXISTS jobs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER,
                  created_by_user_id INTEGER,
                  title TEXT NOT NULL,
                  description TEXT,
                  skills_json TEXT,
                  modules_json TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(company_id) REFERENCES companies(id),
                  FOREIGN KEY(created_by_user_id) REFERENCES users(id))''')

    c.execute('''CREATE TABLE IF NOT EXISTS assessments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  job_id INTEGER,
                  candidate_user_id INTEGER,
                  invited_email TEXT,
                  status TEXT NOT NULL DEFAULT 'Pending',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  updated_at TIMESTAMP,
                  FOREIGN KEY(job_id) REFERENCES jobs(id),
                  FOREIGN KEY(candidate_user_id) REFERENCES users(id))''')

    c.execute('''CREATE TABLE IF NOT EXISTS proctor_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  assessment_id INTEGER,
                  type TEXT NOT NULL,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  payload_json TEXT,
                  FOREIGN KEY(user_id) REFERENCES users(id),
                  FOREIGN KEY(assessment_id) REFERENCES assessments(id))''')

    c.execute('''CREATE TABLE IF NOT EXISTS candidate_reports
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  candidate_user_id INTEGER,
                  assessment_id INTEGER,
                  report_json TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(candidate_user_id) REFERENCES users(id),
                  FOREIGN KEY(assessment_id) REFERENCES assessments(id))''')

    c.execute('''CREATE TABLE IF NOT EXISTS applications
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  candidate_user_id INTEGER NOT NULL,
                  job_id INTEGER NOT NULL,
                  status TEXT NOT NULL DEFAULT 'Applied',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  UNIQUE(candidate_user_id, job_id),
                  FOREIGN KEY(candidate_user_id) REFERENCES users(id),
                  FOREIGN KEY(job_id) REFERENCES jobs(id))''')
    conn.commit()
    conn.close()

init_db()

face_engine = None
face_engine_error = None


# ── Auth helpers ───────────────────────────────────────────────────
ALLOWED_ROLES = {"candidate", "company_admin", "company_hr"}

# JWT Configuration
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_HOURS = int(os.getenv('JWT_EXPIRY_HOURS', 24))


def generate_jwt_token(user_data):
    """Generate JWT token for user authentication"""
    expires_at = datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    payload = {
        'id': user_data['id'],
        'username': user_data['username'],
        'email': user_data['email'],
        'role': user_data['role'],
        'exp': expires_at,
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def require_auth():
    user_id = session.get("user_id")
    if not user_id:
        return None, (jsonify({"message": "Unauthorized"}), 401)
    return user_id, None


def require_role(roles):
    user_id, err = require_auth()
    if err:
        return None, err
    role = session.get("role")
    if role not in roles:
        return None, (jsonify({"message": "Forbidden"}), 403)
    return user_id, None


def db_connect():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def get_face_engine():
    global face_engine, face_engine_error
    if face_engine is not None:
        return face_engine, None
    if face_engine_error is not None:
        return None, face_engine_error
    try:
        face_engine = FaceRecognition(
            min_score=float(os.getenv("FACE_MIN_SCORE", "0.35")),
            ratio_threshold=float(os.getenv("FACE_RATIO_THRESHOLD", "0.18")),
            adaptive_lr=float(os.getenv("FACE_ADAPTIVE_LR", "0.05")),
        )
        return face_engine, None
    except Exception as e:
        face_engine_error = str(e)
        return None, face_engine_error

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for deployment monitoring"""
    health_status = {
        'status': 'ok',
        'message': 'Face Auth Server is running',
        'version': '1.0.0',
        'python_version': '3.11',
        'environment': 'production' if is_production else 'development'
    }
    
    # Check database connectivity
    try:
        conn = sqlite3.connect(DATABASE)
        conn.execute("SELECT 1")
        conn.close()
        health_status['database'] = 'connected'
    except Exception:
        health_status['database'] = 'disconnected'
        health_status['status'] = 'degraded'
    
    return jsonify(health_status), 200 if health_status['status'] == 'ok' else 503

@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'status': 'ok',
        'message': 'Face Auth API. Use /health for status.'
    }), 200


# ── OTP helpers ──────────────────────────────────────────────────────
def generate_otp(length=6):
    """Generate a random numeric OTP"""
    return ''.join(random.choices(string.digits, k=length))


def get_otp_email_template(otp, purpose='register'):
    """Generate HTML email template for OTP"""
    if purpose == 'register':
        title = 'Email Verification Code'
        message = 'You requested to register a new account with Face Auth.'
        instruction = 'Enter this code in the registration form to verify your email:'
    else:
        title = 'Password Reset Code'
        message = 'You requested to reset your password.'
        instruction = 'Enter this code to set a new password:'
    
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica', 'Arial', sans-serif;
                line-height: 1.6;
                color: #333;
            }}
            .email-container {{
                max-width: 600px;
                margin: 0 auto;
                background: #f9fafb;
                padding: 20px;
            }}
            .email-card {{
                background: white;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }}
            .email-header {{
                background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
                padding: 30px 20px;
                text-align: center;
                color: white;
            }}
            .email-header h1 {{
                margin: 0;
                font-size: 24px;
                font-weight: 700;
            }}
            .email-body {{
                padding: 30px;
            }}
            .email-message {{
                font-size: 16px;
                margin-bottom: 20px;
                color: #666;
            }}
            .otp-section {{
                background: #f3f4f6;
                padding: 20px;
                border-radius: 6px;
                text-align: center;
                margin: 20px 0;
            }}
            .otp-label {{
                font-size: 12px;
                color: #999;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 10px;
            }}
            .otp-code {{
                font-size: 36px;
                font-weight: 700;
                letter-spacing: 4px;
                color: #1f2937;
                font-family: 'Courier New', monospace;
                margin: 10px 0;
            }}
            .otp-timer {{
                font-size: 14px;
                color: #f59e0b;
                margin-top: 10px;
            }}
            .email-footer {{
                padding: 0 30px 30px;
                font-size: 12px;
                color: #999;
                border-top: 1px solid #e5e7eb;
                margin-top: 20px;
            }}
            .warning {{
                background: #fef3c7;
                border-left: 4px solid #f59e0b;
                padding: 15px;
                font-size: 13px;
                color: #92400e;
                margin-top: 20px;
                border-radius: 4px;
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="email-card">
                <div class="email-header">
                    <h1>🛡️ Face Auth</h1>
                </div>
                <div class="email-body">
                    <h2 style="margin-top: 0;">{title}</h2>
                    <p class="email-message">{message}</p>
                    <p>{instruction}</p>
                    
                    <div class="otp-section">
                        <div class="otp-label">Your verification code</div>
                        <div class="otp-code">{otp}</div>
                        <div class="otp-timer">⏱️ This code expires in 10 minutes</div>
                    </div>
                    
                    <div class="warning">
                        <strong>⚠️ Security Notice:</strong> Never share this code with anyone. Face Auth support will never ask for your verification code.
                    </div>
                    
                    <div class="email-footer">
                        <p>If you didn't request this code, you can safely ignore this email.</p>
                        <p style="margin-bottom: 0;">© 2026 Face Auth. All rights reserved.</p>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return html_template


def send_otp_email(email, otp, purpose='register'):
    """Send OTP to user's email with HTML template"""
    subject_map = {
        'register': 'Your Registration OTP – Face Auth',
        'forgot_password': 'Password Reset OTP – Face Auth',
    }
    html_body = get_otp_email_template(otp, purpose)
    msg = Message(
        subject=subject_map.get(purpose, 'Your OTP – Face Auth'),
        recipients=[email],
        html=html_body,
    )
    mail.send(msg)


def store_otp(email, otp, purpose='register'):
    """Persist an OTP with 10-minute expiry"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    expires = datetime.utcnow() + timedelta(minutes=10)
    c.execute(
        "INSERT INTO otp_codes (email, otp, purpose, expires_at) VALUES (?, ?, ?, ?)",
        (email, otp, purpose, expires.isoformat()),
    )
    conn.commit()
    conn.close()


def verify_otp(email, otp, purpose='register'):
    """Verify an OTP; returns True when valid and marks it used"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute(
        """SELECT id, expires_at FROM otp_codes
           WHERE email = ? AND otp = ? AND purpose = ? AND used = 0
           ORDER BY created_at DESC LIMIT 1""",
        (email, otp, purpose),
    )
    row = c.fetchone()
    if not row:
        conn.close()
        return False
    otp_id, expires_at = row
    if datetime.utcnow() > datetime.fromisoformat(expires_at):
        conn.close()
        return False
    c.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (otp_id,))
    conn.commit()
    conn.close()
    return True


# ── OTP endpoints ────────────────────────────────────────────────────
@app.route('/api/auth/send-otp', methods=['POST'])
def send_otp():
    """
    Send an OTP to the given email.
    JSON: { "email": "user@example.com", "purpose": "register" | "forgot_password" }
    """
    try:
        data = request.json
        email = (data.get('email') or '').strip().lower()
        purpose = data.get('purpose', 'register')

        if not email:
            return jsonify({'message': 'Email is required'}), 400

        if purpose == 'forgot_password':
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE email = ?", (email,))
            if not c.fetchone():
                conn.close()
                return jsonify({'message': 'No account found with this email'}), 404
            conn.close()

        if purpose == 'register':
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE email = ?", (email,))
            if c.fetchone():
                conn.close()
                return jsonify({'message': 'Email is already registered'}), 400
            conn.close()

        otp = generate_otp()
        store_otp(email, otp, purpose)
        send_otp_email(email, otp, purpose)
        print(f"[OTP] Sent {purpose} OTP to {email}")

        return jsonify({'message': 'OTP sent successfully'}), 200
    except Exception as e:
        print(f"[OTP] Error sending OTP: {e}")
        import traceback; traceback.print_exc()
        return jsonify({'message': f'Failed to send OTP: {str(e)}'}), 500


@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp_endpoint():
    """
    Verify an OTP.
    JSON: { "email": "user@example.com", "otp": "123456", "purpose": "register" | "forgot_password" }
    """
    try:
        data = request.json
        email = (data.get('email') or '').strip().lower()
        otp = data.get('otp', '')
        purpose = data.get('purpose', 'register')

        if not email or not otp:
            return jsonify({'message': 'Email and OTP are required'}), 400

        if verify_otp(email, otp, purpose):
            return jsonify({'message': 'OTP verified', 'verified': True}), 200
        else:
            return jsonify({'message': 'Invalid or expired OTP', 'verified': False}), 400
    except Exception as e:
        return jsonify({'message': f'Server error: {str(e)}'}), 500


# ── Forgot-password / Reset-password ─────────────────────────────────
@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    """
    Step 1 – Send a reset OTP to the user's registered email.
    JSON: { "email": "user@example.com" }
    """
    try:
        data = request.json
        email = (data.get('email') or '').strip().lower()
        if not email:
            return jsonify({'message': 'Email is required'}), 400

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email = ?", (email,))
        if not c.fetchone():
            conn.close()
            return jsonify({'message': 'No account found with this email'}), 404
        conn.close()

        otp = generate_otp()
        store_otp(email, otp, 'forgot_password')
        send_otp_email(email, otp, 'forgot_password')
        print(f"[FORGOT-PASSWORD] Sent reset OTP to {email}")

        return jsonify({'message': 'Reset OTP sent to your email'}), 200
    except Exception as e:
        return jsonify({'message': f'Server error: {str(e)}'}), 500


@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    """
    Step 2 – After OTP is verified on the client, set a new password.
    JSON: { "email": "…", "password": "…", "confirmPassword": "…" }
    """
    try:
        data = request.json
        email = (data.get('email') or '').strip().lower()
        password = data.get('password', '')
        confirm = data.get('confirmPassword', '')

        if not email or not password:
            return jsonify({'message': 'Email and new password are required'}), 400
        if password != confirm:
            return jsonify({'message': 'Passwords do not match'}), 400
        if len(password) < 6:
            return jsonify({'message': 'Password must be at least 6 characters'}), 400

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        hashed = generate_password_hash(password)
        c.execute("UPDATE users SET password = ? WHERE email = ?", (hashed, email))
        if c.rowcount == 0:
            conn.close()
            return jsonify({'message': 'User not found'}), 404
        conn.commit()
        conn.close()

        print(f"[RESET-PASSWORD] Password updated for {email}")
        return jsonify({'message': 'Password reset successfully'}), 200
    except Exception as e:
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/auth/register', methods=['POST'])
def register():
    """
    Register a new user with multiple face encodings from different angles.
    Email OTP must have been verified before calling this endpoint.
    Expected JSON: {
      "username": "user123",
      "email": "user@example.com",
      "password": "pass123",
      "confirmPassword": "pass123",
      "images": ["base64...", ...],
      "role": "candidate" | "company_admin" | "company_hr"
    }
    """
    try:
        data = request.json
        username = data.get('username')
        email = (data.get('email') or '').strip().lower()
        password = data.get('password')
        confirm_password = data.get('confirmPassword')
        images_base64 = data.get('images', [])
        role = data.get('role', 'candidate')  # Default to candidate
        
        # Validate role
        valid_roles = ['candidate', 'company_admin', 'company_hr']
        if role not in valid_roles:
            role = 'candidate'
        
        print(f"[REGISTER] Received registration request for user: {username}, role: {role}")
        print(f"[REGISTER] Number of images received: {len(images_base64)}")
        
        if not username or not password or not email:
            print("[REGISTER] Error: Missing required fields")
            return jsonify({
                'message': 'Username, email and password are required'
            }), 400

        if password != confirm_password:
            return jsonify({'message': 'Passwords do not match'}), 400

        if len(password) < 6:
            return jsonify({'message': 'Password must be at least 6 characters'}), 400
        
        if not images_base64 or len(images_base64) < 3:
            print("[REGISTER] Error: Need at least 3 face images")
            return jsonify({
                'message': 'Please provide at least 3 face images'
            }), 400
        
        engine, engine_error = get_face_engine()
        if engine_error:
            print(f"[REGISTER] Face engine unavailable: {engine_error}")
            return jsonify({
                'message': f'Face engine unavailable: {engine_error}'
            }), 503
        # Check if user already exists by comparing uploaded images with stored faces
        face_exists, existing_user_id, check_error = engine.check_face_exists(images_base64)
        if check_error:
            print(f"[REGISTER] Face duplicate check error: {check_error}")
            # Allow registration to proceed with warning, don't block
        elif face_exists:
            print(f"[REGISTER] Face already registered to user: {existing_user_id}")
            return jsonify({'message': 'You are already registered'}), 409
        # Check if user already exists
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            return jsonify({'message': 'Username already exists'}), 400

        c.execute("SELECT id FROM users WHERE email = ?", (email,))
        if c.fetchone():
            conn.close()
            return jsonify({'message': 'Email is already registered'}), 400
        
        print(f"[REGISTER] Processing face registration for user: {username}")
        result, error = engine.register_user(username, images_base64)
        
        if error:
            conn.close()
            print(f"[REGISTER] Registration failed: {error}")
            return jsonify({'message': error}), 400

        # Store user in database
        hashed_password = generate_password_hash(password)
        face_embedding_json = json.dumps(result.get('embedding', []))
        
        c.execute("""INSERT INTO users (username, email, password, role, face_embedding) 
                     VALUES (?, ?, ?, ?, ?)""", 
                  (username, email, hashed_password, role, face_embedding_json))
        conn.commit()
        user_id = c.lastrowid
        c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user_row = c.fetchone()
        conn.close()

        print(f"[REGISTER] Success! User {username} registered with role {role} and {result['samples']} face samples")
        
        # Log user in automatically
        session['user_id'] = user_id
        session['username'] = username
        session['role'] = role
        
        # Generate JWT token
        user_data = {
            'id': user_row[0],
            'username': user_row[1],
            'email': user_row[2],
            'role': user_row[4]
        }
        token = generate_jwt_token(user_data)
        
        return jsonify({
            'id': user_row[0],
            'username': user_row[1],
            'email': user_row[2],
            'role': user_row[4],
            'token': token,
            'faceEmbedding': json.loads(user_row[5]) if user_row[5] else None,
            'createdAt': user_row[6]
        }), 201
            
    except Exception as e:
        print(f"[REGISTER] Exception occurred: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'message': f'Server error: {str(e)}'
        }), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Traditional username/password login"""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'message': 'Missing credentials'}), 401
        
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_row = c.fetchone()
        conn.close()
        
        if not user_row or not check_password_hash(user_row[3], password):
            return jsonify({'message': 'Invalid username or password'}), 401
        
        session['user_id'] = user_row[0]
        session['username'] = user_row[1]
        session['role'] = user_row[4]
        
        # Generate JWT token
        user_data = {
            'id': user_row[0],
            'username': user_row[1],
            'email': user_row[2],
            'role': user_row[4]
        }
        token = generate_jwt_token(user_data)
        
        return jsonify({
            'id': user_row[0],
            'username': user_row[1],
            'email': user_row[2],
            'role': user_row[4],
            'token': token,
            'faceEmbedding': json.loads(user_row[5]) if user_row[5] else None,
            'createdAt': user_row[6]
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/auth/face-login', methods=['POST'])
def face_login():
    """
    Face-based login - verify face and authenticate user
    Expected JSON: { "image": "base64..." }
    """
    try:
        data = request.json
        image_base64 = data.get('image')
        
        print(f"[FACE-LOGIN] Received face login request")
        
        if not image_base64:
            print(f"[FACE-LOGIN] Error: No image provided")
            return jsonify({'message': 'Missing image'}), 401
        
        engine, engine_error = get_face_engine()
        if engine_error:
            print(f"[FACE-LOGIN] Face engine unavailable: {engine_error}")
            return jsonify({'message': f'Face engine unavailable: {engine_error}'}), 503

        result, error = engine.verify_user(image_base64)
        if error:
            print(f"[FACE-LOGIN] Verification failed: {error}")
            return jsonify({'message': error}), 401

        username = result["user_id"]
        score = result.get("score", 0)
        print(f"[FACE-LOGIN] Face matched with user: {username}, score: {score}")
        
        # Get user from database
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_row = c.fetchone()
        conn.close()
        
        if not user_row:
            print(f"[FACE-LOGIN] Error: User not found in database: {username}")
            return jsonify({'message': 'User not found'}), 401
        
        session['user_id'] = user_row[0]
        session['username'] = user_row[1]
        session['role'] = user_row[4]  # Store role in session
        
        # Generate JWT token
        user_data = {
            'id': user_row[0],
            'username': user_row[1],
            'email': user_row[2],
            'role': user_row[4]
        }
        token = generate_jwt_token(user_data)
        
        print(f"[FACE-LOGIN] Login successful for user: {username}, role: {user_row[4]}")
        return jsonify({
            'id': user_row[0],
            'username': user_row[1],
            'email': user_row[2],
            'role': user_row[4],
            'token': token,
            'faceEmbedding': json.loads(user_row[5]) if user_row[5] else None,
            'createdAt': user_row[6]
        }), 200
            
    except Exception as e:
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/user/me', methods=['GET'])
def get_current_user():
    """Get currently logged in user"""
    try:
        if 'user_id' not in session:
            return jsonify({'message': 'Not authenticated'}), 401
        
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        user_row = c.fetchone()
        conn.close()
        
        if not user_row:
            return jsonify({'message': 'User not found'}), 401
        
        return jsonify({
            'id': user_row[0],
            'username': user_row[1],
            'email': user_row[2],
            'role': user_row[4],
            'faceEmbedding': json.loads(user_row[5]) if user_row[5] else None,
            'createdAt': user_row[6]
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Log out the current user"""
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/auth/reset-face', methods=['POST'])
def reset_face():
    """Reset face data after password verification"""
    try:
        if 'user_id' not in session:
            return jsonify({'message': 'Not authenticated'}), 401
        
        data = request.json
        password = data.get('password')
        images_base64 = data.get('images', [])
        
        if not password:
            return jsonify({'message': 'Password required'}), 400
        
        if not images_base64 or len(images_base64) < 3:
            return jsonify({'message': 'Please provide at least 3 face images'}), 400
        
        # Verify password
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT username, password FROM users WHERE id = ?", (session['user_id'],))
        user_row = c.fetchone()
        # user_row from this query: (username, password)
        if not user_row or not check_password_hash(user_row[1], password):
            conn.close()
            return jsonify({'message': 'Invalid password'}), 401
        
        username = user_row[0]
        
        engine, engine_error = get_face_engine()
        if engine_error:
            return jsonify({'message': f'Face engine unavailable: {engine_error}'}), 503

        # Delete old face data from Pinecone
        try:
            engine.index.delete(filter={"user_id": username})
            print(f"[RESET] Deleted old face data for user: {username}")
        except Exception as e:
            print(f"[RESET] Warning: Could not delete old face data: {e}")
        
        # Register new face data
        result, error = engine.register_user(username, images_base64)
        
        if error:
            conn.close()
            return jsonify({'message': error}), 400
        
        # Update database
        face_embedding_json = json.dumps(result.get('embedding', []))
        c.execute("UPDATE users SET face_embedding = ? WHERE id = ?", 
                  (face_embedding_json, session['user_id']))
        conn.commit()
        conn.close()
        
        print(f"[RESET] Face data reset successfully for user: {username}")
        return jsonify({
            'message': 'Face data reset successfully',
            'samples': result['samples']
        }), 200
        
    except Exception as e:
        print(f"[RESET] Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/auth/verify-identity', methods=['POST'])
def verify_identity():
    """
    Verify that the face in the image matches a specific registered user.
    Used during interviews to ensure the same person who registered is taking the interview.
    Expected JSON: { "user_id": "username", "image": "base64..." }
    """
    try:
        data = request.json
        user_id = data.get('user_id')
        image_base64 = data.get('image')
        strict = data.get('strict', True)  # Use strict matching by default
        
        print(f"[VERIFY-IDENTITY] Received identity verification request for user: {user_id}")
        
        if not user_id:
            return jsonify({'message': 'Missing user_id', 'verified': False}), 400
        
        if not image_base64:
            return jsonify({'message': 'Missing image', 'verified': False}), 400
        
        engine, engine_error = get_face_engine()
        if engine_error:
            print(f"[VERIFY-IDENTITY] Face engine unavailable: {engine_error}")
            return jsonify({'message': f'Face engine unavailable: {engine_error}', 'verified': False}), 503

        result, error = engine.verify_specific_user(user_id, image_base64, strict=strict)
        
        if error:
            print(f"[VERIFY-IDENTITY] Verification error: {error}")
            return jsonify({'message': error, 'verified': False}), 400

        print(f"[VERIFY-IDENTITY] Verification result: verified={result.get('verified')}, score={result.get('score')}")
        
        # Log identity verification for proctoring
        if 'user_id' in session:
            try:
                conn = sqlite3.connect(DATABASE)
                c = conn.cursor()
                c.execute('''INSERT INTO proctor_logs (user_id, type, payload_json)
                            VALUES (?, ?, ?)''',
                         (session['user_id'], 'identity_verification', json.dumps({
                             'verified': result.get('verified'),
                             'score': result.get('score'),
                             'liveness': result.get('liveness'),
                             'timestamp': datetime.now().isoformat()
                         })))
                conn.commit()
                conn.close()
            except Exception as log_error:
                print(f"[VERIFY-IDENTITY] Failed to log verification: {log_error}")
        
        return jsonify({
            'verified': result.get('verified', False),
            'score': result.get('score', 0),
            'liveness': result.get('liveness', False),
            'user_id': result.get('user_id'),
            'reason': result.get('reason')
        }), 200
            
    except Exception as e:
        print(f"[VERIFY-IDENTITY] Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'message': f'Server error: {str(e)}', 'verified': False}), 500

@app.route('/detect_face', methods=['POST'])
def detect_face():
    """Lightweight face presence check for client quality gating"""
    try:
        data = request.json
        image_base64 = data.get('image')
        if not image_base64:
            return jsonify({
                'face': False,
                'message': 'Missing image'
            }), 400

        engine, engine_error = get_face_engine()
        if engine_error:
            return jsonify({
                'face': False,
                'message': f'Face engine unavailable: {engine_error}'
            }), 503

        frame = engine.decode_base64_image(image_base64)
        if frame is None:
            print("[DETECT_FACE] Failed to decode image")
            return jsonify({
                'face': False,
                'message': 'Failed to decode image'
            }), 400

        present = engine.detect_face(frame)
        return jsonify({
            'face': bool(present)
        }), 200
    except Exception as e:
        print(f"[DETECT_FACE] Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'face': False,
            'message': f'Server error: {str(e)}'
        }), 500

@app.route('/users', methods=['GET'])
def get_users():
    """Get stats for registered users in Pinecone"""
    try:
        engine, engine_error = get_face_engine()
        if engine_error:
            return jsonify({
                'success': False,
                'message': f'Face engine unavailable: {engine_error}'
            }), 503

        stats = engine.index.describe_index_stats()
        total = stats.get("total_vector_count", 0)
        return jsonify({
            'success': True,
            'count': total
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}'
        }), 500

@app.route('/admin/users', methods=['GET'])
def admin_list_users():
    """List users with face metadata for the dashboard"""
    try:
        limit = int(request.args.get('limit', 100))
        cursor = request.args.get('cursor')
        engine, engine_error = get_face_engine()
        if engine_error:
            return jsonify({
                'success': False,
                'message': f'Face engine unavailable: {engine_error}'
            }), 503

        users, next_token = engine.list_users(limit=limit, pagination_token=cursor)

        return jsonify({
            'success': True,
            'users': users,
            'next_cursor': next_token
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}'
        }), 500

@app.route('/admin/users/<user_id>/embeddings', methods=['GET'])
def admin_user_embeddings(user_id):
    """Return raw embeddings for debugging"""
    try:
        engine, engine_error = get_face_engine()
        if engine_error:
            return jsonify({
                'success': False,
                'message': f'Face engine unavailable: {engine_error}'
            }), 503

        data = engine.get_user_embedding(user_id)
        if not data:
            return jsonify({
                'success': False,
                'message': 'User not found'
            }), 404
        return jsonify(data), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}'
        }), 500

@app.route('/admin/users/<user_id>/face', methods=['DELETE'])
def admin_delete_face(user_id):
    """Delete user face data from Pinecone"""
    try:
        engine, engine_error = get_face_engine()
        if engine_error:
            return jsonify({
                'success': False,
                'message': f'Face engine unavailable: {engine_error}'
            }), 503

        engine.delete_user_face(user_id)
        return jsonify({
            'success': True
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}'
        }), 500


@app.route('/admin/db-users', methods=['GET'])
def admin_db_users():
    user_id, err = require_role({"company_admin"})
    if err:
        return err
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute(
            "SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC LIMIT 200"
        )
        items = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"users": items}), 200
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ── Hiring & assessment APIs (basic) ───────────────────────────────
@app.route('/admin/create-company', methods=['POST'])
def create_company():
    user_id, err = require_role({"company_admin"})
    if err:
        return err
    data = request.json or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"message": "Missing company name"}), 400
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute("INSERT INTO companies (name) VALUES (?)", (name,))
        conn.commit()
        company_id = c.lastrowid
        conn.close()
        return jsonify({"id": company_id, "name": name, "created_by": user_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Company already exists"}), 400
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/admin/stats', methods=['GET'])
def admin_stats():
    user_id, err = require_role({"company_admin"})
    if err:
        return err
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) AS n FROM companies")
        companies = int(c.fetchone()["n"])
        c.execute("SELECT COUNT(*) AS n FROM jobs")
        jobs = int(c.fetchone()["n"])
        c.execute("SELECT COUNT(*) AS n FROM assessments")
        assessments = int(c.fetchone()["n"])
        c.execute("SELECT COUNT(*) AS n FROM proctor_logs")
        proctor_events = int(c.fetchone()["n"])
        conn.close()
        return jsonify({
            "companies": companies,
            "jobs": jobs,
            "assessments": assessments,
            "proctor_events": proctor_events,
            "server_health": "ok",
        }), 200
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/job/create', methods=['POST'])
def create_job():
    user_id, err = require_role({"company_admin", "company_hr"})
    if err:
        return err
    data = request.json or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"message": "Missing job title"}), 400
    description = (data.get("description") or "").strip()
    skills = data.get("skills") or []
    modules = data.get("modules") or []
    company_id = data.get("company_id")
    try:
        skills_json = json.dumps(skills)
        modules_json = json.dumps(modules)
        conn = db_connect()
        c = conn.cursor()
        c.execute(
            "INSERT INTO jobs (company_id, created_by_user_id, title, description, skills_json, modules_json) VALUES (?, ?, ?, ?, ?, ?)",
            (company_id, user_id, title, description, skills_json, modules_json),
        )
        conn.commit()
        job_id = c.lastrowid
        conn.close()
        return jsonify({
            "id": job_id,
            "title": title,
            "description": description,
            "skills": skills,
            "modules": modules,
        }), 201
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/assessment/invite', methods=['POST'])
def invite_assessment():
    user_id, err = require_role({"company_admin", "company_hr"})
    if err:
        return err
    data = request.json or {}
    job_id = data.get("job_id")
    candidate_email = (data.get("candidateEmail") or data.get("email") or "").strip().lower()
    if not job_id or not candidate_email:
        return jsonify({"message": "Missing job_id or candidateEmail"}), 400
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email = ?", (candidate_email,))
        row = c.fetchone()
        candidate_user_id = int(row["id"]) if row else None

        c.execute(
            "INSERT INTO assessments (job_id, candidate_user_id, invited_email, status, updated_at) VALUES (?, ?, ?, ?, ?)",
            (job_id, candidate_user_id, candidate_email, "Assessment Sent", datetime.utcnow().isoformat()),
        )
        conn.commit()
        assessment_id = c.lastrowid
        conn.close()
        return jsonify({
            "message": "Assessment invite created",
            "assessmentId": assessment_id,
            "jobId": job_id,
            "candidateEmail": candidate_email,
        }), 200
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/api/candidate/assessments', methods=['GET'])
def list_candidate_assessments():
    user_id, err = require_role({"candidate"})
    if err:
        return err
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute(
            "SELECT a.id, a.status, a.created_at, j.title as job_title FROM assessments a LEFT JOIN jobs j ON a.job_id = j.id WHERE a.candidate_user_id = ? OR a.invited_email = (SELECT email FROM users WHERE id = ?) ORDER BY a.created_at DESC",
            (user_id, user_id),
        )
        items = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"assessments": items}), 200
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/api/candidate/jobs', methods=['GET'])
def list_candidate_jobs():
    user_id, err = require_role({"candidate"})
    if err:
        return err
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute(
            """
            SELECT j.id, j.title, j.description, j.skills_json, j.created_at,
                   c.name AS company_name
            FROM jobs j
            LEFT JOIN companies c ON j.company_id = c.id
            ORDER BY j.created_at DESC
            LIMIT 50
            """
        )
        rows = []
        for row in c.fetchall():
            item = dict(row)
            try:
                item["skills"] = json.loads(item.get("skills_json") or "[]")
            except Exception:
                item["skills"] = []
            item.pop("skills_json", None)
            rows.append(item)
        conn.close()
        return jsonify({"jobs": rows}), 200
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/api/candidate/apply', methods=['POST'])
def candidate_apply_job():
    user_id, err = require_role({"candidate"})
    if err:
        return err
    data = request.json or {}
    job_id = data.get("job_id")
    if not job_id:
        return jsonify({"message": "Missing job_id"}), 400
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute(
            "INSERT INTO applications (candidate_user_id, job_id, status) VALUES (?, ?, ?)",
            (user_id, job_id, "Applied"),
        )
        conn.commit()
        app_id = c.lastrowid
        conn.close()
        return jsonify({"id": app_id, "job_id": job_id, "status": "Applied"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Already applied"}), 400
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/api/candidate/applications', methods=['GET'])
def list_candidate_applications():
    user_id, err = require_role({"candidate"})
    if err:
        return err
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute(
            """
            SELECT a.id, a.status, a.created_at,
                   j.id AS job_id, j.title AS job_title,
                   c.name AS company_name
            FROM applications a
            LEFT JOIN jobs j ON a.job_id = j.id
            LEFT JOIN companies c ON j.company_id = c.id
            WHERE a.candidate_user_id = ?
            ORDER BY a.created_at DESC
            LIMIT 100
            """,
            (user_id,),
        )
        items = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"applications": items}), 200
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/candidate/<int:candidate_id>/report', methods=['GET'])
def get_candidate_report(candidate_id):
    user_id, err = require_role({"company_admin", "company_hr"})
    if err:
        return err
    assessment_id = request.args.get("assessmentId")
    try:
        conn = db_connect()
        c = conn.cursor()
        if assessment_id:
            c.execute(
                "SELECT report_json, created_at FROM candidate_reports WHERE candidate_user_id = ? AND assessment_id = ? ORDER BY created_at DESC LIMIT 1",
                (candidate_id, assessment_id),
            )
        else:
            c.execute(
                "SELECT report_json, created_at FROM candidate_reports WHERE candidate_user_id = ? ORDER BY created_at DESC LIMIT 1",
                (candidate_id,),
            )
        row = c.fetchone()
        conn.close()
        if not row:
            return jsonify({
                "candidateId": candidate_id,
                "report": None,
                "message": "No report available yet",
            }), 200
        return jsonify({
            "candidateId": candidate_id,
            "report": json.loads(row["report_json"]),
            "createdAt": row["created_at"],
        }), 200
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/proctor/log', methods=['POST'])
def proctor_log():
    user_id, err = require_auth()
    if err:
        return err
    data = request.json or {}
    event_type = (data.get("type") or "").strip()
    if not event_type:
        return jsonify({"message": "Missing type"}), 400
    assessment_id = data.get("assessmentId")
    payload = data.get("payload")
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute(
            "INSERT INTO proctor_logs (user_id, assessment_id, type, payload_json) VALUES (?, ?, ?, ?)",
            (user_id, assessment_id, event_type, json.dumps(payload) if payload is not None else None),
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True}), 200
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/code/execute', methods=['POST'])
def code_execute():
    user_id, err = require_role({"candidate"})
    if err:
        return err
    # Intentionally disabled for safety in this basic implementation.
    return jsonify({
        "stdout": "",
        "stderr": "Code execution is disabled in this basic backend implementation.",
        "exitCode": 1,
    }), 200


@app.route('/code/analyze', methods=['POST'])
def code_analyze():
    user_id, err = require_role({"candidate"})
    if err:
        return err
    data = request.json or {}
    code = data.get("code") or ""
    language = (data.get("language") or "").strip() or "unknown"
    lines = len([ln for ln in code.splitlines() if ln.strip()])
    # Basic heuristic score; replace with your model integration later.
    score = max(0, min(100, 30 + min(70, lines)))
    return jsonify({
        "issues": [],
        "complexity": "N/A",
        "score": int(score),
        "language": language,
        "lines": lines,
    }), 200


@app.route('/api/v1/generate-report', methods=['POST'])
def generate_report():
    user_id, err = require_role({"candidate"})
    if err:
        return err
    data = request.json or {}
    candidate_id = data.get("candidateId")
    assessment_id = data.get("assessmentId")
    if not candidate_id or not assessment_id:
        return jsonify({"message": "Missing candidateId or assessmentId"}), 400
    # Candidate can only generate their own report.
    if str(candidate_id) != str(user_id):
        return jsonify({"message": "Forbidden"}), 403

    report = {
        "candidateId": candidate_id,
        "assessmentId": assessment_id,
        "codeSnapshot": data.get("codeSnapshot"),
        "browserLogs": data.get("browserLogs") or [],
        "audioTranscript": data.get("audioTranscript") or "",
        "generatedAt": datetime.utcnow().isoformat() + "Z",
        "summary": "Basic report generated (model integration pending).",
    }

    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute(
            "INSERT INTO candidate_reports (candidate_user_id, assessment_id, report_json) VALUES (?, ?, ?)",
            (user_id, assessment_id, json.dumps(report)),
        )
        # Update assessment status if it exists.
        c.execute(
            "UPDATE assessments SET status = ?, updated_at = ? WHERE id = ?",
            ("Completed", datetime.utcnow().isoformat(), assessment_id),
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "report": report}), 200
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ── Resume Upload / Download / Delete ─────────────────────────────

def _allowed_resume(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_RESUME_EXTENSIONS


@app.route('/api/candidate/resume', methods=['POST'])
def upload_resume():
    user_id, err = require_role({"candidate"})
    if err:
        return err
    if 'resume' not in request.files:
        return jsonify({"message": "No file uploaded"}), 400
    file = request.files['resume']
    if file.filename == '':
        return jsonify({"message": "Empty filename"}), 400
    if not _allowed_resume(file.filename):
        return jsonify({"message": "Only PDF, DOC, DOCX files are allowed"}), 400
    try:
        ext = file.filename.rsplit('.', 1)[1].lower()
        safe_name = f"resume_{user_id}_{int(datetime.utcnow().timestamp())}.{ext}"
        filepath = os.path.join(UPLOAD_FOLDER, safe_name)
        # Remove old resume file if exists
        conn = db_connect()
        c = conn.cursor()
        c.execute("SELECT resume_filename FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if row and row["resume_filename"]:
            old_path = os.path.join(UPLOAD_FOLDER, row["resume_filename"])
            if os.path.exists(old_path):
                os.remove(old_path)
        # Save new file
        file.save(filepath)
        now = datetime.utcnow().isoformat()
        c.execute(
            "UPDATE users SET resume_filename = ?, resume_original_name = ?, resume_uploaded_at = ? WHERE id = ?",
            (safe_name, file.filename, now, user_id),
        )
        conn.commit()
        conn.close()
        return jsonify({
            "ok": True,
            "resume": {"filename": safe_name, "original_name": file.filename, "uploaded_at": now},
        }), 200
    except Exception as e:
        return jsonify({"message": f"Upload failed: {str(e)}"}), 500


@app.route('/api/candidate/resume', methods=['GET'])
def get_resume_info():
    user_id, err = require_role({"candidate"})
    if err:
        return err
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute("SELECT resume_filename, resume_original_name, resume_uploaded_at FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        conn.close()
        if not row or not row["resume_filename"]:
            return jsonify({"resume": None}), 200
        return jsonify({"resume": {
            "filename": row["resume_filename"],
            "original_name": row["resume_original_name"],
            "uploaded_at": row["resume_uploaded_at"],
        }}), 200
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/api/candidate/resume/download', methods=['GET'])
def download_resume():
    user_id, err = require_role({"candidate"})
    if err:
        return err
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute("SELECT resume_filename, resume_original_name FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        conn.close()
        if not row or not row["resume_filename"]:
            return jsonify({"message": "No resume found"}), 404
        filepath = os.path.join(UPLOAD_FOLDER, row["resume_filename"])
        if not os.path.exists(filepath):
            return jsonify({"message": "Resume file missing"}), 404
        from flask import send_file
        return send_file(filepath, as_attachment=True, download_name=row["resume_original_name"])
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/api/candidate/resume', methods=['DELETE'])
def delete_resume():
    user_id, err = require_role({"candidate"})
    if err:
        return err
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute("SELECT resume_filename FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if row and row["resume_filename"]:
            old_path = os.path.join(UPLOAD_FOLDER, row["resume_filename"])
            if os.path.exists(old_path):
                os.remove(old_path)
        c.execute("UPDATE users SET resume_filename = NULL, resume_original_name = NULL, resume_uploaded_at = NULL WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        return jsonify({"ok": True}), 200
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/interview/stream', methods=['GET', 'POST'])
def interview_stream_placeholder():
    # Placeholder: Planning.md specifies WebSocket; implement with flask-socketio later.
    return jsonify({
        "message": "WebSocket streaming not implemented in this basic backend."
    }), 501

if __name__ == '__main__':
    port = int(os.getenv("PORT", "5000"))
    print("Starting Face Authentication Server...")
    print(f"Server running on http://0.0.0.0:{port}")
    app.run(debug=not is_production, host='0.0.0.0', port=port)
