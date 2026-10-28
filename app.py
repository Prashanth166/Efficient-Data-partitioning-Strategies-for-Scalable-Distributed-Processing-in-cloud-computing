import os
import io
import hashlib
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-only-change-this-before-deploying")
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB starter limit
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///partitioning.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

STORAGE_DIR = os.path.join(app.instance_path, "encrypted_parts")
os.makedirs(STORAGE_DIR, exist_ok=True)
KEY_PATH = os.path.join(app.instance_path, "fernet.key")

def get_cipher():
    env_key = os.getenv("ENCRYPTION_KEY")
    if env_key:
        return Fernet(env_key.encode())
    # Local-development convenience. A persistent key file is created once.
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, "wb") as key_file:
            key_file.write(Fernet.generate_key())
    with open(KEY_PATH, "rb") as key_file:
        return Fernet(key_file.read().strip())

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class StoredFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    partition_count = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner = db.relationship("User", backref="stored_files")
    partitions = db.relationship("Partition", backref="stored_file", cascade="all, delete-orphan")

class Partition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("stored_file.id"), nullable=False)
    partition_index = db.Column(db.Integer, nullable=False)
    digest = db.Column(db.String(64), nullable=False)
    encrypted_path = db.Column(db.String(500), nullable=False)
    encrypted_size = db.Column(db.Integer, nullable=False)

class KeyRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("stored_file.id"), nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(20), default="pending", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    stored_file = db.relationship("StoredFile", backref="key_requests")
    requester = db.relationship("User", backref="key_requests")

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.context_processor
def inject_counts():
    if current_user.is_authenticated:
        return {"nav_file_count": StoredFile.query.filter_by(owner_id=current_user.id).count()}
    return {"nav_file_count": 0}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3:
            flash("Username must contain at least 3 characters.", "error")
        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
        elif User.query.filter_by(username=username).first():
            flash("That username is already taken.", "error")
        else:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("Account created successfully.", "success")
            return redirect(url_for("dashboard"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("admin_requests" if user.is_admin else "dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have logged out.", "success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    files = StoredFile.query.filter_by(owner_id=current_user.id).order_by(StoredFile.created_at.desc()).all()
    total_bytes = sum(f.size_bytes for f in files)
    total_parts = sum(f.partition_count for f in files)
    pending = KeyRequest.query.filter_by(requester_id=current_user.id, status="pending").count()
    return render_template("dashboard.html", files=files, total_bytes=total_bytes,
                           total_parts=total_parts, pending=pending)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        uploaded = request.files.get("file")
        try:
            chunk_size = int(request.form.get("chunk_size", "65536"))
        except ValueError:
            chunk_size = 65536
        if not uploaded or not uploaded.filename:
            flash("Choose a file to upload.", "error")
            return redirect(url_for("upload"))
        if chunk_size < 4096 or chunk_size > 1048576:
            flash("Chunk size must be between 4 KB and 1 MB.", "error")
            return redirect(url_for("upload"))
        original_name = secure_filename(uploaded.filename)
        if not original_name:
            flash("Invalid filename.", "error")
            return redirect(url_for("upload"))
        data = uploaded.read()
        if not data:
            flash("Empty files are not supported in this starter version.", "error")
            return redirect(url_for("upload"))
        cipher = get_cipher()
        pieces = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        record = StoredFile(owner_id=current_user.id, original_name=original_name,
                            size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                            partition_count=len(pieces))
        db.session.add(record)
        db.session.flush()
        try:
            for idx, piece in enumerate(pieces):
                # Hash-based partition assignment is deterministic; modulo maps each chunk to a partition slot.
                slot = int(hashlib.sha256(f"{record.id}:{idx}".encode()).hexdigest(), 16) % len(pieces)
                encrypted = cipher.encrypt(piece)
                path = os.path.join(STORAGE_DIR, f"file_{record.id}_part_{idx}.bin")
                with open(path, "wb") as out:
                    out.write(encrypted)
                db.session.add(Partition(file_id=record.id, partition_index=slot,
                                         digest=hashlib.sha256(piece).hexdigest(),
                                         encrypted_path=path, encrypted_size=len(encrypted)))
            db.session.commit()
        except Exception:
            db.session.rollback()
            for idx in range(len(pieces)):
                path = os.path.join(STORAGE_DIR, f"file_{record.id}_part_{idx}.bin")
                if os.path.exists(path):
                    os.remove(path)
            raise
        flash(f"Uploaded and encrypted {original_name} into {len(pieces)} chunks.", "success")
        return redirect(url_for("file_detail", file_id=record.id))
    return render_template("upload.html")

@app.route("/files/<int:file_id>")
@login_required
def file_detail(file_id):
    record = db.get_or_404(StoredFile, file_id)
    if record.owner_id != current_user.id and not current_user.is_admin:
        abort(403)
    requests_for_file = KeyRequest.query.filter_by(file_id=record.id).order_by(KeyRequest.created_at.desc()).all()
    return render_template("file_detail.html", record=record, requests_for_file=requests_for_file)

@app.route("/search")
@login_required
def search():
    query = request.args.get("q", "").strip()
    results = []
    if query:
        results = StoredFile.query.filter(StoredFile.owner_id == current_user.id,
                                          StoredFile.original_name.ilike(f"%{query}%")).order_by(
                                              StoredFile.created_at.desc()).all()
    return render_template("search.html", query=query, results=results)

@app.route("/files/<int:file_id>/request-key", methods=["POST"])
@login_required
def request_key(file_id):
    record = db.get_or_404(StoredFile, file_id)
    if record.owner_id != current_user.id:
        abort(403)
    existing = KeyRequest.query.filter_by(file_id=file_id, requester_id=current_user.id,
                                          status="pending").first()
    if existing:
        flash("A key request for this file is already pending.", "error")
    else:
        db.session.add(KeyRequest(file_id=file_id, requester_id=current_user.id))
        db.session.commit()
        flash("Decryption access request sent to the administrator.", "success")
    return redirect(url_for("file_detail", file_id=file_id))

@app.route("/admin/requests")
@login_required
@admin_required
def admin_requests():
    requests_list = KeyRequest.query.order_by(KeyRequest.created_at.desc()).all()
    return render_template("admin_requests.html", requests_list=requests_list)

@app.route("/admin/requests/<int:request_id>/<decision>", methods=["POST"])
@login_required
@admin_required
def review_request(request_id, decision):
    key_request = db.get_or_404(KeyRequest, request_id)
    if decision not in ("approve", "reject"):
        abort(400)
    key_request.status = "approved" if decision == "approve" else "rejected"
    key_request.reviewed_at = datetime.utcnow()
    db.session.commit()
    flash(f"Request {key_request.status}.", "success")
    return redirect(url_for("admin_requests"))

@app.route("/files/<int:file_id>/download")
@login_required
def download(file_id):
    record = db.get_or_404(StoredFile, file_id)
    if record.owner_id != current_user.id and not current_user.is_admin:
        abort(403)
    approved = KeyRequest.query.filter_by(file_id=file_id, requester_id=current_user.id,
                                          status="approved").first()
    if not current_user.is_admin and not approved:
        flash("Request decryption access and wait for administrator approval before downloading.", "error")
        return redirect(url_for("file_detail", file_id=file_id))
    try:
        cipher = get_cipher()
        output = bytearray()
        for part in sorted(record.partitions, key=lambda p: p.id):
            with open(part.encrypted_path, "rb") as encrypted_file:
                output.extend(cipher.decrypt(encrypted_file.read()))
        content = bytes(output)
        if hashlib.sha256(content).hexdigest() != record.sha256:
            raise ValueError("Integrity check failed")
    except Exception:
        app.logger.exception("Unable to reconstruct encrypted file")
        flash("Could not decrypt or verify this file. Check the encryption key and stored chunks.", "error")
        return redirect(url_for("file_detail", file_id=file_id))
    return send_file(io.BytesIO(content), as_attachment=True, download_name=record.original_name)

@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403

@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The requested page or record was not found."), 404

@app.errorhandler(413)
def too_large(_error):
    return render_template("error.html", code=413, message="File too large. The current upload limit is 20 MB."), 413

with app.app_context():
    db.create_all()
    # Set these environment variables before first run to create an administrator.
    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")
    if admin_username and admin_password and not User.query.filter_by(username=admin_username).first():
        admin = User(username=admin_username, is_admin=True)
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "1") == "1")
