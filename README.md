# SecureShard — Efficient Data Partitioning for Scalable Distributed Processing

A beginner-friendly Flask project demonstrating user authentication, hash-based chunk assignment, encrypted file storage, file search, administrator-reviewed decryption requests, and integrity-verified downloads.

## Requirements
- Python 3.12 recommended
- VS Code + Python extension
- SQLite for the first local run (built in)
- Optional MySQL Server for persistent MySQL storage

## Run locally (Windows PowerShell)
1. Open this folder in VS Code.
2. Create a virtual environment: `py -3.12 -m venv venv`
3. Activate it: `.\venv\Scripts\Activate.ps1`
4. Install dependencies: `python -m pip install -r requirements.txt`
5. Copy `.env.example` to `.env` and change the secret/admin password.
6. Run: `python app.py`
7. Visit `http://127.0.0.1:5000`.

If `py -3.12` is not available, install Python 3.12 or use `python -m venv venv`.

## MySQL option
1. In MySQL, create a database and a dedicated application user, granting it access only to this database.
2. Copy `.env.example` to `.env`.
3. Set `DATABASE_URL=mysql+pymysql://partition_user:URL_ENCODED_PASSWORD@127.0.0.1/partitioning_db?charset=utf8mb4`.
4. Restart the app. Tables are created automatically on startup for this educational prototype.

Do not put real credentials into source control. URL-encode special characters in database passwords.

## Administrator
Set `ADMIN_USERNAME` and `ADMIN_PASSWORD` in `.env` before the first app run. The app creates that admin account if it does not already exist. Use a strong password. If you have already run the app without these variables, set them and restart; the account will be created if the username is unused.

## Encryption key
Local development creates `instance/fernet.key` once. Keep it safe and backed up; if you lose it, existing encrypted chunks cannot be decrypted. Never commit `instance/` or `.env`. For deployment, set a persistent `ENCRYPTION_KEY` environment variable generated with:
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`

## What partitioning means here
Files are split into chunks according to the chosen chunk size. Each chunk is encrypted independently. A deterministic hash maps each chunk to a partition slot, and the metadata and encrypted chunks are stored locally. This is a learning prototype, not a distributed cluster: chunks are not yet sent to separate physical/cloud storage nodes.

## Security and production notes
This is a teaching starter, not production-hardened. Before real deployment, add CSRF protection to every form (Flask-WTF is installed), rate limiting, secure cookie settings, audit logs, strict admin provisioning, managed key storage, migrations, backup/recovery, and cloud object storage. Use HTTPS. Do not use Flask's development server in production.
