"""Database configuration notes.

The Flask application configures SQLAlchemy in app.py.
Local default: SQLite database at instance/partitioning.db.
For MySQL, set DATABASE_URL in .env, for example:
mysql+pymysql://partition_user:YOUR_PASSWORD@127.0.0.1/partitioning_db?charset=utf8mb4

Create the MySQL database and user before switching DATABASE_URL.
"""
