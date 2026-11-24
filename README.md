⚡ HourBoost

An automated Steam game hour boosting service. Connect multiple Steam accounts, select your games, and boost your hours automatically — 24/7.

🚀 Features

- 🎮 Multiple Steam account support
- ⏱️ Timed boost — set a timer and stop automatically
- 📊 Per-game boost statistics
- 🔒 Email verification system
- 🔑 Password reset & email change
- 💳 Shopier payment integration
- 🛡️ Brute force protection
- 📱 Active session management (with IP and device info)
- 🌐 Bilingual support (Turkish & English)
- 👤 Admin panel (user management, payment approval, announcements)
- 🔄 Auto reconnect on connection drop

🛡️ Security

1. Steam passwords are encrypted with Fernet symmetric encryption
2. JWT token blacklist system
3. IP and user-based brute force protection (5 failed attempts = 5 min lockout)
4. Email verification required before adding Steam accounts
5. CSRF protection on all state-changing endpoints
6. SQL Injection protection via SQLAlchemy ORM
7. Shopier webhook signature verification
8. Duplicate payment prevention via transaction ID check


📋 Requirements

- Python 3.10+
- pip
- Node.js and npm for the Steam worker

⚙️ Installation

1. Clone the repository and activate a Python virtual environment.
2. Run `python -m pip install -r requirements.txt` and `npm ci`.
3. Copy `.env.example` to `.env` and set your own values. Do not commit this file.
4. Initialize or audit SQLite as described in [the migration guide](migrations/README.md).
   The database URL must point to an existing, initialized SQLite database via an absolute path.
5. For local development, run `python app.py` on a trusted network.

The application runtime is SQLite with a single worker. The PostgreSQL
migrations and WAL utilities do not enable PostgreSQL in production. The WAL
utilities are building blocks, not a complete backup or recovery installation.

Candidate PostgreSQL backups are operator-triggered. Capture, transfer and a
successful isolated restore are separate outcomes: downloading a file does not
verify it. Retention keeps the three latest restore-verified native generations
and preserves the WAL required by the retained backups. Periodic Windows pulls
and notifications are disabled; backup operations do not need a background
connection from the operator's PC. This policy does not back up live SQLite.
Host-specific operators, recovery material and backup receipts are not part
of this public distribution.

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)


