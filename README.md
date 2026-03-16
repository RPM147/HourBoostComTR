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

⚙️ Installation

1. Clone the repository
2. Create a virtual environment
3. Install dependencies
4. Set up environment variables
5. Fill in .env with your own values:
6. Run




