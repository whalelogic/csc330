# Flask Web Application Development Guide

A comprehensive reference for building web applications with Flask, SQLite, Jinja2 templates, and modern deployment practices.

## 📚 Table of Contents

1. [Flask Basics & Project Setup](#flask-basics)
2. [Flask CLI Commands](./documents/flask-cli.md)
3. [Jinja2 Template Syntax](./documents/jinja-templates.md)
4. [SQLite Database Integration](./documents/sqlite-integration.md)
5. [Redis Caching](./documents/redis-cache.md)
6. [User Authentication](./documents/authentication.md)
7. [Subscription & Notifications](./documents/subscriptions-notifications.md)
8. [Google Cloud Deployment](./documents/gcloud-deployment.md)
9. [API Development](./documents/api-development.md)

---

## Flask Basics

### Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Flask and common dependencies
pip install flask flask-sqlalchemy flask-login redis flask-mail
```

### Minimal Flask Application

```python
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/data', methods=['GET', 'POST'])
def api_data():
    if request.method == 'POST':
        data = request.get_json()
        return jsonify({'status': 'success', 'received': data})
    return jsonify({'message': 'Hello from API'})

if __name__ == '__main__':
    app.run(debug=True)
```

### Project Structure

```
flask-app/
├── app.py                 # Main application file
├── config.py              # Configuration settings
├── models.py              # Database models
├── requirements.txt       # Python dependencies
├── static/
│   ├── css/
│   ├── js/
│   └── images/
├── templates/
│   ├── base.html
│   ├── index.html
│   └── components/
└── instance/
    └── database.db        # SQLite database
```

---

## Quick Reference Links

- **[Flask CLI Commands & Usage](./documents/flask-cli.md)** - Complete guide to Flask command-line interface
- **[Jinja2 Templates](./documents/jinja-templates.md)** - Template syntax, filters, and dynamic content
- **[SQLite Integration](./documents/sqlite-integration.md)** - Database setup, queries, and Python functions
- **[Redis Caching](./documents/redis-cache.md)** - In-memory caching strategies
- **[User Authentication](./documents/authentication.md)** - Login, sessions, and password management
- **[Subscriptions & Notifications](./documents/subscriptions-notifications.md)** - Email notifications and webhooks
- **[Google Cloud Deployment](./documents/gcloud-deployment.md)** - VM setup and application management
- **[API Development](./documents/api-development.md)** - RESTful API design and implementation

---

## Essential Flask Patterns

### Configuration Management

```python
# config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///instance/app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_URL = 'redis://localhost:6379/0'
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
```

### Error Handling

```python
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500
```

### Request Context

```python
from flask import request, session, g

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])
```

---

## Contributing

This guide is intended for CSC 330 students. Feel free to add examples and improve documentation.

## License

Educational use only - CSC 330 Spring 2026
