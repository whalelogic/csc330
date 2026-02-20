from flask import Flask
import os
from dotenv import load_dotenv
from app.city import City

load_dotenv('.flaskenv')

city_data = {}

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'csc330-spring-2026'
    app.config['WTF_CSRF_ENABLED'] = True
    
    # Init database
    from app import database
    with app.app_context():
        database.init_db()
    
    app.teardown_appcontext(database.close_connection)
    
    # Import routes
    from app import routes
    routes.init_app(app)
    
    return app
