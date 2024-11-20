from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = '5fde69b0a71bf95db99942fafd7745a2c31143147bd8f1a8'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://Akaranja:Alfredkaranja1@localhost/is_project'

    db.init_app(app)  # Initialize the database
    login_manager.init_app(app)  # Initialize the login manager

    # Import and register blueprints
    from app.routes import main  # Replace with the correct path to your blueprint

    app.register_blueprint(main)

    return app