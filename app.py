import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()

# create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET") or "dev-secret-key-change-in-production"
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# configure the database
database_url = os.environ.get("mysql://root:AhYjFLpdQkFGThMLLOcDoNEhWpdgYeEt@mysql.railway.internal:3306/railway")
if database_url:
    # Using the DATABASE_URL environment variable provided by the hosting service
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    logging.info("Using DATABASE_URL from environment.")
else:
    # Fallback to local MySQL for development
    app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://webuser:StrongPassword123@localhost/project_mgm"

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# initialize extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

# Import and register routes
import routes

# Create tables on startup in production
if os.environ.get("DATABASE_URL"):
    with app.app_context():
        # NOTE: This should point to your models file name, which I've updated to 'models.py' based on the trace.
        import models as models_module
        import models_extensions as models_extensions_module
        db.create_all()
        print("Database tables created/updated in production.")
