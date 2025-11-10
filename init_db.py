from app import app, db
import models
import models_extensions

with app.app_context():
    # Drop all tables first to ensure clean slate
    db.drop_all()
    # Create all tables
    db.create_all()
    print("Database tables recreated successfully.")
