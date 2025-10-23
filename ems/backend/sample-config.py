import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-super-secret-key'
    
    # --- SQLAlchemy Database Configuration ---
    
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://USERNAME:PASSWORD@localhost/aether_ems_db'
    # IMP: Replace username and password with your own creds
    SQLALCHEMY_TRACK_MODIFICATIONS = False
