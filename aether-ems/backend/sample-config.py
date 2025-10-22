import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-super-secret-key'
    
    # --- SQLAlchemy Database Configuration ---
    # Add your own credentials here
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://USERNAME:PASSWORD@localhost/aether_ems_db'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False