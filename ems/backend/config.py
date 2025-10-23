import os

class Config:
    # secret key for session management
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-super-secret-key'
    
    # connection string for db
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://root:$8Herokite@localhost/aether_ems_db'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False