# ==========================================
# MILESTONE 0: CONFIGURATION SETUP
# ==========================================

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'emp-secret-key-mad1-academic-2026')
    
    # Store database in the instance/ directory as required
    INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URI', 
        f"sqlite:///{os.path.join(INSTANCE_DIR, 'emp.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

