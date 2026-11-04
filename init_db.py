# ==========================================
# MILESTONE 1: DATABASE INITIALIZATION SCRIPT
# ==========================================

import os
from flask import Flask
from config import Config
from models import db, User, ExaminerProfile, Course

def initialize_database():
    """
    Creates database tables in instance/emp.db and sets up the default Admin account.
    Repeatable: safely checks for existing records to prevent duplicates.
    """
    app = Flask(__name__)
    app.config.from_object(Config)

    # Ensure the instance directory exists
    os.makedirs(app.config['INSTANCE_DIR'], exist_ok=True)
    db.init_app(app)

    with app.app_context():
        # Create all database tables
        db.create_all()
        print("-> Database schema verified / created successfully.")

        # Check and create default Admin account
        admin_email = "admin@emp.gov"
        existing_admin = User.query.filter_by(email=admin_email).first()

        if not existing_admin:
            admin = User(
                full_name="EMP Administrator",
                email=admin_email,
                role="admin",
                status="active"
            )
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()
            print(f"-> Default Admin created: {admin_email} / admin123")
        else:
            print(f"-> Admin account already exists: {admin_email}")

        # Optional: Seed sample course if none exists for quick viva demonstration
        if Course.query.count() == 0:
            sample_course = Course(
                course_code="MAD101",
                course_name="Modern Application Development I",
                description="Core academic course focusing on Web Application Development using Python, Flask, and SQLite.",
                status="active"
            )
            db.session.add(sample_course)
            db.session.commit()
            print("-> Sample Course 'MAD101' created.")

        print("-> Database initialization complete!")

if __name__ == '__main__':
    initialize_database()

