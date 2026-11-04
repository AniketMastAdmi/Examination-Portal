# ==========================================
# MILESTONE 1: DATABASE MODELS AND SCHEMA
# ==========================================

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# ----------------------------------------------------
# Association Table: Examination <-> Assigned Examiners
# ----------------------------------------------------
examination_examiners = db.Table(
    'examination_examiners',
    db.Column('examination_id', db.Integer, db.ForeignKey('examinations.id', ondelete='CASCADE'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
)


class User(UserMixin, db.Model):
    """
    Central User model for all three roles: Admin, Examiner, Student.
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Role: 'admin', 'examiner', 'student'
    role = db.Column(db.String(20), nullable=False)
    
    # Account status: 'active', 'inactive', 'pending'
    status = db.Column(db.String(20), default='active', nullable=False)
    
    # Student specific optional fields
    student_id = db.Column(db.String(50), nullable=True, index=True)
    department = db.Column(db.String(100), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    examiner_profile = db.relationship('ExaminerProfile', backref='user', uselist=False, cascade='all, delete-orphan')
    slots = db.relationship('ExaminationSlot', backref='examiner', lazy=True)
    bookings = db.relationship('Booking', backref='student', foreign_keys='Booking.student_id', lazy=True)
    evaluations_given = db.relationship('Evaluation', backref='examiner', lazy=True)

    def set_password(self, password):
        """Hash and store the password securely."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify password against the stored hash."""
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        """Flask-Login check: Only active accounts can log in."""
        return self.status == 'active'

    def __repr__(self):
        return f'<User {self.email} ({self.role})>'


class ExaminerProfile(db.Model):
    """
    Detailed profile information for users with the 'examiner' role.
    """
    __tablename__ = 'examiner_profiles'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False)
    department = db.Column(db.String(100), nullable=False)
    contact_details = db.Column(db.String(150), nullable=False)
    
    # Approval status: 'pending', 'approved', 'rejected'
    approval_status = db.Column(db.String(20), default='pending', nullable=False)

    def __repr__(self):
        return f'<ExaminerProfile UserID={self.user_id} Status={self.approval_status}>'


class Course(db.Model):
    """
    Academic course details.
    """
    __tablename__ = 'courses'

    id = db.Column(db.Integer, primary_key=True)
    course_code = db.Column(db.String(30), unique=True, nullable=False, index=True)
    course_name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Status: 'active', 'inactive'
    status = db.Column(db.String(20), default='active', nullable=False)

    # Relationships
    examinations = db.relationship('Examination', backref='course', cascade='all, delete-orphan', lazy=True)

    def __repr__(self):
        return f'<Course {self.course_code}: {self.course_name}>'


class Examination(db.Model):
    """
    Specific examination associated with a course.
    """
    __tablename__ = 'examinations'

    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    exam_type = db.Column(db.String(50), nullable=False, default='Viva Voce')
    duration = db.Column(db.Integer, nullable=False)  # in minutes
    max_marks = db.Column(db.Float, nullable=False, default=100.0)
    description = db.Column(db.Text, nullable=True)

    # Timeline Management
    slot_creation_start = db.Column(db.DateTime, nullable=False)
    slot_creation_end = db.Column(db.DateTime, nullable=False)
    booking_start = db.Column(db.DateTime, nullable=False)
    booking_end = db.Column(db.DateTime, nullable=False)

    # Status: 'draft', 'published', 'completed', 'cancelled'
    status = db.Column(db.String(20), default='draft', nullable=False)

    # Relationships
    rubrics = db.relationship('ExaminationRubric', backref='examination', cascade='all, delete-orphan', lazy=True)
    slots = db.relationship('ExaminationSlot', backref='examination', cascade='all, delete-orphan', lazy=True)
    assigned_examiners = db.relationship(
        'User',
        secondary=examination_examiners,
        backref=db.backref('assigned_examinations', lazy='dynamic')
    )

    def is_slot_creation_open(self):
        """Check if examiner slot creation window is currently open."""
        now = datetime.now()
        return self.slot_creation_start <= now <= self.slot_creation_end

    def is_booking_open(self):
        """Check if student booking window is currently open."""
        now = datetime.now()
        return self.status == 'published' and (self.booking_start <= now <= self.booking_end)

    def can_cancel_booking(self):
        """Check if students can still cancel their booking (before booking deadline)."""
        now = datetime.now()
        return now <= self.booking_end

    @property
    def total_rubric_marks(self):
        """Calculate sum of maximum marks configured across all criteria."""
        return sum(r.max_marks for r in self.rubrics)

    def __repr__(self):
        return f'<Examination {self.name} (CourseID={self.course_id})>'


class ExaminationRubric(db.Model):
    """
    Evaluation rubric criteria for an examination.
    """
    __tablename__ = 'examination_rubrics'

    id = db.Column(db.Integer, primary_key=True)
    examination_id = db.Column(db.Integer, db.ForeignKey('examinations.id', ondelete='CASCADE'), nullable=False)
    criterion_name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    max_marks = db.Column(db.Float, nullable=False)
    weightage = db.Column(db.Float, default=1.0, nullable=False)

    # Relationships
    scores = db.relationship('EvaluationScore', backref='rubric', cascade='all, delete-orphan', lazy=True)

    def __repr__(self):
        return f'<Rubric {self.criterion_name} ({self.max_marks} marks)>'


class ExaminationSlot(db.Model):
    """
    Specific time slot created by an assigned examiner for an examination.
    """
    __tablename__ = 'examination_slots'

    id = db.Column(db.Integer, primary_key=True)
    examination_id = db.Column(db.Integer, db.ForeignKey('examinations.id', ondelete='CASCADE'), nullable=False)
    examiner_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    
    max_capacity = db.Column(db.Integer, nullable=False, default=1)
    booked_count = db.Column(db.Integer, nullable=False, default=0)
    
    # Status: 'available', 'full', 'cancelled'
    status = db.Column(db.String(20), default='available', nullable=False)

    # Relationships
    bookings = db.relationship('Booking', backref='slot', cascade='all, delete-orphan', lazy=True)

    @property
    def available_seats(self):
        """Calculate remaining seats reliably."""
        return max(0, self.max_capacity - self.booked_count)

    def update_status(self):
        """Synchronize slot status based on capacity and current bookings."""
        if self.booked_count >= self.max_capacity:
            self.status = 'full'
        else:
            self.status = 'available'

    def __repr__(self):
        return f'<Slot ID={self.id} Date={self.date} Time={self.start_time}-{self.end_time}>'


class Booking(db.Model):
    """
    Student examination slot booking record.
    """
    __tablename__ = 'bookings'

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    slot_id = db.Column(db.Integer, db.ForeignKey('examination_slots.id', ondelete='CASCADE'), nullable=False)
    booking_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Status: 'confirmed', 'cancelled', 'completed'
    status = db.Column(db.String(20), default='confirmed', nullable=False)
    cancellation_timestamp = db.Column(db.DateTime, nullable=True)

    # Relationships
    evaluation = db.relationship('Evaluation', backref='booking', uselist=False, cascade='all, delete-orphan')
    history = db.relationship('BookingHistory', backref='booking', cascade='all, delete-orphan', lazy=True)

    def __repr__(self):
        return f'<Booking ID={self.id} StudentID={self.student_id} SlotID={self.slot_id} Status={self.status}>'


class Evaluation(db.Model):
    """
    Evaluation and marks awarded by the examiner for a completed booking.
    """
    __tablename__ = 'evaluations'

    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('bookings.id', ondelete='CASCADE'), unique=True, nullable=False)
    examiner_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    total_marks = db.Column(db.Float, nullable=False, default=0.0)
    remarks = db.Column(db.Text, nullable=True)
    evaluated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Result visibility to students
    is_published = db.Column(db.Boolean, default=False, nullable=False)

    # Relationships
    criterion_scores = db.relationship('EvaluationScore', backref='evaluation', cascade='all, delete-orphan', lazy=True)

    def __repr__(self):
        return f'<Evaluation ID={self.id} BookingID={self.booking_id} Marks={self.total_marks}>'


class EvaluationScore(db.Model):
    """
    Detailed marks awarded for each individual rubric criterion.
    """
    __tablename__ = 'evaluation_scores'

    id = db.Column(db.Integer, primary_key=True)
    evaluation_id = db.Column(db.Integer, db.ForeignKey('evaluations.id', ondelete='CASCADE'), nullable=False)
    rubric_id = db.Column(db.Integer, db.ForeignKey('examination_rubrics.id', ondelete='CASCADE'), nullable=False)
    
    marks_obtained = db.Column(db.Float, nullable=False)
    feedback = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<EvaluationScore RubricID={self.rubric_id} Marks={self.marks_obtained}>'


class BookingHistory(db.Model):
    """
    Audit log preserving booking, rescheduling, and examiner reassignment events.
    """
    __tablename__ = 'booking_history'

    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('bookings.id', ondelete='CASCADE'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # 'created', 'rescheduled', 'reassigned', 'cancelled'
    previous_slot_id = db.Column(db.Integer, nullable=True)
    new_slot_id = db.Column(db.Integer, nullable=True)
    changed_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f'<BookingHistory Action={self.action} BookingID={self.booking_id} at {self.timestamp}>'

