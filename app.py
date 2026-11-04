# ==========================================
# EMP 0.2 — EXAMINATION MANAGEMENT PORTAL
# APP LAYER (ROUTES, CONTROLLERS, AUTH, AMV)
# ==========================================

import os
from datetime import datetime, time
from functools import wraps

from flask import (
    Flask, render_template, redirect, url_for, 
    flash, request, abort
)
from flask_login import (
    LoginManager, login_user, logout_user, 
    login_required, current_user
)

from config import Config
from models import (
    db, User, ExaminerProfile, Course, Examination, 
    ExaminationRubric, ExaminationSlot, Booking, 
    Evaluation, EvaluationScore, BookingHistory
)

# --------------------------------------------------
# APPLICATION INITIALIZATION (AMV: App Layer)
# --------------------------------------------------
app = Flask(__name__, template_folder='views', static_folder='static')
app.config.from_object(Config)

# Ensure instance folder exists
os.makedirs(app.config['INSTANCE_DIR'], exist_ok=True)

# Initialize Database ORM and Login Manager
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id):
    """Load user by primary key for session management."""
    return db.session.get(User, int(user_id))


# --------------------------------------------------
# ROLE-BASED ACCESS CONTROL DECORATORS
# --------------------------------------------------
def role_required(*allowed_roles):
    """
    Decorator to enforce role-based access control and account status on routes.
    """
    def decorator(fn):
        @wraps(fn)
        @login_required
        def decorated_view(*args, **kwargs):
            if current_user.role not in allowed_roles:
                flash("Access denied: You do not have permission to access this resource.", "danger")
                return redirect(url_for('index'))
            
            # Additional check: Examiner must be approved
            if current_user.role == 'examiner':
                if not current_user.examiner_profile or current_user.examiner_profile.approval_status != 'approved':
                    flash("Your examiner account is awaiting administrator approval.", "warning")
                    return redirect(url_for('index'))

            # Check account active status
            if current_user.status != 'active':
                flash("Your account is currently inactive. Please contact support.", "danger")
                logout_user()
                return redirect(url_for('login'))

            return fn(*args, **kwargs)
        return decorated_view
    return decorator


# ==========================================
# MILESTONE 2: AUTHENTICATION AND ROLE ACCESS
# ==========================================

@app.route('/')
def index():
    """
    Central root router: directs authenticated users to their role dashboard
    or unauthenticated guests to login.
    """
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'examiner':
        if current_user.examiner_profile and current_user.examiner_profile.approval_status == 'approved':
            return redirect(url_for('examiner_dashboard'))
        else:
            flash("Your examiner account is awaiting administrator approval. You will gain full access once approved.", "info")
            return render_template('login.html')
    elif current_user.role == 'student':
        return redirect(url_for('student_dashboard'))
    
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Common login page for all portal roles."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            flash("Invalid email address or password.", "danger")
            return render_template('login.html')

        # Check approval status for examiners
        if user.role == 'examiner':
            if user.examiner_profile and user.examiner_profile.approval_status == 'pending':
                flash("Your examiner registration is pending administrator approval. Please wait for authorization.", "warning")
                return render_template('login.html')
            elif user.examiner_profile and user.examiner_profile.approval_status == 'rejected':
                flash("Your examiner application has been declined by the administrator.", "danger")
                return render_template('login.html')

        if user.status != 'active':
            flash("Your account is deactivated. Please contact the administrator.", "danger")
            return render_template('login.html')

        login_user(user)
        flash(f"Welcome back, {user.full_name}!", "success")
        return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Logs out user and clears the session."""
    logout_user()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for('login'))


@app.route('/register/student', methods=['GET', 'POST'])
def student_register():
    """Student registration route."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        student_id = request.form.get('student_id', '').strip()
        department = request.form.get('department', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Server-side validation
        if not full_name or not email or not password or not student_id:
            flash("Please fill in all required fields.", "danger")
            return render_template('student_register.html')

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('student_register.html')

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "warning")
            return render_template('student_register.html')

        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists. Please log in.", "warning")
            return render_template('student_register.html')

        # Create new student account
        student = User(
            full_name=full_name,
            email=email,
            role='student',
            status='active',
            student_id=student_id,
            department=department
        )
        student.set_password(password)
        db.session.add(student)
        db.session.commit()

        flash("Student account created successfully! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('student_register.html')


@app.route('/register/examiner', methods=['GET', 'POST'])
def examiner_register():
    """Examiner registration route (requires Admin approval)."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        department = request.form.get('department', '').strip()
        contact_details = request.form.get('contact_details', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not full_name or not email or not password or not department:
            flash("Please complete all required fields.", "danger")
            return render_template('examiner_register.html')

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('examiner_register.html')

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "warning")
            return render_template('examiner_register.html')

        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists.", "warning")
            return render_template('examiner_register.html')

        # Examiner starts as 'pending' until approved by Admin
        examiner = User(
            full_name=full_name,
            email=email,
            role='examiner',
            status='pending',
            department=department
        )
        examiner.set_password(password)
        db.session.add(examiner)
        db.session.flush()

        profile = ExaminerProfile(
            user_id=examiner.id,
            department=department,
            contact_details=contact_details,
            approval_status='pending'
        )
        db.session.add(profile)
        db.session.commit()

        flash("Examiner application registered! Your account is pending administrator approval.", "info")
        return redirect(url_for('login'))

    return render_template('examiner_register.html')


# ==========================================
# MILESTONE 3: ADMIN DASHBOARD AND MANAGEMENT
# ==========================================

@app.route('/admin/dashboard')
@role_required('admin')
def admin_dashboard():
    """Administrator main dashboard with real-time database-derived statistics."""
    stats = {
        'total_courses': Course.query.count(),
        'total_examinations': Examination.query.count(),
        'total_examiners': User.query.filter_by(role='examiner').count(),
        'total_students': User.query.filter_by(role='student').count(),
        'total_slots': ExaminationSlot.query.count(),
        'total_bookings': Booking.query.count(),
        'pending_examiners': ExaminerProfile.query.filter_by(approval_status='pending').count()
    }
    recent_exams = Examination.query.order_by(Examination.id.desc()).limit(5).all()
    recent_bookings = Booking.query.order_by(Booking.id.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', stats=stats, recent_exams=recent_exams, recent_bookings=recent_bookings)


# ---------------- COURSE MANAGEMENT ----------------
@app.route('/admin/courses')
@role_required('admin')
def admin_courses():
    """List all courses with examination counts and management controls."""
    courses = Course.query.order_by(Course.id.desc()).all()
    return render_template('admin/courses.html', courses=courses)


@app.route('/admin/courses/create', methods=['POST'])
@role_required('admin')
def admin_courses_create():
    """Create a new academic course."""
    course_code = request.form.get('course_code', '').strip().upper()
    course_name = request.form.get('course_name', '').strip()
    description = request.form.get('description', '').strip()
    status = request.form.get('status', 'active')

    if not course_code or not course_name:
        flash("Course code and course name are mandatory.", "danger")
        return redirect(url_for('admin_courses'))

    if Course.query.filter_by(course_code=course_code).first():
        flash(f"A course with code '{course_code}' already exists.", "warning")
        return redirect(url_for('admin_courses'))

    course = Course(
        course_code=course_code,
        course_name=course_name,
        description=description,
        status=status
    )
    db.session.add(course)
    db.session.commit()
    flash(f"Course '{course_code}: {course_name}' created successfully.", "success")
    return redirect(url_for('admin_courses'))


@app.route('/admin/courses/<int:course_id>/edit', methods=['POST'])
@role_required('admin')
def admin_courses_edit(course_id):
    """Edit course details."""
    course = Course.query.get_or_404(course_id)
    new_code = request.form.get('course_code', '').strip().upper()
    new_name = request.form.get('course_name', '').strip()
    new_desc = request.form.get('description', '').strip()

    if not new_code or not new_name:
        flash("Course code and name cannot be empty.", "danger")
        return redirect(url_for('admin_courses'))

    # Check for duplicate code
    existing = Course.query.filter_by(course_code=new_code).first()
    if existing and existing.id != course.id:
        flash(f"Another course with code '{new_code}' already exists.", "danger")
        return redirect(url_for('admin_courses'))

    course.course_code = new_code
    course.course_name = new_name
    course.description = new_desc
    db.session.commit()
    flash(f"Course '{new_code}' updated successfully.", "success")
    return redirect(url_for('admin_courses'))


@app.route('/admin/courses/<int:course_id>/toggle', methods=['POST'])
@role_required('admin')
def admin_courses_toggle(course_id):
    """Toggle course active/inactive status."""
    course = Course.query.get_or_404(course_id)
    course.status = 'inactive' if course.status == 'active' else 'active'
    db.session.commit()
    flash(f"Course '{course.course_code}' status updated to {course.status}.", "info")
    return redirect(url_for('admin_courses'))


@app.route('/admin/courses/<int:course_id>/delete', methods=['POST'])
@role_required('admin')
def admin_courses_delete(course_id):
    """Safely delete a course."""
    course = Course.query.get_or_404(course_id)
    db.session.delete(course)
    db.session.commit()
    flash(f"Course '{course.course_code}' and associated data removed.", "info")
    return redirect(url_for('admin_courses'))


# ---------------- EXAMINATION MANAGEMENT ----------------
@app.route('/admin/examinations')
@role_required('admin')
def admin_examinations():
    """List all examinations with configuration controls."""
    examinations = Examination.query.order_by(Examination.id.desc()).all()
    courses = Course.query.filter_by(status='active').order_by(Course.course_code).all()
    
    # Only approved active examiners can be assigned
    examiners = User.query.join(ExaminerProfile).filter(
        User.role == 'examiner',
        User.status == 'active',
        ExaminerProfile.approval_status == 'approved'
    ).all()

    return render_template(
        'admin/examinations.html', 
        examinations=examinations, 
        courses=courses, 
        examiners=examiners
    )


@app.route('/admin/examinations/create', methods=['POST'])
@role_required('admin')
def admin_examinations_create():
    """Create a new examination with timelines, max marks, and assigned examiners."""
    try:
        course_id = int(request.form.get('course_id'))
        name = request.form.get('name', '').strip()
        exam_type = request.form.get('exam_type', 'Viva Voce')
        duration = int(request.form.get('duration', 30))
        max_marks = float(request.form.get('max_marks', 100))
        description = request.form.get('description', '').strip()
        status = request.form.get('status', 'draft')

        # Timelines
        slot_creation_start = datetime.strptime(request.form.get('slot_creation_start'), '%Y-%m-%dT%H:%M')
        slot_creation_end = datetime.strptime(request.form.get('slot_creation_end'), '%Y-%m-%dT%H:%M')
        booking_start = datetime.strptime(request.form.get('booking_start'), '%Y-%m-%dT%H:%M')
        booking_end = datetime.strptime(request.form.get('booking_end'), '%Y-%m-%dT%H:%M')

        # Assigned examiners
        examiner_ids = request.form.getlist('examiner_ids')

        # Validate date ranges
        if slot_creation_start >= slot_creation_end:
            flash("Slot creation start must be before slot creation end.", "danger")
            return redirect(url_for('admin_examinations'))

        if booking_start >= booking_end:
            flash("Booking start must be before booking deadline.", "danger")
            return redirect(url_for('admin_examinations'))

        exam = Examination(
            course_id=course_id,
            name=name,
            exam_type=exam_type,
            duration=duration,
            max_marks=max_marks,
            description=description,
            slot_creation_start=slot_creation_start,
            slot_creation_end=slot_creation_end,
            booking_start=booking_start,
            booking_end=booking_end,
            status=status
        )

        # Assign selected examiners
        for ex_id in examiner_ids:
            ex_user = User.query.get(int(ex_id))
            if ex_user:
                exam.assigned_examiners.append(ex_user)

        db.session.add(exam)
        db.session.commit()
        flash(f"Examination '{name}' created successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to create examination: {str(e)}", "danger")

    return redirect(url_for('admin_examinations'))


@app.route('/admin/examinations/<int:exam_id>/edit', methods=['POST'])
@role_required('admin')
def admin_examinations_edit(exam_id):
    """Edit examination parameters and assigned examiners."""
    exam = Examination.query.get_or_404(exam_id)
    try:
        exam.name = request.form.get('name', '').strip()
        exam.exam_type = request.form.get('exam_type', exam.exam_type)
        exam.duration = int(request.form.get('duration', exam.duration))
        exam.max_marks = float(request.form.get('max_marks', exam.max_marks))
        exam.status = request.form.get('status', exam.status)

        exam.slot_creation_start = datetime.strptime(request.form.get('slot_creation_start'), '%Y-%m-%dT%H:%M')
        exam.slot_creation_end = datetime.strptime(request.form.get('slot_creation_end'), '%Y-%m-%dT%H:%M')
        exam.booking_start = datetime.strptime(request.form.get('booking_start'), '%Y-%m-%dT%H:%M')
        exam.booking_end = datetime.strptime(request.form.get('booking_end'), '%Y-%m-%dT%H:%M')

        # Update assigned examiners
        examiner_ids = request.form.getlist('examiner_ids')
        exam.assigned_examiners = []
        for ex_id in examiner_ids:
            ex_user = User.query.get(int(ex_id))
            if ex_user:
                exam.assigned_examiners.append(ex_user)

        db.session.commit()
        flash(f"Examination '{exam.name}' updated successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating examination: {str(e)}", "danger")

    return redirect(url_for('admin_examinations'))


@app.route('/admin/examinations/<int:exam_id>/toggle', methods=['POST'])
@role_required('admin')
def admin_examinations_toggle(exam_id):
    """Toggle examination published / draft status."""
    exam = Examination.query.get_or_404(exam_id)
    exam.status = 'draft' if exam.status == 'published' else 'published'
    db.session.commit()
    flash(f"Examination '{exam.name}' status is now {exam.status}.", "info")
    return redirect(url_for('admin_examinations'))


# ---------------- RUBRIC CRITERIA MANAGEMENT ----------------
@app.route('/admin/examinations/<int:exam_id>/rubrics')
@role_required('admin')
def admin_rubrics(exam_id):
    """Manage rubric criteria for a specific examination."""
    exam = Examination.query.get_or_404(exam_id)
    return render_template('admin/rubrics.html', exam=exam)


@app.route('/admin/examinations/<int:exam_id>/rubrics/create', methods=['POST'])
@role_required('admin')
def admin_rubrics_create(exam_id):
    """Add a new evaluation criterion to an examination."""
    exam = Examination.query.get_or_404(exam_id)
    criterion_name = request.form.get('criterion_name', '').strip()
    description = request.form.get('description', '').strip()
    max_marks = float(request.form.get('max_marks', 0))
    weightage = float(request.form.get('weightage', 1.0))

    if not criterion_name or max_marks <= 0:
        flash("Criterion name and valid positive maximum marks are required.", "danger")
        return redirect(url_for('admin_rubrics', exam_id=exam.id))

    rubric = ExaminationRubric(
        examination_id=exam.id,
        criterion_name=criterion_name,
        description=description,
        max_marks=max_marks,
        weightage=weightage
    )
    db.session.add(rubric)
    db.session.commit()
    flash(f"Criterion '{criterion_name}' added to {exam.name}.", "success")
    return redirect(url_for('admin_rubrics', exam_id=exam.id))


@app.route('/admin/rubrics/<int:rubric_id>/edit', methods=['POST'])
@role_required('admin')
def admin_rubrics_edit(rubric_id):
    """Edit an existing rubric criterion."""
    rubric = ExaminationRubric.query.get_or_404(rubric_id)
    rubric.criterion_name = request.form.get('criterion_name', rubric.criterion_name).strip()
    rubric.description = request.form.get('description', rubric.description).strip()
    rubric.max_marks = float(request.form.get('max_marks', rubric.max_marks))
    rubric.weightage = float(request.form.get('weightage', rubric.weightage))

    db.session.commit()
    flash("Rubric criterion updated.", "success")
    return redirect(url_for('admin_rubrics', exam_id=rubric.examination_id))


@app.route('/admin/rubrics/<int:rubric_id>/delete', methods=['POST'])
@role_required('admin')
def admin_rubrics_delete(rubric_id):
    """Delete a rubric criterion."""
    rubric = ExaminationRubric.query.get_or_404(rubric_id)
    exam_id = rubric.examination_id
    db.session.delete(rubric)
    db.session.commit()
    flash("Criterion removed.", "info")
    return redirect(url_for('admin_rubrics', exam_id=exam_id))


# ---------------- EXAMINER APPROVAL & MANAGEMENT ----------------
@app.route('/admin/examiners')
@role_required('admin')
def admin_examiners():
    """List all registered examiners with approval and status controls."""
    examiners = User.query.filter_by(role='examiner').order_by(User.id.desc()).all()
    return render_template('admin/examiners.html', examiners=examiners)


@app.route('/admin/examiners/<int:user_id>/<action>', methods=['POST'])
@role_required('admin')
def admin_examiners_status(user_id, action):
    """Approve, reject, activate, or deactivate an examiner."""
    user = User.query.get_or_404(user_id)
    if user.role != 'examiner':
        flash("Action only valid for examiner accounts.", "danger")
        return redirect(url_for('admin_examiners'))

    profile = user.examiner_profile

    if action == 'approve':
        if profile:
            profile.approval_status = 'approved'
        user.status = 'active'
        flash(f"Examiner {user.full_name} has been APPROVED and activated.", "success")
    elif action == 'reject':
        if profile:
            profile.approval_status = 'rejected'
        user.status = 'inactive'
        flash(f"Examiner {user.full_name} application was REJECTED.", "warning")
    elif action == 'deactivate':
        user.status = 'inactive'
        flash(f"Examiner {user.full_name} has been DEACTIVATED.", "info")
    elif action == 'activate':
        user.status = 'active'
        flash(f"Examiner {user.full_name} has been ACTIVATED.", "success")

    db.session.commit()
    return redirect(url_for('admin_examiners'))


# ---------------- STUDENT MANAGEMENT ----------------
@app.route('/admin/students')
@role_required('admin')
def admin_students():
    """Search and view registered students."""
    search_query = request.args.get('search', '').strip()
    query = User.query.filter_by(role='student')

    if search_query:
        query = query.filter(
            (User.full_name.ilike(f'%{search_query}%')) |
            (User.email.ilike(f'%{search_query}%')) |
            (User.student_id.ilike(f'%{search_query}%')) |
            (User.department.ilike(f'%{search_query}%'))
        )

    students = query.order_by(User.id.desc()).all()
    return render_template('admin/students.html', students=students, search_query=search_query)


# ---------------- SLOTS MONITORING ----------------
@app.route('/admin/slots')
@role_required('admin')
def admin_slots():
    """Filter and inspect examination slots across all examinations."""
    exam_id = request.args.get('exam_id', type=int)
    status = request.args.get('status', '').strip()

    query = ExaminationSlot.query
    if exam_id:
        query = query.filter_by(examination_id=exam_id)
    if status:
        query = query.filter_by(status=status)

    slots = query.order_by(ExaminationSlot.date.desc(), ExaminationSlot.start_time.asc()).all()
    examinations = Examination.query.order_by(Examination.name).all()

    return render_template(
        'admin/slots.html',
        slots=slots,
        examinations=examinations,
        selected_exam_id=exam_id,
        selected_status=status
    )


# ---------------- BOOKING MANAGEMENT & RESCHEDULING ----------------
@app.route('/admin/bookings')
@role_required('admin')
def admin_bookings():
    """View and manage all student bookings with audit trail access."""
    search_query = request.args.get('search', '').strip()
    exam_id = request.args.get('exam_id', type=int)
    status = request.args.get('status', '').strip()

    query = Booking.query.join(User, Booking.student_id == User.id).join(ExaminationSlot, Booking.slot_id == ExaminationSlot.id)

    if search_query:
        query = query.filter(
            (User.full_name.ilike(f'%{search_query}%')) |
            (User.student_id.ilike(f'%{search_query}%')) |
            (User.email.ilike(f'%{search_query}%'))
        )
    if exam_id:
        query = query.filter(ExaminationSlot.examination_id == exam_id)
    if status:
        query = query.filter(Booking.status == status)

    bookings = query.order_by(Booking.id.desc()).all()
    examinations = Examination.query.order_by(Examination.name).all()

    return render_template(
        'admin/bookings.html',
        bookings=bookings,
        examinations=examinations,
        search_query=search_query,
        selected_exam_id=exam_id,
        selected_status=status
    )


@app.route('/admin/bookings/<int:booking_id>/reschedule', methods=['POST'])
@role_required('admin')
def admin_bookings_reschedule(booking_id):
    """
    Reschedule booking or change assigned examiner by moving student to another available slot.
    Preserves audit history.
    """
    booking = Booking.query.get_or_404(booking_id)
    new_slot_id = request.form.get('new_slot_id', type=int)
    reason = request.form.get('reason', '').strip()

    if not new_slot_id:
        flash("Please select a valid new slot.", "danger")
        return redirect(url_for('admin_bookings'))

    new_slot = ExaminationSlot.query.get_or_404(new_slot_id)
    old_slot = booking.slot

    # Verify both slots belong to the same examination
    if new_slot.examination_id != old_slot.examination_id:
        flash("Rescheduling is only permitted between slots of the same examination.", "danger")
        return redirect(url_for('admin_bookings'))

    # Verify new slot capacity
    if new_slot.available_seats <= 0:
        flash("Target slot has no remaining capacity.", "danger")
        return redirect(url_for('admin_bookings'))

    # Execute transfer within transaction
    old_slot.booked_count = max(0, old_slot.booked_count - 1)
    old_slot.update_status()

    new_slot.booked_count += 1
    new_slot.update_status()

    prev_slot_id = booking.slot_id
    booking.slot_id = new_slot.id

    # Audit log
    audit_notes = f"Admin rescheduled from Slot #{prev_slot_id} (Examiner: {old_slot.examiner.full_name}) to Slot #{new_slot.id} (Examiner: {new_slot.examiner.full_name}). Reason: {reason}"
    history_entry = BookingHistory(
        booking_id=booking.id,
        action='rescheduled',
        previous_slot_id=prev_slot_id,
        new_slot_id=new_slot.id,
        changed_by_user_id=current_user.id,
        notes=audit_notes
    )
    db.session.add(history_entry)
    db.session.commit()

    flash(f"Booking #BK-{booking.id} successfully rescheduled to {new_slot.date.strftime('%d %b %Y')} with examiner {new_slot.examiner.full_name}.", "success")
    return redirect(url_for('admin_bookings'))


# ==========================================
# MILESTONE 4: EXAMINER DASHBOARD AND SLOTS
# ==========================================

@app.route('/examiner/dashboard')
@role_required('examiner')
def examiner_dashboard():
    """Examiner portal dashboard displaying assigned duties and pending tasks."""
    assigned_exams = current_user.assigned_examinations.all()
    assigned_exams_count = len(assigned_exams)
    
    total_slots_count = ExaminationSlot.query.filter_by(examiner_id=current_user.id).count()

    # Query bookings for this examiner's slots
    examiner_slot_ids = [s.id for s in ExaminationSlot.query.filter_by(examiner_id=current_user.id).all()]
    
    booked_students_count = Booking.query.filter(
        Booking.slot_id.in_(examiner_slot_ids),
        Booking.status == 'confirmed'
    ).count() if examiner_slot_ids else 0

    # Bookings awaiting evaluation
    pending_evals = Booking.query.filter(
        Booking.slot_id.in_(examiner_slot_ids),
        Booking.status == 'confirmed',
        ~Booking.evaluation.has()
    ).all() if examiner_slot_ids else []

    return render_template(
        'examiner/dashboard.html',
        assigned_exams=assigned_exams,
        assigned_exams_count=assigned_exams_count,
        total_slots_count=total_slots_count,
        booked_students_count=booked_students_count,
        pending_evaluations_count=len(pending_evals),
        pending_evaluations_list=pending_evals[:5]
    )


@app.route('/examiner/examinations')
@role_required('examiner')
def examiner_examinations():
    """View details of examinations assigned to the examiner."""
    examinations = current_user.assigned_examinations.all()
    return render_template('examiner/examinations.html', examinations=examinations)


@app.route('/examiner/slots')
@role_required('examiner')
def examiner_slots():
    """List and manage examination slots created by the examiner."""
    selected_exam_id = request.args.get('exam_id', type=int)
    assigned_exams = current_user.assigned_examinations.all()
    
    slots = ExaminationSlot.query.filter_by(examiner_id=current_user.id).order_by(
        ExaminationSlot.date.desc(), ExaminationSlot.start_time.asc()
    ).all()

    return render_template(
        'examiner/slots.html',
        slots=slots,
        assigned_exams=assigned_exams,
        selected_exam_id=selected_exam_id
    )


@app.route('/examiner/slots/create', methods=['POST'])
@role_required('examiner')
def examiner_slots_create():
    """Create a new slot during the permitted slot creation window."""
    try:
        exam_id = int(request.form.get('examination_id'))
        slot_date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        start_time_val = datetime.strptime(request.form.get('start_time'), '%H:%M').time()
        end_time_val = datetime.strptime(request.form.get('end_time'), '%H:%M').time()
        max_capacity = int(request.form.get('max_capacity', 1))

        exam = Examination.query.get_or_404(exam_id)

        # Enforce: Examiner must be assigned to this examination
        if exam not in current_user.assigned_examinations:
            flash("You are not assigned as an examiner for this examination.", "danger")
            return redirect(url_for('examiner_slots'))

        # Enforce: Permitted slot creation window
        if not exam.is_slot_creation_open():
            flash("Slot creation window is currently closed for this examination.", "danger")
            return redirect(url_for('examiner_slots'))

        # Enforce: Start time before End time
        if start_time_val >= end_time_val:
            flash("Slot start time must be strictly earlier than end time.", "danger")
            return redirect(url_for('examiner_slots'))

        # Enforce: Positive capacity
        if max_capacity <= 0:
            flash("Capacity must be at least 1 student.", "danger")
            return redirect(url_for('examiner_slots'))

        # Enforce: Prevent conflicting examiner slots on same date
        conflict = ExaminationSlot.query.filter(
            ExaminationSlot.examiner_id == current_user.id,
            ExaminationSlot.date == slot_date,
            ExaminationSlot.start_time < end_time_val,
            ExaminationSlot.end_time > start_time_val
        ).first()

        if conflict:
            flash(f"Time conflict: You already have a slot scheduled on {slot_date} from {conflict.start_time.strftime('%H:%M')} to {conflict.end_time.strftime('%H:%M')}.", "danger")
            return redirect(url_for('examiner_slots'))

        # Create slot
        slot = ExaminationSlot(
            examination_id=exam.id,
            examiner_id=current_user.id,
            date=slot_date,
            start_time=start_time_val,
            end_time=end_time_val,
            max_capacity=max_capacity,
            booked_count=0,
            status='available'
        )
        db.session.add(slot)
        db.session.commit()
        flash("Examination slot scheduled successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to create slot: {str(e)}", "danger")

    return redirect(url_for('examiner_slots'))


@app.route('/examiner/slots/<int:slot_id>/edit', methods=['POST'])
@role_required('examiner')
def examiner_slots_edit(slot_id):
    """
    Edit slot parameters.
    Enforce: Only allowed before booking begins and capacity cannot drop below existing bookings.
    """
    slot = ExaminationSlot.query.get_or_404(slot_id)

    # Ownership check
    if slot.examiner_id != current_user.id:
        abort(403)

    now = datetime.now()
    if now >= slot.examination.booking_start:
        flash("Slots cannot be edited after student booking has commenced.", "warning")
        return redirect(url_for('examiner_slots'))

    try:
        new_date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        new_start = datetime.strptime(request.form.get('start_time'), '%H:%M').time()
        new_end = datetime.strptime(request.form.get('end_time'), '%H:%M').time()
        new_cap = int(request.form.get('max_capacity'))

        if new_start >= new_end:
            flash("Slot start time must be before end time.", "danger")
            return redirect(url_for('examiner_slots'))

        if new_cap < slot.booked_count:
            flash(f"Capacity cannot be reduced below current bookings ({slot.booked_count}).", "danger")
            return redirect(url_for('examiner_slots'))

        slot.date = new_date
        slot.start_time = new_start
        slot.end_time = new_end
        slot.max_capacity = new_cap
        slot.update_status()

        db.session.commit()
        flash("Slot details updated successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error editing slot: {str(e)}", "danger")

    return redirect(url_for('examiner_slots'))


@app.route('/examiner/slots/<int:slot_id>/delete', methods=['POST'])
@role_required('examiner')
def examiner_slots_delete(slot_id):
    """
    Delete an unbooked slot.
    Enforce: Allowed only if booked_count == 0.
    """
    slot = ExaminationSlot.query.get_or_404(slot_id)

    if slot.examiner_id != current_user.id:
        abort(403)

    if slot.booked_count > 0:
        flash("Cannot delete a slot that already has student bookings.", "danger")
        return redirect(url_for('examiner_slots'))

    db.session.delete(slot)
    db.session.commit()
    flash("Examination slot removed successfully.", "info")
    return redirect(url_for('examiner_slots'))


# ---------------- EXAMINER EVALUATION ----------------
@app.route('/examiner/students')
@role_required('examiner')
def examiner_students():
    """View students booked into examiner's slots."""
    examiner_slot_ids = [s.id for s in ExaminationSlot.query.filter_by(examiner_id=current_user.id).all()]
    
    bookings = Booking.query.filter(
        Booking.slot_id.in_(examiner_slot_ids)
    ).order_by(Booking.id.desc()).all() if examiner_slot_ids else []

    return render_template('examiner/students.html', bookings=bookings)


@app.route('/examiner/evaluate/<int:booking_id>')
@role_required('examiner')
def examiner_evaluate(booking_id):
    """Display the rubric evaluation form for a booked student."""
    booking = Booking.query.get_or_404(booking_id)

    # Ownership check: Examiner can only evaluate students booked in their own slots
    if booking.slot.examiner_id != current_user.id:
        flash("Access forbidden: You can only evaluate students scheduled in your own slots.", "danger")
        return redirect(url_for('examiner_students'))

    existing_evaluation = booking.evaluation
    existing_scores = {}
    if existing_evaluation:
        for score in existing_evaluation.criterion_scores:
            existing_scores[score.rubric_id] = score

    return render_template(
        'examiner/evaluate.html',
        booking=booking,
        existing_evaluation=existing_evaluation,
        existing_scores=existing_scores
    )


@app.route('/examiner/evaluate/<int:booking_id>/submit', methods=['POST'])
@role_required('examiner')
def examiner_evaluate_submit(booking_id):
    """
    Save or update criterion-wise rubric evaluation and marks.
    Enforce: Total marks <= Examination max_marks.
    """
    booking = Booking.query.get_or_404(booking_id)

    if booking.slot.examiner_id != current_user.id:
        abort(403)

    exam = booking.slot.examination
    rubrics = exam.rubrics
    is_published = bool(request.form.get('is_published'))
    overall_remarks = request.form.get('overall_remarks', '').strip()

    try:
        total_marks = 0.0
        scores_data = []

        if rubrics:
            for r in rubrics:
                val = float(request.form.get(f'marks_{r.id}', 0))
                feedback = request.form.get(f'feedback_{r.id}', '').strip()

                if val < 0 or val > r.max_marks:
                    flash(f"Marks for '{r.criterion_name}' must be between 0 and {r.max_marks}.", "danger")
                    return redirect(url_for('examiner_evaluate', booking_id=booking.id))

                total_marks += val
                scores_data.append((r.id, val, feedback))
        else:
            # Direct total marks if no rubrics configured
            total_marks = float(request.form.get('direct_total_marks', 0))
            if total_marks < 0 or total_marks > exam.max_marks:
                flash(f"Total marks must be between 0 and {exam.max_marks}.", "danger")
                return redirect(url_for('examiner_evaluate', booking_id=booking.id))

        if total_marks > exam.max_marks:
            flash(f"Sum of marks ({total_marks}) exceeds examination maximum ({exam.max_marks}).", "danger")
            return redirect(url_for('examiner_evaluate', booking_id=booking.id))

        # Check existing evaluation or create new
        evaluation = booking.evaluation
        if not evaluation:
            evaluation = Evaluation(
                booking_id=booking.id,
                examiner_id=current_user.id,
                total_marks=total_marks,
                remarks=overall_remarks,
                is_published=is_published
            )
            db.session.add(evaluation)
            db.session.flush()
        else:
            evaluation.total_marks = total_marks
            evaluation.remarks = overall_remarks
            evaluation.is_published = is_published
            evaluation.evaluated_at = datetime.utcnow()
            # Clear old scores
            EvaluationScore.query.filter_by(evaluation_id=evaluation.id).delete()

        # Add criterion scores
        for r_id, marks_ob, fb in scores_data:
            score = EvaluationScore(
                evaluation_id=evaluation.id,
                rubric_id=r_id,
                marks_obtained=marks_ob,
                feedback=fb
            )
            db.session.add(score)

        booking.status = 'completed'
        db.session.commit()
        flash(f"Evaluation for {booking.student.full_name} saved successfully (Score: {total_marks}/{exam.max_marks}).", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to submit evaluation: {str(e)}", "danger")

    return redirect(url_for('examiner_students'))


# ==========================================
# MILESTONE 5: STUDENT DASHBOARD AND BOOKING
# ==========================================

@app.route('/student/dashboard')
@role_required('student')
def student_dashboard():
    """Student dashboard displaying open examinations, active bookings, and results."""
    now = datetime.now()
    
    # Open exams count
    open_exams_count = Examination.query.filter(
        Examination.status == 'published',
        Examination.booking_start <= now,
        Examination.booking_end >= now
    ).count()

    active_bookings = Booking.query.filter_by(
        student_id=current_user.id,
        status='confirmed'
    ).order_by(Booking.id.desc()).all()

    total_history_count = Booking.query.filter_by(student_id=current_user.id).count()

    # Published results
    published_results = Evaluation.query.join(Booking).filter(
        Booking.student_id == current_user.id,
        Evaluation.is_published == True
    ).order_by(Evaluation.evaluated_at.desc()).all()

    return render_template(
        'student/dashboard.html',
        open_exams_count=open_exams_count,
        confirmed_bookings_count=len(active_bookings),
        total_history_count=total_history_count,
        published_results_count=len(published_results),
        active_bookings=active_bookings,
        recent_results=published_results[:3]
    )


@app.route('/student/examinations')
@role_required('student')
def student_examinations():
    """Search and filter published examinations available for booking."""
    search_query = request.args.get('search', '').strip()
    selected_type = request.args.get('exam_type', '').strip()

    query = Examination.query.join(Course).filter(Examination.status == 'published')

    if search_query:
        query = query.filter(
            (Examination.name.ilike(f'%{search_query}%')) |
            (Course.course_code.ilike(f'%{search_query}%')) |
            (Course.course_name.ilike(f'%{search_query}%'))
        )
    if selected_type:
        query = query.filter(Examination.exam_type == selected_type)

    examinations = query.order_by(Examination.booking_end.asc()).all()

    # Active booked exam IDs for this student
    active_bookings = Booking.query.filter_by(
        student_id=current_user.id, 
        status='confirmed'
    ).all()
    booked_exam_ids = {b.slot.examination_id for b in active_bookings}

    return render_template(
        'student/examinations.html',
        examinations=examinations,
        booked_exam_ids=booked_exam_ids,
        search_query=search_query,
        selected_type=selected_type
    )


@app.route('/student/slots')
@role_required('student')
def student_slots():
    """Browse slots for an examination and initiate booking."""
    exam_id = request.args.get('exam_id', type=int)
    published_exams = Examination.query.filter_by(status='published').order_by(Examination.name).all()

    selected_exam = None
    slots = []
    already_booked = False

    active_bookings = Booking.query.filter_by(student_id=current_user.id, status='confirmed').all()
    booked_exam_ids = {b.slot.examination_id for b in active_bookings}

    if exam_id:
        selected_exam = Examination.query.get_or_404(exam_id)
        slots = ExaminationSlot.query.filter_by(
            examination_id=selected_exam.id
        ).order_by(ExaminationSlot.date.asc(), ExaminationSlot.start_time.asc()).all()
        already_booked = selected_exam.id in booked_exam_ids

    return render_template(
        'student/slots.html',
        published_exams=published_exams,
        selected_exam=selected_exam,
        slots=slots,
        booked_exam_ids=booked_exam_ids,
        already_booked_this_exam=already_booked
    )


@app.route('/student/book/<int:slot_id>', methods=['POST'])
@role_required('student')
def student_book_slot(slot_id):
    """
    Student slot booking endpoint.
    Strictly enforces:
    1. Examination booking window is open.
    2. Student has NOT already booked the same examination.
    3. Slot is available and capacity is not exceeded.
    4. Reliable capacity decrement and slot status update.
    5. Booking audit history log.
    """
    slot = ExaminationSlot.query.get_or_404(slot_id)
    exam = slot.examination

    # Rule 1: Booking window check
    if not exam.is_booking_open():
        flash("Booking window is currently closed for this examination.", "danger")
        return redirect(url_for('student_slots', exam_id=exam.id))

    # Rule 2: Prevent duplicate active booking for the same exam
    existing_booking = Booking.query.join(ExaminationSlot).filter(
        Booking.student_id == current_user.id,
        Booking.status == 'confirmed',
        ExaminationSlot.examination_id == exam.id
    ).first()

    if existing_booking:
        flash("You already have an active booking for this examination.", "warning")
        return redirect(url_for('student_bookings'))

    # Rule 3: Slot capacity and availability check
    if slot.available_seats <= 0 or slot.status == 'full':
        flash("This examination slot is already fully booked.", "danger")
        return redirect(url_for('student_slots', exam_id=exam.id))

    try:
        # Create confirmed booking
        booking = Booking(
            student_id=current_user.id,
            slot_id=slot.id,
            status='confirmed',
            booking_date=datetime.utcnow()
        )
        db.session.add(booking)
        db.session.flush()

        # Update slot availability reliably
        slot.booked_count += 1
        slot.update_status()

        # Preserve audit history
        audit_entry = BookingHistory(
            booking_id=booking.id,
            action='created',
            new_slot_id=slot.id,
            changed_by_user_id=current_user.id,
            notes=f"Student confirmed booking with examiner {slot.examiner.full_name} for {slot.date.strftime('%d %b %Y')}."
        )
        db.session.add(audit_entry)
        db.session.commit()

        flash(f"Booking confirmed for {exam.name} on {slot.date.strftime('%d %b %Y')} at {slot.start_time.strftime('%H:%M')}!", "success")
        return redirect(url_for('student_bookings'))
    except Exception as e:
        db.session.rollback()
        flash(f"Booking could not be completed: {str(e)}", "danger")
        return redirect(url_for('student_slots', exam_id=exam.id))


@app.route('/student/bookings')
@role_required('student')
def student_bookings():
    """View active confirmed bookings."""
    bookings = Booking.query.filter_by(
        student_id=current_user.id,
        status='confirmed'
    ).order_by(Booking.id.desc()).all()
    return render_template('student/bookings.html', bookings=bookings)


@app.route('/student/cancel/<int:booking_id>', methods=['POST'])
@role_required('student')
def student_cancel_booking(booking_id):
    """
    Cancel student booking.
    Enforce:
    1. Booking ownership check.
    2. Cancellation allowed only before examination booking deadline.
    3. Release slot seat and restore capacity.
    4. Preserve historical booking record.
    """
    booking = Booking.query.get_or_404(booking_id)

    # Ownership check
    if booking.student_id != current_user.id:
        abort(403)

    if booking.status != 'confirmed':
        flash("This booking is no longer active.", "warning")
        return redirect(url_for('student_bookings'))

    exam = booking.slot.examination
    now = datetime.now()

    # Timeline check
    if now > exam.booking_end:
        flash("Cancellation deadline has passed. Bookings are now locked.", "danger")
        return redirect(url_for('student_bookings'))

    try:
        # Mark as cancelled
        booking.status = 'cancelled'
        booking.cancellation_timestamp = datetime.utcnow()

        # Restore slot seat
        slot = booking.slot
        slot.booked_count = max(0, slot.booked_count - 1)
        slot.update_status()

        # Record cancellation in audit history
        audit_entry = BookingHistory(
            booking_id=booking.id,
            action='cancelled',
            previous_slot_id=slot.id,
            changed_by_user_id=current_user.id,
            notes="Student cancelled booking prior to deadline. Seat released."
        )
        db.session.add(audit_entry)
        db.session.commit()

        flash(f"Booking #BK-{booking.id} cancelled. Seat has been released.", "info")
    except Exception as e:
        db.session.rollback()
        flash(f"Error cancelling booking: {str(e)}", "danger")

    return redirect(url_for('student_bookings'))


# ==========================================
# MILESTONE 6: BOOKING HISTORY AND EVALUATION
# ==========================================

@app.route('/student/history')
@role_required('student')
def student_history():
    """Complete chronological booking history for the logged-in student."""
    bookings = Booking.query.filter_by(
        student_id=current_user.id
    ).order_by(Booking.id.desc()).all()
    return render_template('student/history.html', bookings=bookings)


@app.route('/student/results')
@role_required('student')
def student_results():
    """
    Display official evaluation results.
    Enforce: Results remain private until published (is_published == True).
    """
    evaluations = Evaluation.query.join(Booking).filter(
        Booking.student_id == current_user.id,
        Evaluation.is_published == True
    ).order_by(Evaluation.evaluated_at.desc()).all()

    return render_template('student/results.html', evaluations=evaluations)


# --------------------------------------------------
# RUN SERVER (LOCAL DEVELOPMENT)
# --------------------------------------------------
if __name__ == '__main__':
    # Default local port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)

