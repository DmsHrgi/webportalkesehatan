from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-this-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///healthcare_portal.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)

with app.app_context():
    db.create_all()
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    age_group = db.Column(db.Enum('18-34', '35-49', '50-64', '65-74', '≥75'), nullable=False)
    birth_sex = db.Column(db.Enum('Male', 'Female'), nullable=False)
    numeracy_score = db.Column(db.Enum('Very easy', 'Easy', 'Hard'), nullable=False)
    health_literacy_level = db.Column(db.Enum('High', 'Medium', 'Low'), nullable=False)
    preferred_access_mode = db.Column(db.Enum('Website only', 'App only', 'Both'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    health_profile = db.relationship('HealthProfile', backref='user', uselist=False)
    provider_communications = db.relationship('ProviderCommunication', backref='user')
    portal_usage_logs = db.relationship('PortalUsageLog', backref='user')
    content_feedbacks = db.relationship('ContentFeedback', backref='user')
    interface_preference = db.relationship('InterfacePreference', backref='user', uselist=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class HealthProfile(db.Model):
    __tablename__ = 'health_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    general_health = db.Column(db.Enum('Excellent', 'Very good', 'Good', 'Fair', 'Poor'))
    confidence_manage_health = db.Column(db.Enum('Completely', 'Very', 'Somewhat', 'Little', 'Not at all'))
    has_deafness = db.Column(db.Boolean, default=False)
    has_diabetes = db.Column(db.Boolean, default=False)
    has_hypertension = db.Column(db.Boolean, default=False)
    has_heart_condition = db.Column(db.Boolean, default=False)
    has_lung_disease = db.Column(db.Boolean, default=False)
    has_depression = db.Column(db.Boolean, default=False)
    has_cancer_history = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ProviderCommunication(db.Model):
    __tablename__ = 'provider_communications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    provider_name = db.Column(db.String(200), nullable=False)
    message_type = db.Column(db.Enum('Appointment', 'Test Result', 'Prescription', 'General'), nullable=False)
    message_content = db.Column(db.Text, nullable=False)
    sent_date = db.Column(db.DateTime, default=datetime.utcnow)
    read_status = db.Column(db.Boolean, default=False)

class PortalUsageLog(db.Model):
    __tablename__ = 'portal_usage_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action_type = db.Column(db.Enum('Login', 'View Records', 'Send Message', 'Update Profile', 'Logout'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    session_duration = db.Column(db.Integer)  # in minutes

class ContentFeedback(db.Model):
    __tablename__ = 'content_feedbacks'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_type = db.Column(db.Enum('Article', 'Video', 'Infographic', 'Form'), nullable=False)
    rating = db.Column(db.Enum('Very Helpful', 'Helpful', 'Neutral', 'Not Helpful', 'Confusing'), nullable=False)
    comments = db.Column(db.Text)
    feedback_date = db.Column(db.DateTime, default=datetime.utcnow)

class InterfacePreference(db.Model):
    __tablename__ = 'interface_preferences'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    font_size = db.Column(db.Enum('Small', 'Medium', 'Large'), default='Medium')
    color_scheme = db.Column(db.Enum('Light', 'Dark', 'High Contrast'), default='Light')
    language = db.Column(db.String(10), default='en')
    notification_preferences = db.Column(db.Text)  # JSON string for preferences
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Appointment(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    provider_name = db.Column(db.String(200), nullable=False)
    appointment_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.Enum('Scheduled', 'Confirmed', 'Completed', 'Cancelled'), default='Scheduled')
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Medication(db.Model):
    __tablename__ = 'medications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    dosage = db.Column(db.String(100), nullable=False)
    frequency = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date)
    is_active = db.Column(db.Boolean, default=True)
    prescribed_by = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TestResult(db.Model):
    __tablename__ = 'test_results'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    test_name = db.Column(db.String(200), nullable=False)
    test_date = db.Column(db.DateTime, nullable=False)
    result_value = db.Column(db.String(500))
    normal_range = db.Column(db.String(200))
    status = db.Column(db.Enum('Normal', 'Abnormal', 'Critical'), default='Normal')
    notes = db.Column(db.Text)
    is_new = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    file_size = db.Column(db.Integer)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)

class PrescriptionRefill(db.Model):
    __tablename__ = 'prescription_refills'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    medication_name = db.Column(db.String(200), nullable=False)
    pharmacy_name = db.Column(db.String(200))
    last_fill_date = db.Column(db.Date)
    status = db.Column(db.Enum('Pending', 'Approved', 'Rejected', 'Completed'), default='Pending')
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
            
        user = User(
            email=email,
            age_group=request.form.get('age_group'),
            birth_sex=request.form.get('birth_sex'),
            numeracy_score=request.form.get('numeracy_score'),
            health_literacy_level=request.form.get('health_literacy_level'),
            preferred_access_mode=request.form.get('preferred_access_mode')
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Create default interface preferences
        pref = InterfacePreference(user_id=user.id)
        db.session.add(pref)
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('dashboard'))
        
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get real data for the dashboard
    upcoming_appointments = Appointment.query.filter_by(user_id=current_user.id)\
        .filter(Appointment.appointment_date >= datetime.now())\
        .filter(Appointment.status.in_(['Scheduled', 'Confirmed']))\
        .order_by(Appointment.appointment_date).limit(5).all()
    
    active_medications = Medication.query.filter_by(user_id=current_user.id, is_active=True).all()
    
    recent_test_results = TestResult.query.filter_by(user_id=current_user.id)\
        .order_by(TestResult.created_at.desc()).limit(5).all()
    
    new_test_results_count = TestResult.query.filter_by(user_id=current_user.id, is_new=True).count()
    
    # Get user's health profile if exists
    health_profile = HealthProfile.query.filter_by(user_id=current_user.id).first()
    
    return render_template('dashboard.html', 
                         user=current_user,
                         upcoming_appointments=upcoming_appointments,
                         active_medications=active_medications,
                         recent_test_results=recent_test_results,
                         new_test_results_count=new_test_results_count,
                         health_profile=health_profile)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Appointment routes
@app.route('/appointments')
@login_required
def appointments():
    all_appointments = Appointment.query.filter_by(user_id=current_user.id)\
        .order_by(Appointment.appointment_date.desc()).all()
    return render_template('appointments.html', appointments=all_appointments)

@app.route('/appointments/new', methods=['GET', 'POST'])
@login_required
def new_appointment():
    if request.method == 'POST':
        appointment = Appointment(
            user_id=current_user.id,
            title=request.form.get('title'),
            provider_name=request.form.get('provider_name'),
            appointment_date=datetime.strptime(request.form.get('appointment_date'), '%Y-%m-%dT%H:%M'),
            notes=request.form.get('notes')
        )
        db.session.add(appointment)
        db.session.commit()
        flash('Appointment scheduled successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('new_appointment.html')

# Document upload routes
@app.route('/documents')
@login_required
def documents():
    user_documents = Document.query.filter_by(user_id=current_user.id)\
        .order_by(Document.upload_date.desc()).all()
    return render_template('documents.html', documents=user_documents)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_document():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            document = Document(
                user_id=current_user.id,
                filename=filename,
                original_filename=file.filename,
                file_type=file.content_type,
                file_size=os.path.getsize(file_path),
                description=request.form.get('description')
            )
            db.session.add(document)
            db.session.commit()
            flash('Document uploaded successfully!', 'success')
            return redirect(url_for('documents'))
    
    return render_template('upload.html')

# Prescription refill routes
@app.route('/prescription-refill', methods=['GET', 'POST'])
@login_required
def prescription_refill():
    if request.method == 'POST':
        refill = PrescriptionRefill(
            user_id=current_user.id,
            medication_name=request.form.get('medication_name'),
            pharmacy_name=request.form.get('pharmacy_name'),
            last_fill_date=datetime.strptime(request.form.get('last_fill_date'), '%Y-%m-%d').date() if request.form.get('last_fill_date') else None,
            notes=request.form.get('notes')
        )
        db.session.add(refill)
        db.session.commit()
        flash('Prescription refill request submitted successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('prescription_refill.html')

# Message routes
@app.route('/messages')
@login_required
def messages():
    user_messages = ProviderCommunication.query.filter_by(user_id=current_user.id)\
        .order_by(ProviderCommunication.sent_date.desc()).all()
    return render_template('messages.html', messages=user_messages)

@app.route('/messages/new', methods=['GET', 'POST'])
@login_required
def new_message():
    if request.method == 'POST':
        message = ProviderCommunication(
            user_id=current_user.id,
            provider_name=request.form.get('provider_name'),
            message_type=request.form.get('message_type'),
            message_content=request.form.get('message_content')
        )
        db.session.add(message)
        db.session.commit()
        flash('Message sent successfully!', 'success')
        return redirect(url_for('messages'))
    
    return render_template('new_message.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
