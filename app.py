import eventlet
eventlet.monkey_patch()
from flask import Flask, request, render_template, redirect, url_for, session, flash, g, jsonify, send_from_directory, Blueprint
from flask_login import login_required, current_user, UserMixin, LoginManager, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from sqlalchemy import event, Index, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
import tempfile
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
from functools import wraps
from flask import abort
from flask_mail import Mail, Message
import os
import pg8000
import re
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask import send_file
import zipfile
import io
from itsdangerous import URLSafeTimedSerializer
import json
import pyimgur
from dotenv import load_dotenv
load_dotenv()
# ===================================================
#                  >>>> APP CONFIGURATIONS <<<<
# ===================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "3ab7b7e619e24a3ae40a46c79b9b80439251aa976d03eb909dfe37d4a4a927dd")
app.config['SESSION_PERMANENT'] = True 
db_url = os.getenv("DATABASE_URL1")
if not db_url:
    raise RuntimeError("❌ DATABASE_URL is missing. Make sure it's set in Render env settings.")
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = '1b2bd05468432c4f8a4a2b3f23aef5afebd1995ac49af3536ce147b5d48c781d'
app.config['ACTIVITY_RETENTION_DAYS'] = 30

app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT"))
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS") == 'True'
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")

# ===================================================
#                  >>>> EXTENSIONS INIT <<<<
# ===================================================

db = SQLAlchemy(app)

mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

jwt = JWTManager(app)

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])

CORS(app)

socketio = SocketIO(app, cors_allowed_origins="*",  async_mode='eventlet')

csrf = CSRFProtect()
csrf.init_app(app)

os.environ['TZ'] = 'Africa/Nairobi'

def nairobi_time():
    return datetime.utcnow() + timedelta(hours=3)
    
# ===================================================
#                  >>>> BLUEPRINTS <<<<
# ===================================================

messaging_bp = Blueprint('messaging', __name__, template_folder='templates')

#===================================================
#                   >>>> DATABASE MODELS <<<<
#===================================================

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    mobile = db.Column(db.String(10), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True,  nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')
    created_at = db.Column(db.DateTime, default=nairobi_time)
    profile_image = db.Column(db.String(255), default='/static/default-profile.png')
    location = db.Column(db.String(255), nullable=True)
    agreed = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=False)
    
#---------------------------------------------------
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=True)
    image_url = db.Column(db.String(200), nullable=False)
    imgur_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=nairobi_time)
    category = db.Column(db.String(200), nullable=False)
    
    ratings = db.relationship('Rating', backref='product', lazy=True)

    def get_average_rating(self):
        """Return the average rating (as a float) for the product."""
        if self.ratings:
            total = sum(r.rating for r in self.ratings)
            return total // len(self.ratings)
        return 0

class Product3D(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    model_filename = db.Column(db.String(200), nullable=False)  # GLB file
    stock = db.Column(db.Integer, default=1)

#---------------------------------------------------
class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Ensure a user can rate a product only once
    __table_args__ = (db.UniqueConstraint('user_id', 'product_id', name='_user_product_uc'),)
#---------------------------------------------------
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    quantity = db.Column(db.Integer, nullable=True, default=1)
    total = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(20), default='Pending')
    location = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=nairobi_time)

    user = db.relationship('User', backref='orders')
    product = db.relationship('Product', backref='orders')

    def __repr__(self):
        return f"<Order {self.id}, User {self.user_id}, Product {self.product_id}, Status {self.status}>"
#--------------------------------------------------- 
class UserMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mobile = db.Column(db.String(10), db.ForeignKey('user.mobile'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_from_admin = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=nairobi_time)
    read = db.Column(db.Boolean, default=False)
#---------------------------------------------------
class AdminSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    secret = db.Column(db.String(255), nullable=False, default='479admin479')

    def __repr__(self):
        return f'<AdminSetting {self.secret}>'  
#for the CEOs
class SuperAdminSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    super_secret = db.Column(db.String(255), nullable=False, default='479superadmin479')

    def __repr__(self):
        return f'<SuperAdminSetting {self.secret}>'
#---------------------------------------------------
class About(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shop_name = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.Date, nullable=False)
    description = db.Column(db.Text, nullable=False)
    owner = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(100), nullable=True)
    logo = db.Column(db.String(255), nullable=True)

#-----------------‐-------‐-------------------------

class AdminActivity(db.Model):
    __tablename__ = 'admin_activity'
    
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=nairobi_time,  nullable=True)
    target_type = db.Column(db.String(50),  nullable=True)
    target_id = db.Column(db.Integer,  nullable=True)
    ip_address = db.Column(db.String(45),  nullable=True)
    user_agent = db.Column(db.Text,  nullable=True)

    admin = db.relationship('User', backref=db.backref('admin_activities', lazy='dynamic'))

    __table_args__ = (
        Index('ix_activity_timestamp', 'timestamp'),
        Index('ix_activity_admin', 'admin_id'),
        Index('ix_activity_target', 'target_type', 'target_id'),
    )

#---------------------------------------------------
#              ____INITIALISING DATABASE____

with app.app_context():
    db.create_all()
        
#---------------------------------------------------
#                     ____HELPER FUNCTIONS____

def is_admin():
    return session.get('role') == 'admin'

def logout_user():
    session.clear()
    return redirect(url_for("home"))

@app.route('/is_authenticated')
def is_authenticated():
    user_id = current_user.id
    if user_id in session:
        return jsonify({'authenticated': True})
    return jsonify({'authenticated': False})
    
@app.before_request
def make_session_permanent():
    session.permanent = True        

@app.before_request
def auto_logout_user():
    if current_user.is_authenticated:
        user = User.query.filter_by(id=current_user.id).first()
        if user and user.role != current_user.role:
            logout_user()
            flash("Role has changed. Please log in again.", "error")
            return redirect(url_for('login'))

@app.before_request
def auto_restore_if_empty():
    # Check if the products table is empty
    if Product.query.count() == 0:
        backup_file = os.path.join(app.root_path, 'imgur_backup.json')
        
        # Check if the backup file exists
        if os.path.exists(backup_file):
            try:
                with open(backup_file, 'r') as f:
                    data = json.load(f)
                    
                    # Restore products from the backup
                    for item in data:
                        product = Product(
                            name=item.get("name", "Restored"),
                            description=item.get("description", "Recovered from Imgur backup"),
                            price=item.get("price", 0),
                            image_url="/uploads/missing.jpg",  # Default image for missing ones
                            imgur_url=item.get("imgur_url")
                        )
                        db.session.add(product)
                    
                    db.session.commit()
                    print(f"[✓] Restored {len(data)} products from backup.")
            except Exception as e:
                print(f"[✗] Failed to restore from JSON: {e}")
        else:
            print("[!] Backup file not found.")

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'superadmin']:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'superadmin':
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader  
def load_user(user_id):  
    return User.query.get(int(user_id))       

@app.route('/admin/backup_images')
@admin_required
def backup_images():
    upload_folder = os.path.join(app.root_path, 'static', 'uploads')
    
    # Create in-memory ZIP
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(upload_folder):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, upload_folder)
                zf.write(file_path, arcname)
    
    memory_file.seek(0)
    return send_file(memory_file, mimetype='application/zip',
                     download_name='uploads_backup.zip',
                     as_attachment=True)
    log_admin_activity("[ADMIN BACKUP] Downloaded backup_data")
    
def get_image_url(product):
    import os
    filename = os.path.basename(product.image_url or '')
    local = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if os.path.exists(local):
        return product.image_url
    elif product.imgur_url:
        return product.imgur_url
    else:
        return "/uploads/default.jpg"

def backup_product_to_json(product):
    backup_file = os.path.join(app.root_path, 'imgur_backup.json')
    backup_data = []

    # Load existing backup
    if os.path.exists(backup_file):
        with open(backup_file, 'r') as f:
            try:
                backup_data = json.load(f)
            except Exception:
                pass  # corrupted file or empty

    # Add new entry
    backup_data.append({
        "name": product.name,
        "description": product.description,
        "price": product.price,
        "imgur_url": product.imgur_url
    })

    # Save back
    with open(backup_file, 'w') as f:
        json.dump(backup_data, f, indent=2)
        
@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('uploaded_file', filename='favicon.ico'))
#===================================================

def send_order_email(subject, recipient, subject_title, message_intro, mobile, email, role, active, products):
    total_price = sum([item['price'] * item['quantity'] for item in products])

    msg = Message(
        subject=subject,
        recipients=[recipient],
        html=render_template(
            'order_email.html', 
            mobile=mobile, 
            total_price=total_price, 
            products=products,
            shop_url=url_for('home')  
        )
    )

    try:
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")

@app.route('/admin/send_email', methods=['GET', 'POST'])
@login_required
@admin_required
def send_email():

    users = User.query.all()
    if request.method == 'POST':
        selected_emails = request.form.getlist('emails')  
        subject = request.form.get('subject')
        message = request.form.get('message')

        for email in selected_emails:
            send_email_to_user(subject, email, message)

        flash('Emails sent successfully!', 'success')
        return redirect(url_for('admin_dashboard' if current_user.role == 'admin' else 'super_admin_dashboard')) 

    return render_template('send_email.html', users=users)

def send_email_to_user(subject, recipient, message):
    msg = Message(
        subject=subject,
        recipients=[recipient],
        html=render_template(
            'email_template.html',  
            message=message,
            email=recipient
        )
    )
    try:
        mail.send(msg)  # Send the email using Flask-Mail
    except Exception as e:
        print(f"Error sending email: {e}")

#===================================================    
#---------------------------------------------------
def format_mobile(mobile):
    """Ensure mobile is stored as 07XXXXXXXX format."""
    if len(mobile) == 9 and (mobile.startswith('7') or mobile.startswith('1')):
        return "0" + mobile
    return mobile
#---------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def login():
    if current_user.is_authenticated:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif session.get('role') == 'superadmin':
            return redirect(url_for('super_admin_dashboard'))
        else:
            return redirect(url_for('products'))

    mobile = ""

    if request.method == 'POST':
        raw_mobile = request.form['mobile'].strip()
        mobile = format_mobile(raw_mobile)
        password = request.form['password']
        
        user = User.query.filter_by(mobile=mobile).first()

        if user and check_password_hash(user.password, password):
            if user.role == 'banned':
                flash('⛔ Account banned.', 'error')
                return render_template("banned.html")

            if not user.active:
                flash("⚠️ Account Deactivated", "error")
                return redirect(url_for('login'))
            if not user.email_verified:
                flash('Please verify your email first before logging in.', 'error')
                return render_template('login.html', mobile=raw_mobile)    

            login_user(user)
            session['role'] = user.role
            session['active'] = user.active

            if user.role == 'admin':
                log_admin_activity("[ADMIN LOGIN] logged in.")

            flash("♻ Welcome back!", "success")

            if user.role == 'superadmin':
                return redirect(url_for('super_admin_dashboard'))
            elif user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('products'))

        flash(" nvalid mobile or password", "error")
        return render_template("login.html", mobile=raw_mobile, password=password)

    return render_template('login.html', mobile=mobile)
#---------------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("200 per hour")
def register():
    if request.method == 'POST':
        mbl = request.form['mobile']
        mobile = format_mobile(mbl)
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        location = request.form['location']
        email = request.form['email']
        admin_secret_input = request.form.get('admin_secret')

        # Validation checks
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template('register.html', mobile=mbl, password=password, confirm_password=confirm_password, location=location, email=email)

        if User.query.filter_by(mobile=mobile).first():
            flash("Mobile already exists.", "error")
            return render_template('register.html', mobile=mbl, location=location, email=email)

        if User.query.filter_by(email=email).first():
            flash("Email already exists.", "error")
            return render_template('register.html', mobile=mbl, location=location, email=email)

        if not (email.endswith('@gmail.com') or email.endswith('@yahoo.com')):
            flash('Invalid Email Address.', 'error')
            return render_template('register.html', mobile=mbl, location=location, email=email)

        if not location:
            flash("Location is needed.", "error")
            return render_template('register.html', mobile=mbl, password=password, confirm_password=confirm_password, email=email)

        # Determine role
        admin_setting = AdminSetting.query.first()
        if not admin_setting:
            new_setting = AdminSetting(secret='479admin479')
            db.session.add(new_setting)
            db.session.commit()
            admin_setting = AdminSetting.query.first()

        if admin_setting and admin_secret_input == admin_setting.secret:
            role = 'admin'
        else:
            role = 'user'

        super_admin_setting = SuperAdminSetting.query.first()
        if not super_admin_setting:
            new_setting = SuperAdminSetting(super_secret='479superadmin479')
            db.session.add(new_setting)
            db.session.commit()
            super_admin_setting = SuperAdminSetting.query.first()

        if super_admin_setting and admin_secret_input == super_admin_setting.super_secret:
            role = 'superadmin'

        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(mobile=mobile, password=hashed_password, role=role, location=location, email=email, agreed=True)
        db.session.add(new_user)
        db.session.commit()

        # Send email verification
        send_verification_email(new_user)

        flash("Check your email to finish Registration", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

def generate_email_token(user):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(user.email, salt='email-verification')

def verify_email_token(token, expiration=300):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-verification', max_age=expiration)
    except Exception:
        return None
    return email

def send_verification_email(user):
    token = generate_email_token(user)
    verify_link = url_for('verify_registration', token=token, _external=True)

    msg = Message(
        subject="Verify your T-Give Nexus account",
        recipients=[user.email]
    )
    msg.html = render_template('verify_email_template.html', verify_link=verify_link)

    try:
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send verification email: {e}")

@app.route('/verify_registration/<token>')
def verify_registration(token):
    email = verify_email_token(token)
    if not email:
        flash('Invalid or expired verification link.', 'error')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    user.email_verified=True
    db.session.commit()
    login_user(user)
    flash('Email verified! Welcome to T-Give Nexus.', 'success')
    return redirect(url_for('welcome'))
        
#-------------‐-------------------------------------

@app.route("/welcome")
def welcome():
    return render_template("welcome.html")                                

#===================================================
#               >>>> USERS ENDPOINTS <<<<
#===================================================
from itsdangerous import URLSafeTimedSerializer

def create_reset_token(user):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(user.email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except Exception:
        return None
    return email

@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
            flash('Password reset email sent!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email not found.', 'error')
            return redirect(url_for('login'))

    return render_template('forgot_password.html')

def send_reset_email(user):
    token = create_reset_token(user)
    reset_link = url_for('reset_password', token=token, _external=True)

    msg = Message(
        subject="Password Reset Request",
        sender=("T-Give-3 Nexus", "vinneyjoy1@gmail.com"),
        recipients=[user.email],
    )
    msg.html = render_template('forgot_password_email.html', reset_link=reset_link)
    mail.send(msg)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        hashed_password = generate_password_hash(new_password)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')
#===================================================
@app.route("/home")
@csrf.exempt
def home(): 
    
    products = Product.query.all()
    for product in products:
        product.display_image = get_image_url(product)
    
    return render_template("index.html", products=products)
#------------------------------‐--------------------
@app.route('/HELP')
@csrf.exempt
def HELP():
    return render_template('HELP.html')
#---------------------------------------------------
@app.route('/logout')
def logout():
    if current_user.is_authenticated and current_user.role == 'admin':
        log_admin_activity(f"[ADMIN LOGOUT] logged out")
    else:
        pass
    session.clear()
    flash("Logged out", "success")
    return redirect(url_for('home'))

#---------------------------------------------------
@app.route('/search-suggestions')
@limiter.limit("50 per minute")
def search_suggestions():
    query = request.args.get('q', '').lower()
    if not query:
        return jsonify(results=[])

    results = Product.query.filter(Product.name.ilike(f'%{query}%')).limit(5).all()
    return jsonify(results=[{'id': p.id, 'name': p.name} for p in results])
    
@app.route('/search')
@limiter.limit("20 per minute")
def search_results():
    query = request.args.get('q', '').lower()
    results = Product.query.filter(Product.name.ilike(f'%{query}%')).all()
    return render_template('search.html', products=results, query=query)    

@app.route('/categories')
def categories():
    categories = db.session.query(
        Product.category,
        db.func.count(Product.id)
    ).group_by(Product.category).all()
    return render_template('categories.html', categories=categories)

@app.route('/category/<string:category_name>')
def category_products(category_name):
    products = Product.query.filter_by(category=category_name).all()
    return render_template('category_products.html',
                         category=category_name,
                         category_products=products)

@app.route('/products')
def products():
    all_products = Product.query.limit(30).all()
    
    new_arrivals = Product.query.order_by(Product.created_at.desc()).limit(10).all()
    top_rated = sorted(all_products, key=lambda p: p.get_average_rating(), reverse=True)[:10]
    
    categories = db.session.query(Product.category).distinct().all() 
    
    category_products = {}
    for cat_tuple in categories:
        category_name = cat_tuple[0]
        products = Product.query.filter_by(category=category_name).all()
        if products:
            category_products[category_name] = products
    
    suggestions = [{'id': p.id, 'name': p.name} for p in all_products]

    return render_template(
        'products.html',
        new_arrivals=new_arrivals,
        top_rated=top_rated,
        all_products=all_products,
        category_products=category_products,
        suggestions=suggestions  
    )
    
@app.route('/product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def product_details(product_id):
    product = Product.query.options(joinedload(Product.ratings)).get(product_id)

    if request.method == 'POST' and request.is_json:
        rating_value = request.json.get('rating')
        
        if rating_value:
            try:
                rating_value = int(rating_value)
            except ValueError:
                return jsonify({'success': False, 'message': 'Invalid rating value.'}), 400

            if rating_value < 1 or rating_value > 5:
                return jsonify({'success': False, 'message': 'Rating must be between 1 and 5.'}), 400

            existing_rating = Rating.query.filter_by(product_id=product_id, user_id=current_user.id).first()
            if existing_rating:
                message = "Your rating has been updated."
            else:
                new_rating = Rating(rating=rating_value, product_id=product_id, user_id=current_user.id)
                db.session.add(new_rating)
                message = "Thank you for your rating!"

            db.session.commit()
            
            average_rating = product.get_average_rating()
            return jsonify({'success': True, 'message': message, 'average_rating': average_rating})

        return jsonify({'success': False, 'message': 'Rating value is required.'}), 400

    user_rating = Rating.query.filter_by(product_id=product_id, user_id=current_user.id).first()
    average_rating = product.get_average_rating()

    return render_template('product_details.html', product=product, user_rating=user_rating, average_rating=average_rating)

#---------------------------------------------------

@app.route('/showroom/<int:product3d_id>')
def showroom(product3d_id):
    product = Product3D.query.get_or_404(product3d_id)
    return render_template('showroom.html', product=product)

@app.route('/products3d')
def products3d():
    products = Product.query.all()
    return render_template('products3D.html', products=products)

@app.route('/add_to_cart_3d/<int:product3d_id>', methods=['POST'])
@login_required
def add_to_cart_3d(product3d_id):
    product = Product3D.query.get_or_404(product3d_id)

    cart = session.get('cart3d', {})
    cart[str(product3d_id)] = cart.get(str(product3d_id), 0) + 1
    session['cart3d'] = cart

    flash(f"{product.name} added to your 3D cart!", "success")
    return redirect(url_for('showroom', product3d_id=product3d_id))

@app.route('/cart3d')
@login_required
def cart3d():
    cart = session.get('cart3d', {})
    items = []
    total = 0
    for product_id, quantity in cart.items():
        product = Product3D.query.get(int(product_id))
        if product:
            items.append({
                'id': product.id,
                'name': product.name,
                'price': product.price,
                'quantity': quantity
            })
            total += product.price * quantity
    return render_template('cart3d.html', cart_items=items, total=total)

@app.route('/checkout3d')
@login_required
def checkout3d():
    cart = session.get('cart3d', {})
    total = 0
    for product_id, quantity in cart.items():
        product = Product3D.query.get(int(product_id))
        if product:
            total += product.price * quantity
    return render_template('checkout3d.html', total=total)

@app.route('/complete_checkout3d', methods=['POST'])
@login_required
def complete_checkout3d():
    session.pop('cart3d', None)
    flash("✅ 3D Order Successful! Thank you.", "success")
    return redirect(url_for('products3d'))

import uuid
@app.route('/upload_product3d', methods=['GET', 'POST'])
@login_required
def upload_product3d():
    if current_user.role not in ['admin', 'superadmin']:
        abort(403)

    if request.method == 'POST':
        try:
            # Ensure 'uploads' directory exists
            os.makedirs('uploads', exist_ok=True)
            
            # Get form data
            name = request.form['name']
            description = request.form['description']
            price = float(request.form['price'])
            stock = int(request.form['stock'])
            model_file = request.files['model_file']

            if model_file:
                filename = secure_filename(model_file.filename)
                file_ext = os.path.splitext(filename)[1].lower()
                
                if file_ext == '.fbx':  # Changed from .glb to .fbx
                    # Generate unique filename to prevent collisions
                    unique_filename = f"{uuid.uuid4().hex}{file_ext}"
                    save_path = os.path.join('uploads', unique_filename)
                    
                    # Save file
                    model_file.save(save_path)

                    # Create database record
                    new_product = Product3D(
                        name=name,
                        description=description,
                        price=price,
                        stock=stock,
                        model_filename=unique_filename  # Store unique filename
                    )
                    db.session.add(new_product)
                    db.session.commit()

                    flash('FBX model uploaded successfully!', 'success')
                    return redirect(url_for('products3d'))
                else:
                    flash('Only .fbx files are accepted', 'error')
            else:
                flash('No file selected', 'error')

        except Exception as e:
            db.session.rollback()
            flash(f'Upload failed: {str(e)}', 'error')

    return render_template('upload_product3d.html')
#---------------------------------------------------
def get_cart():
    if 'cart' not in session:
        session['cart'] = {}
    return session['cart']

@app.route('/cart')
def cart():
    cart = session.get('cart', {})
    cart_items = []
    total_price = 0

    for product_id, quantity in cart.items():
        product = Product.query.get(product_id)
        if product:
            item_total = product.price * quantity
            cart_items.append({
                'product_id': product.id,
                'name': product.name,
                'price': product.price,
                'quantity': quantity,
                'image_url': product.image_url,
                'description': product.description
            })
            total_price += item_total

    return render_template('cart.html', cart=cart_items, total_price=total_price)

#ADD TO CART
@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    data = request.json
    product_id = str(data.get('product_id'))
    quantity = abs(int(data.get('quantity', 1)))
    if quantity == int('0'):
        message = "Quantity not Valid!."
        return redirect("products")

    cart = get_cart()

    if product_id in cart:
        cart[product_id] += quantity
        message = "Added  to cart"
    else:
        cart[product_id] = quantity

    session.modified = True
    message = "Added to cart"
    return jsonify({'success': True, 'cart': cart, 'message': message})
    
# Update Cart Quantity
@app.route('/update_cart', methods=['POST'])
@limiter.limit("45 per minute")
def update_cart():
    data = request.json
    product_id = str(data.get('product_id'))
    change = int(data.get('change'))

    cart = get_cart()
    if product_id in cart:
        cart[product_id] = max(1, cart[product_id] + change)  # Prevent 0 or negative quantity

    session.modified = True
    return jsonify({'success': True, 'cart': cart})
    

# Remove from Cart
@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    cart = get_cart()
    product_id_str = str(product_id)

    if product_id_str in cart:
        del cart[product_id_str]
        session.modified = True
        flash('Removed', 'success')
        return jsonify({'success': True, 'message': 'Remove'})
   
    return jsonify({'success': False, 'message': 'Product not in cart'})

#---------------------------------------------------
@app.route("/non_users")
@csrf.exempt
def non_users():
    return render_template("non_users.html")
#---------------------------------------------------
@app.route('/order_summary')
@login_required
def order_summary():
    user_id = current_user.id
    user = User.query.get_or_404(user_id)
    if user.role != 'user':
        return redirect(url_for("non_users"))
    cart = session.get('cart', {})

    if not cart:
        flash('Cart is empty')
        return redirect(url_for('products'))

    orders = []
    total_price = 0

    for product_id, quantity in cart.items():
        product = Product.query.get(int(product_id))
        if product:
            item_total = product.price * quantity
            total_price += item_total
            orders.append({
                'name': product.name,
                'quantity': quantity,
                'price': product.price,
                'total': item_total
            })

    return render_template('order_summary.html', orders=orders, total_price=total_price)
#---------------------------------------------------
@app.route('/order_confirmation')
@csrf.exempt
def order_confirmation():
    return render_template('order_confirmation.html')
#---------------------------------------------------
@app.route('/thank_you')
@csrf.exempt
def thank_you():
    return render_template('thank_you.html')
#---------------------------------------------------
@app.route('/place_order', methods=['POST'])
@limiter.limit("50 per minute")
@login_required  
def place_order():
    user_id = current_user.id
    user = User.query.get_or_404(user_id)

    if user.role != 'user':
        return redirect(url_for('non_users'))

    cart = session.get('cart', {})
    if not cart:
        flash('Cart is empty', 'error')
        return redirect(url_for('cart'))

    if user.role == 'banned':
        return render_template("banned.html")

    try:
        orders = []
        email_products = []  # << for email, independent

        # For each product in the cart, process it
        for product_id, quantity in cart.items():
            product = Product.query.get(int(product_id))
            if product and product.stock >= quantity:  # Check if stock is sufficient
                new_order = Order(
                    user_id=user_id,
                    product_id=product.id,
                    location=current_user.location,
                    quantity=quantity,
                    total=product.price * quantity,
                    status='Pending'
                )
                db.session.add(new_order)

                # For Email
                email_products.append({
                    'name': product.name,
                    'description': product.description,
                    'price': product.price,
                    'quantity': quantity,
                    'image_url': product.image_url
                })

                # For Confirmation page
                orders.append({
                    'name': product.name,
                    'quantity': quantity,
                    'price': product.price,
                    'total': product.price * quantity
                })

                # Update stock before committing
                product.stock = int(product.stock - quantity)

        db.session.commit()
        session.pop('cart', None)

        flash("Order Placed!", "success")

        # Sending email independently
        try:
            send_order_email(
                subject="Order Confirmation",
                recipient=current_user.email,
                subject_title="Order Successful!",
                message_intro="Thanks for your Purchase!",
                mobile=current_user.mobile,
                email=current_user.email,
                role=current_user.role,
                active=current_user.active,
                products=email_products
            )
        except Exception as e:
            print("Error sending email:", e)
            flash("Your order was placed, but there was an issue sending the confirmation email.", "warning")

        return render_template('order_confirmation.html', orders=orders)

    except IntegrityError as e:
        db.session.rollback()
        print("Database error:", e)
        flash("An error occurred, Order not placed", "error")
        return redirect(url_for('cart'))
#---------------------------------------------------
@app.route('/checkout')
@csrf.exempt
def checkout():
    return render_template('checkout.html') 
#---------------------------------------------------
@app.route('/order_history')
@csrf.exempt
def order_history():
    user_id = current_user.id
    user = User.query.get_or_404(user_id)
    if user.role != 'user':
        return redirect(url_for("non_users"))
    
    orders = Order.query.filter_by(user_id=user_id).order_by(Order.id.desc()).all()

    return render_template('order_history.html', orders=orders)
#---------------------------------------------------

@app.route('/contact')
@csrf.exempt
def contact():
    return render_template('contact.html')
#---------------------------------------------------
@app.route('/details')
@csrf.exempt
def details():
    return render_template('details.html')
#---------------------------------------------------
@app.route('/payment_success')
def payment_success():
    return render_template('payment_success.html') 
#---------------------------------------------------
@app.route('/privacy')
@csrf.exempt
def privacy():
    return render_template('privacy.html')
#---------------------------------------------------
@app.route('/services')
@csrf.exempt
def services():
    return render_template('services.html')
#---------------------------------------------------
@app.route("/update_user")
@login_required
@csrf.exempt
def update_user():
    return render_template("user_settings.html")
#---------------------------------------------------
@app.route('/dashboard', methods=['GET'])
@csrf.exempt
@login_required
def user_dashboard():
    user = User.query.filter_by(id=current_user.id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    if user.role != 'user':
        return redirect(url_for("non_users"))

    #unread_message_count = UserMessage.query.filter_by(sender_id=current_user.id, read=True).count()

    user_order_count = Order.query.filter_by(user_id=current_user.id).count()

    cart_item_count = len(session.get('cart', {}))

    user_orders = Order.query.filter_by(user_id=current_user.id).all()
    cart = session.get('cart', {})

    return render_template('user_dashboard.html', 
                           user=user, 
                           user_order_count=user_order_count,
                           cart_count=cart_item_count,
                           user_orders=user_orders, 
                           cart=cart)

#-------------------------‐--------------------------

@app.route("/profile")  
@login_required  
def profile():  
    return render_template("profile.html", user=current_user)  

# Allowed file extensions for profile picture
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Set the maximum content length for uploaded files (16MB)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Allowed file extensions in the upload folder
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.jpeg', '.gif']

# Set the upload folder path
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create the upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Update profile picture route
@app.route("/update_profile_pic", methods=["POST"])
@limiter.limit("10 per minute")
@login_required
def update_profile_pic():
    if 'profile_pic' not in request.files:
        flash("No file uploaded!", "error")
        return redirect(url_for("profile"))

    file = request.files['profile_pic']  
    
    if file.filename == '':  
        flash("No selected file!", "error")  
        return redirect(url_for("account" if current_user.role == 'admin' or current_user.role=='superadmin' else "profile"))

    if file and allowed_file(file.filename):  
        filename = secure_filename(file.filename)  
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)  
        file.save(file_path)  

        # Update user profile image
        current_user.profile_image = f"/uploads/{filename}"   
        db.session.commit()  

        flash("Profile picture updated!", "success")  
    else:  
        flash("⚠️ Invalid file type! Only PNG, JPG, JPEG allowed.", "error")

    return redirect(url_for("account" if current_user.role == 'admin' or current_user.role=='superadmin' else "profile"))

# LOCATION UPDATE
@app.route("/update_location", methods=["POST"])
@limiter.limit("10 per minute")
@login_required
def update_location():
    location = request.form.get("location")
    if location:
        current_user.location = location
        db.session.commit()
        flash("Location updated!", "success")
    else:
        flash("Location cannot be empty!", "error")

    return redirect(url_for("account" if current_user.role == 'admin' or current_user.role=='superadmin' else 'profile'))    

# EMAIL UPDATE
@app.route("/update_email", methods=["POST"])
@limiter.limit("10 per minute")
@login_required
def update_email():
    email = request.form.get("email") 
    if email.endswith('@gmail.com') or email.endswith('@yahoo.com'):
        try:
            current_user.email = email
            db.session.commit()
            flash('Email updated', 'success')
        except IntegrityError as e:
            flash("Email already exists")
            return render_template('admin_account.html' if current_user.role == 'admin' else 'profile.html')
    else:
        flash('Invalid Email')
        return redirect(url_for("account" if current_user.role == 'admin' or current_user.role=='superadmin' else 'profile'))
        
    return redirect(url_for("account" if current_user.role == 'admin' or current_user.role=='superadmin' else 'profile'))
#---------------------------------------------------
#              ____ACCOUNT SETTINGS PAGE____

@app.route("/account")
@login_required
def account_settings():
    user = User.query.get_or_404(current_user.id)
    return render_template("account.html", user=user)

#CHANGE PASSWORD
@app.route("/change_password", methods=["POST"])
@limiter.limit("20 per minute")
@login_required
def change_password():
    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")
    confirm_new_password = request.form.get("confirm_new_password")

    if not check_password_hash(current_user.password, current_password):
        flash("Incorrect current password!", "error")
        return redirect(url_for("account" if current_user.role == 'admin' else 'account_settings'))

    if new_password != confirm_new_password:
        flash("New passwords do not match!", "error")
        return redirect(url_for("account" if current_user.role == 'admin' else 'account_settings'))

    current_user.password = generate_password_hash(new_password)
    db.session.commit()
    flash("Password changed!", "success")

    return redirect(url_for("account_settings"))

#DELETE ACCOUNT
@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    delete_password = request.form.get("delete_password")

    if not check_password_hash(current_user.password, delete_password):
        flash("Incorrect password! Account not deleted.", "error")
        return redirect(url_for("account" if current_user.role == 'admin' else 'account_settings'))

    db.session.delete(current_user)
    db.session.commit()
    
    flash("Account deleted!", "success")
    return redirect(url_for("login"))

# ===================================================
#                  >>>> MESSAGING ROUTES <<<<
# ===================================================
def is_from_admin():
    return 'admin' == True

@messaging_bp.route('/messages', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@csrf.exempt
@login_required
def messages():
    if current_user.role == 'user':
        if request.method == 'POST':
            content = request.form['content']
            if content.strip():
                msg = UserMessage(
                    sender_id=current_user.id,
                    message=content,
                    is_from_admin=False,
                    mobile=current_user.mobile
                )
                db.session.add(msg)
                db.session.commit()
                flash("Message sent.", "success")
        msgs = UserMessage.query.filter(
            ((UserMessage.sender_id == current_user.id) & (UserMessage.is_from_admin == False)) |
            ((UserMessage.is_from_admin == True) & (UserMessage.mobile == current_user.mobile))
        ).order_by(UserMessage.timestamp).all()
        return render_template('messaging_user.html', messages=msgs, user=current_user)
    else:
        users = User.query.filter_by(role='user').all()
        unread_counts = {
            u.id: UserMessage.query.filter_by(sender_id=u.id, read=False, is_from_admin=False).count()
            for u in users
        }
        return render_template('messaging_admin.html', users=users, unread_counts=unread_counts, admin=current_user)

@messaging_bp.route('/messages/<int:user_id>', methods=['GET', 'POST'])
@csrf.exempt
@login_required
def admin_chat(user_id):
    if current_user.role != 'admin':
        flash("Unauthorized.", "danger")
        return redirect(url_for('messaging.messages'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        content = request.form['content']
        if content.strip():
            reply = UserMessage(
                sender_id=current_user.id,
                message=content,
                is_from_admin=True,
                mobile=user.mobile  # Set to the user's mobile to target the reply
            )
            db.session.add(reply)
            db.session.commit()
            log_admin_activity(f"Sent message to user #{user_id}", 'message', user_id)
            flash("Reply sent.", "success")
        return redirect(url_for('messaging.admin_chat', user_id=user_id))
    msgs = UserMessage.query.filter(
        ((UserMessage.sender_id == user.id) & (UserMessage.is_from_admin == False)) |
        ((UserMessage.is_from_admin == True) & (UserMessage.mobile == user.mobile))
    ).order_by(UserMessage.timestamp).all()
    return render_template('messaging_admin_room.html', messages=msgs, user=user, admin=current_user)

@messaging_bp.route('/admin/mark_read/<int:user_id>')
@csrf.exempt
@login_required
def mark_read(user_id):
    if current_user.role != 'admin':
        return "", 403
    msgs = UserMessage.query.filter_by(sender_id=user_id, read=False, is_from_admin=False).all()
    for m in msgs:
        m.read = True
    db.session.commit()
    log_admin_activity(f"[ADMIN MARKED_READ] Marked message from #{user_id} as read", 'message', user_id)
    return "", 204

@socketio.on('join_room')
@csrf.exempt
def handle_join_room(data):
    join_room(str(data['user_id']))

@socketio.on('send_message')
@limiter.limit("20 per minute")
@csrf.exempt
def handle_send_message(data):
    msg = data['message']
    sender_id = data['sender_id']
    mobile = data['mobile']
    is_from_admin = data.get('is_from_admin', False)
    new_msg = UserMessage(
        sender_id=sender_id,
        message=msg,
        is_from_admin=is_from_admin,
        mobile=mobile,
        timestamp=datetime.utcnow() + timedelta(hours=3)
    )
    db.session.add(new_msg)
    db.session.commit()
    room = str(data.get('receiver_id')) if is_from_admin else str(sender_id)
    emit('receive_message', {
        'message': msg,
        'sender_id': sender_id,
        'mobile': mobile,
        'is_from_admin': is_from_admin,
        'timestamp': new_msg.timestamp.strftime("%H:%M")
    }, room=room)

#===================================================

#---------------------------------------------------
app.register_blueprint(messaging_bp)
#---------------------------------------------------

@app.route('/about')
@csrf.exempt
def about():
    about_info = About.query.first()
    return render_template('about.html', about=about_info)

#===================================================
#                       >>>>ADMIN ENDPOINTS<<<<<
#===================================================

@app.route('/admin/db_storage_neon')
@admin_required 
def db_storage_neon():
    try:
        conn = pg8000.connect(
            user="tgive3_owner",
            password="npg_0ZwEQleozq3O",
            host="ep-snowy-silence-a8kfnz7h-pooler.eastus2.azure.neon.tech",
            database="tgive3",
            ssl_context=True
        )
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
              table_schema || '.' || table_name AS table,
              pg_size_pretty(pg_total_relation_size(table_schema || '.' || table_name)) AS size
            FROM information_schema.tables
            WHERE table_schema = 'public'
            ORDER BY pg_total_relation_size(table_schema || '.' || table_name) DESC
        """)
        table_sizes = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('admin_storage.html', tables=table_sizes)
        log_admin_activity("[ADMIN VIEW DB] Viewed database storage")
    except Exception as e:
        return f"<h3>Error: {e}</h3>"


import requests

# Xata API endpoint and API key
XATA_API_URL = "https://vinney560-s-workspace-utg7k3.us-east-1.xata.sh/db/tgive3:main/query"
XATA_API_KEY = "xau_lpoTy0N9vEJVZXEe7XUMZcL0xdKvxjgs2"  # Your API key

@app.route('/admin/db_storage_xata')
@admin_required
def db_storage_xata():
    try:
        # Prepare headers with the correct API key for authentication
        headers = {
            "Authorization": f"Bearer {XATA_API_KEY}",
            "Content-Type": "application/json"
        }

        # Sample SQL-like query to fetch table information from Xata
        query = {
            "query": """
                SELECT table_name, COUNT(*) AS num_rows
                FROM information_schema.tables
                WHERE table_schema = 'public'
                GROUP BY table_name
                ORDER BY num_rows DESC;
            """
        }

        # Send the POST request to Xata API
        response = requests.post(XATA_API_URL, json=query, headers=headers)
        
        # Raise an error for 4xx/5xx responses
        response.raise_for_status()
        
        # Parse the JSON response
        table_sizes = response.json()

        # Render the results in the admin storage page
        return render_template('admin_storage.html', tables=table_sizes['rows'])

    except requests.exceptions.RequestException as e:
        # Return an error message with full response for debugging
        return f"<h3>Error: {str(e)}</h3><br>Response: {e.response.text}"

    log_admin_activity("[ADMIN VIEW DB] Viewed database storage")
#===================================================
#===================================================

@app.route('/admin/dashboard')
@admin_required
@csrf.exempt
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/super_admin/dashboard')
@superadmin_required
def super_admin_dashboard():
    return render_template('super_admin_dashboard.html')
#---------------------------------------------------

@app.route('/admin/quick_view')
@admin_required
def quick_view():
    log_admin_activity("[ADMIN VIEW] Viewed web's activities")
    return render_template('admin_quick_view.html')

# API Endpoints
@app.route('/api/admin/orders')
@admin_required
def api_orders():
    orders = Order.query.order_by(Order.id.desc()).limit(25).all()
    return jsonify([format_order(o) for o in orders])

@app.route('/api/admin/users')
@admin_required
def api_users():
    users = User.query.order_by(User.id.desc()).limit(20).all()
    return jsonify([format_user(u) for u in users])

@app.route('/api/admin/admins')
@admin_required
def api_admins():
    admins = User.query.filter_by(role='admin').all()
    return jsonify([format_admin(a) for a in admins])

@app.route('/api/admin/products')
@admin_required
def api_products():
    products = Product.query.order_by(Product.id.desc()).limit(25).all()
    return jsonify([format_product(p) for p in products])

# Data formatters
def format_order(order):
    return {
        'id': order.id,
        'user_mobile': order.user.mobile if order.user else 'Unknown',
        'product_name': order.product.name if order.product else 'Unavailable',
        'quantity': order.quantity,
        'status': order.status,
        'created_at': order.created_at,
        'location': order.location
    }

def format_user(user):
    return {
        'id': user.id,
        'mobile': user.mobile,
        'agreed': user.agreed,
        'active': user.active,
        'role': user.role
    }

def format_admin(admin):
    return {
        'id': admin.id,
        'mobile': admin.mobile
    }

def format_product(product):
    return {
        'id': product.id,
        'name': product.name,
        'price': f"Ksh {product.price}",
        'stock': product.stock
    }

#---------------------------------------------------

@app.route('/admin/panel')
@superadmin_required
def admin_panel():    
    users = User.query.order_by(User.id.desc()).all()
    products=Product.query.order_by(Product.id.desc()).all()
    orders=Order.query.order_by(Order.id.desc()).all()
    
    log_admin_activity("[ADMIN VIEW] Viewed Panel")
   
    return render_template('admin_panel.html', users=users, products=products,  orders=orders)

#---------------------------------------------------
#                             ____SHOP SETTINGS____

@app.route('/admin/admin_about', methods=['GET', 'POST'])
@admin_required
def admin_about():
    about = About.query.first()
    secret_path = 'admin_secret.txt'

    if request.method == 'POST':  
        if not about:  
            about = About()  

        # Update shop info  
        about.shop_name = request.form.get('shop_name').strip()
        about.date_created = datetime.strptime(request.form.get('date_created'), '%Y-%m-%d').date()
        about.description = request.form.get('description').strip()
        about.owner = request.form.get('owner').strip()
        about.contact = request.form.get('contact').strip()

        # Validate required fields before committing to the DB
        if not about.shop_name or not about.description or not about.owner:
            flash("Please fill in all required fields!", "danger")
            return redirect(url_for('admin_about'))

        # Handle logo upload (optional)  
        if 'logo' in request.files:  
            logo = request.files['logo']  
            if logo.filename:  
                # Validate logo file extension
                allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif']
                filename = secure_filename(logo.filename)
                ext = os.path.splitext(filename)[1].lower()
                
                if ext not in allowed_extensions:
                    flash("Invalid logo file format!", "danger")
                    return redirect(url_for('admin_about'))

                # Construct path and save the logo
                logo_path = os.path.join('static', 'uploads', filename)
                os.makedirs(os.path.dirname(logo_path), exist_ok=True)
                logo.save(logo_path)  
                about.logo = logo_path  

        # Handle secret code change  
        current_code = request.form.get('current_code')  
        new_code = request.form.get('new_code')

        if current_code and new_code:  
            if os.path.exists(secret_path):  
                with open(secret_path, 'r') as f:  
                    saved_code = f.read().strip()  
                if current_code == saved_code:  
                    with open(secret_path, 'w') as f:  
                        f.write(new_code.strip())  
                    flash("Secret code updated successfully!", "success")  
                    log_admin_activity("[ADMIN] Updated Secret Code", 'system')  
                else:  
                    flash("Incorrect current secret code!", "danger")  
                    return redirect(url_for('admin_about'))  
            else:  
                # If the file doesn't exist, create it with new code  
                with open(secret_path, 'w') as f:  
                    f.write(new_code.strip())  
                flash("Secret code file created and saved!", "success")  
                log_admin_activity("[ADMIN] Created initial Secret Code", 'system')  

        # Commit the shop details changes
        db.session.add(about)  
        db.session.commit()  
        log_admin_activity(f"[ADMIN UPDATE SHOP_DETAILS] Updated shop information", 'system')  
        flash("Settings updated successfully!", "success")  
        return redirect(url_for('admin_about'))  

    return render_template('admin_about.html', about=about)
#---------------------------------------------------

@app.route("/admin/admin_settings")
@superadmin_required
def admin_settings():
    admin_setting = AdminSetting.query.first()
    return render_template('admin_settings.html', admin_secret=admin_setting.secret if admin_setting else '')

@app.route("/admin/super_admin_settings")
@superadmin_required
def super_admin_settings():
    super_admin_setting = SuperAdminSetting.query.first()
    return render_template('super_admin_settings.html', admin_secret=super_admin_setting.super_secret if super_admin_setting else '')
#--------------------------------------------------

@app.route('/admin_secret', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
@superadmin_required
def admin_secret():
    admin_setting = AdminSetting.query.first()

    if request.method == 'POST':
        current_secret = request.form.get('current_secret')
        new_secret = request.form.get('new_secret')

        if not admin_setting:
            flash("Admin setting not initialized.", "error")
            return redirect(url_for('admin_secret'))

        stored_secret = admin_setting.secret
        is_hashed = stored_secret.startswith('pbkdf2:')

        # Check if the current secret matches
        valid = check_password_hash(stored_secret, current_secret) if is_hashed else current_secret == stored_secret

        if not valid:
            flash("Incorrect current admin secret.", "error")
            return redirect(url_for('admin_secret'))

        if not new_secret or len(new_secret.strip()) < 6:
            flash("New secret must be at least 6 characters.", "error")
            return redirect(url_for('admin_secret'))

        # Always hash the new secret
        admin_setting.secret = generate_password_hash(new_secret.strip())
        db.session.commit()

        log_admin_activity("[SUPERADMIN] Updated Admin secret", 'system')
        flash("Admin secret updated successfully!", "success")
        return redirect(url_for('admin_secret'))

    return render_template('admin_settings.html')

from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/super_admin_secret', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
@superadmin_required
def super_admin_secret():
    super_admin_setting = SuperAdminSetting.query.first()

    if request.method == 'POST':
        current_secret = request.form.get('current_secret')
        new_secret = request.form.get('new_secret')

        if not super_admin_setting:
            flash("Super admin setting not initialized.", "error")
            return redirect(url_for('super_admin_secret'))

        stored_secret = super_admin_setting.super_secret
        is_hashed = stored_secret.startswith('pbkdf2:')

        # Validate current secret
        valid = check_password_hash(stored_secret, current_secret) if is_hashed else current_secret == stored_secret

        if not valid:
            flash("Incorrect current super admin secret.", "error")
            return redirect(url_for('super_admin_secret'))

        if not new_secret or len(new_secret.strip()) < 6:
            flash("New secret must be at least 6 characters.", "error")
            return redirect(url_for('super_admin_secret'))

        # Save hashed secret
        super_admin_setting.super_secret = generate_password_hash(new_secret.strip())
        db.session.commit()

        log_admin_activity("[SUPERADMIN] Updated Super Admin secret", 'system')
        flash("Super Admin secret updated successfully!", "success")
        return redirect(url_for('super_admin_secret'))

    return render_template('super_admin_settings.html')

#---------------------------------------------------
#                          ____MESSAGING ROUTES____

#---------------------------------------------------
#                         ____MANAGE USERS____

@app.route('/admin/manage_users')
@admin_required
def manage_users():
    if current_user.role == 'superadmin':
        users = User.query.filter(User.id != current_user.id).all()
    else:
        users = User.query.filter_by(role='user').filter(User.id != current_user.id).all()
    return render_template('admin_manage_users.html', users=users)

#BAN USER
@app.route('/admin/ban-user/<int:user_id>', methods=['POST'])
@limiter.limit("10 per minute")
@admin_required
def admin_ban_user(user_id):
    user = User.query.get_or_404(user_id)
    if current_user.id == user.id:
        flash('Can not BAN yourself', 'error')
        return redirect(url_for('manage_users'))
    if user.role == 'superadmin':
        flash("NOT ALLOWED!")
        return redirect(url_for('manage_users'))
    if user.role == 'banned':
        flash('User already Banned', 'error')
        return redirect(url_for('manage_users'))
    user.role='banned'
    user.active=False
    db.session.commit()
    log_admin_activity(f"[ADMIN BANNED] Banned user {user.mobile}", 'user', user.id)
    flash(f"User {user.mobile} banned", "success")
    return redirect(url_for('manage_users'))

#UNBAN USER
@app.route('/admin/unban-user/<int:user_id>', methods=['POST'])
@limiter.limit("10 per minute")
@admin_required
def admin_unban_user(user_id):
    user = User.query.get_or_404(user_id)
    if current_user.id == user.id:
        flash('Can not UNBAN yourself', 'error')
        return redirect(url_for('manage_users'))
    if user.role == 'admin' or user.role == 'user' or user.active == True or user.role == 'superadmin':
        flash('User was never Banned')
        return redirect('manage_users', 'danger')    
    user.role='user'
    user.active=True
    db.session.commit()
    log_admin_activity(f"[ADMIN UNBAN] Unbanned user {user.mobile}", 'user', user.id)
    flash(f"User {user.mobile} unbanned", "success")
    return redirect(url_for('manage_users'))
    
#DELETE USER
@app.route('/admin_delete_user/<int:user_id>', methods=['POST'])
@limiter.limit("10 per minute")
@admin_required
def admin_delete_user(user_id):
    user=User.query.get_or_404(user_id)
    if user.role == 'superadmin':
        flash("NOT ALLOWED!")
        return redirect(url_for('manage_users'))
    if current_user.id == user.id:
        flash('Can not DELETE yourself', 'error')
        log_admin_activity("[ADMIN FORGE DELETE] Tried to Delete him/herself",  'user', user.id)
        return redirect(url_for('manage_users'))
    db.session.delete(user)
    db.session.commit()
    log_admin_activity(f"[ADMIN DELETE] Deleted user {user.mobile}", 'user', user.id)
    flash(f"User {user.mobile} deleted.", "success")
    return redirect(url_for('manage_users'))

#PROMOTE USER
@app.route('/admin_promote_user/<int:user_id>', methods=['POST'])
@limiter.limit("10 per minute")
@superadmin_required
def admin_promote_user(user_id):
    user=User.query.get_or_404(user_id)
    if current_user.id == user.id:
        flash('Can not PROMOTE yourself', 'error')
        log_admin_activity("[ADMIN FORGE PROMOTE] Tried to promote him/herself",  'user',  user.id)
        return redirect(url_for('manage_users'))
    if user.role == 'admin':
        flash('User already Admin',  'error')
        user.role='superadmin'
        user.active=True
        db.session.commit()
        flash("User Super Admin", "success")
        return redirect(url_for('manage_users'))
    if user.role == 'banned':
        flash('User was Banned', 'error')
        return redirect(url_for('manage_users'))
    user.role='admin'
    user.active=True
    db.session.commit()
    log_admin_activity(f"[SUPER ADMIN PROMOTE] Promoted {user.mobile} to admin", 'user', user.id)
    flash(f"User {user.mobile} will be an admin", "success")
    return redirect(url_for('manage_users'))

#DEMOTE ADMIN
@app.route('/admin_demote_user/<int:user_id>', methods=['POST'])
@limiter.limit("20 per minute")
@superadmin_required
def admin_demote_user(user_id):
    user=User.query.get_or_404(user_id)
    if current_user.id == user.id:
        flash('Can not DEMOTE yourself', 'error')
        log_admin_activity("[ADMIN FORGE DEMOTE] Tried to demote him/herself", 'user', user.id)
        return redirect(url_for('manage_users'))
    if user.role == 'user':
        flash('User already User', 'error')
        return redirect(url_for('manage_users'))
    if user.role == 'banned':
        flash('User was Banned', 'error')
        return redirect(url_for('manage_users'))
    user.role='user'
    user.active=True
    db.session.commit()
    log_admin_activity(f"[ADMIN DEMOTE] Demoted: {user.mobile} to user", ' user', user.id)
    flash(f"User {user.mobile} is now a user.", "success")
    return redirect(url_for ("manage_users"))
    
#Deactivate User|ADMIN
@app.route('/admin_deactivate_user/<int:user_id>', methods=['POST']) 
@limiter.limit("10 per minute")
def admin_deactivate_user(user_id):
    user = User.query.get_or_404(user_id)
    if current_user.id == user.id:
        flash('Can not DEACTIVATE yourself', 'error')
        log_admin_activity("[ADMIN FORGE DEACTIVATE] Tried to activate him/herself",  'user', user.id)
        return redirect(url_for('manage_users'))
    if user.active == False and user.role == 'inactive':
        flash('User already inactive', 'error')
        return redirect(url_for('manage_users'))
    if user.role == 'superadmin':
        flash("NOT ALLOWED!")
        return redirect(url_for('manage_users'))
    user.active = False
    user.role = 'inactive'
    db.session.commit()
    log_admin_activity(f"[ADMIN DEACTIVATE] Deactivated: {user.mobile}", 'user', user.id)
    flash(f"User {user.mobile} is deactivated", "success")
    return redirect(url_for('manage_users'))

#Activate User|ADMIN
@app.route('/admin_activate_user/<int:user_id>', methods=['POST']) 
@limiter.limit("20 per minute")
def admin_activate_user(user_id):
    user = User.query.get_or_404(user_id)
    if current_user.id == user.id:
        flash('Can not ACTIVATE yourself', 'error')
        log_admin_activity("[ADMIN FORGE ACTIVATE] Tried to activate him/herself", 'user', user.id)
        return redirect(url_for('manage_users'))
    if user.role == 'banned':
        flash('User was Banned', 'error')
        return redirect(url_for('manage_users'))
    if user.active == True and (user.role == 'user' or user.role == 'admin' or user.role == 'superadmin'):
        flash('User already Active', 'error')
        return redirect(url_for('manage_users'))
    user.active = True
    user.role = 'user'
    db.session.commit()
    log_admin_activity(f"[ADMIN ACTIVATE] Activated: {user.mobile}", 'user', user.id)
    flash(f"User {user.mobile} is activated", "success")
    return redirect(url_for('manage_users'))

#----------------------------------------------------

@app.route('/admin/manage_emails')
@admin_required
@csrf.exempt
def manage_emails():       
    users = User.query.all()
    log_admin_activity("[ADMIN VIEW] Viewed Emails")
    return render_template('admin_manage_emails.html', users=users)

#---------------------------------------------------
#                              ____PRODUCTS_____

@app.route("/admin/products")
@admin_required
@csrf.exempt
def admin_products():
    products=Product.query.all()
    return render_template("admin_products.html", products=products)

#                        >>>>>>>>>>>>>>>>>>>>>>>>>>>>

@app.route("/admin/manage_products")
@admin_required
@csrf.exempt
def manage_products():
    
    products=Product.query.all()
    
    return render_template('admin_products.html', products=products)
    
#>>>>>>>>>>>>>>>>>>>>>>>>>>>

# Serve uploaded files from the "uploads" folder
@app.route('/uploads/<filename>')
@csrf.exempt
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Add Product Route
@app.route('/admin/add_product', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
@admin_required
def admin_add_product():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = abs(float(request.form['price']))
        stock = abs(int(request.form['stock']))
        category = request.form['category']
        image = request.files['image']

        if image and image.filename:  
            filename = secure_filename(image.filename)
            ext = os.path.splitext(filename)[1].lower()

            if ext not in app.config['UPLOAD_EXTENSIONS']:
                flash("Invalid file format!", "error")
                return redirect(url_for('admin_add_product'))
        else:
            flash("No image selected")
            filename = secure_filename('1743405389852.jpg')  # Default image name

        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(image_path)
        try:
            im = pyimgur.Imgur(CLIENT_ID)
            uploaded = im.upload_image(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            imgur_link = uploaded.link
        except Exception as e:
            print(f"Imgur upload failed: {e}")
            imgur_link = None

        new_product = Product(name=name, description=description, price=price, stock=stock, category=category, image_url=f'/uploads/{filename}', imgur_url = imgur_link)
        db.session.add(new_product)
        db.session.commit()
        log_admin_activity(f"[ADMIN ADD PRODUCT] Added product: {new_product.name}", target_type="product", target_id=new_product.id)
        backup_product_to_json(new_product)

        flash("Product added successfully!", "success")
        return redirect(url_for('admin_products'))

    return render_template("upload_product.html", product=None)

# Edit Product Route
@app.route('/admin/edit_product/<int:product_id>', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_edit_product(product_id):
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':  
        name = request.form.get('name', '').strip()  
        description = request.form.get('description', '').strip()  
        price = request.form.get('price', '').strip()  
        stock = request.form.get('stock', '').strip()  
        category = request.form.get('category', '').strip()  
        image = request.files.get('image') 

        # Ensure required fields are filled  
        if not name or not description or not price or not stock:  
            flash("All fields are required!", "error")  
            return redirect(url_for('admin_edit_product', product_id=product.id))  

        try:  
            product.price = abs(float(price))  
            product.stock = abs(int(stock))  
        except ValueError:  
            flash("Invalid price or stock value.", "error")  
            return redirect(url_for('admin_edit_product', product_id=product.id))
        try:
            im = pyimgur.Imgur(CLIENT_ID)
            uploaded = im.upload_image(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            imgur_link = uploaded.link
        except Exception as e:
            print(f"Imgur upload failed: {e}")
            imgur_link = None

        product.name = name  
        product.description = description  
        product.category = category  
        product.created_at = datetime.utcnow()  
        product.imgur_url = imgur_link

        if image and image.filename:  
            filename = secure_filename(image.filename)  
            ext = os.path.splitext(filename)[1].lower()  
            
            if ext not in app.config['UPLOAD_EXTENSIONS']:  
                flash("Invalid file format!", "error")  
                return redirect(url_for('admin_edit_product', product_id=product.id))  

            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)  
            image.save(image_path)  
            product.image_url = f'/uploads/{filename}'  

        db.session.commit()
        log_admin_activity(f"[ADMIN EDIT PRODUCT] Edited product: {product.name}", target_type="product", target_id=product.id)
        flash("Product updated successfully!", "success")  
        return redirect(url_for('admin_products'))  

    return render_template("upload_product.html", product=product)

# Delete Product Route
@app.route("/admin/delete_product/<int:product_id>", methods=['POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    try:
        db.session.delete(product)
        db.session.commit()
        log_admin_activity(f"[ADMIN ADD PRODUCT] Deleted product: {product.name}", target_type="product", target_id=product.id)
        flash("Product has been deleted", "success")
    except IntegrityError as e:
        flash("Product not deleted!", "error")
    return redirect(url_for('admin_products'))

#---------------------------------------------------
#                              ____ORDERS____

@app.route('/admin/manage_orders')
@admin_required
@csrf.exempt
def admin_manage_orders():
    return render_template('admin_manage_orders.html')

@app.route('/admin/orders_data')
@admin_required
def orders_data():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))

    pagination = Order.query.order_by(Order.id.desc()).paginate(page=page, per_page=per_page, error_out=False)
    orders = pagination.items

    orders_data = []
    for order in orders:
        orders_data.append({
            'id': order.id,
            'user': order.user.mobile if order.user else "Guest",
            'product': order.product.name if order.product else "Unavailable",
            'quantity': order.quantity,
            'status': order.status,
            'created_at': order.created_at,
            'location': order.location
        })

    return jsonify({
        'orders': orders_data,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev,
        'next_page': pagination.next_num if pagination.has_next else None,
        'prev_page': pagination.prev_num if pagination.has_prev else None,
        'current_page': page
    }) 


@app.route('/admin/update_order', methods=['POST'])
@limiter.limit("25 per minute")
@admin_required
def admin_update_order():
    data = request.json
    order_id = data.get('order_id')
    new_status = data.get('status')

    order = Order.query.get(order_id)
    if order:
        order.status = new_status
        db.session.commit()
        log_admin_activity(f"[ADMIN UPDATE_STARUS] Updated order #{order.id} status to {new_status}", 'order', order.id)
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Order not found'}), 404

@app.route('/admin/delete_order/<int:order_id>', methods=['POST'])
@limiter.limit("50 per minute")
@admin_required
def admin_delete_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order:
        db.session.delete(order)
        log_admin_activity(f"[ADMIN DELETE_ORDER] Deleted order #{order.id}", 'order', order.id)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Order not found'}), 404    

#----------------------------------------------------

@app.route('/admin/account')
@csrf.exempt
@login_required
@admin_required
def account():
    user = User.query.get_or_404(current_user.id)
    return render_template('admin_account.html', user=user)
  
#----------------------------------------------------

@app.route('/admin/activities')
@admin_required
def admin_activities():
    activities = AdminActivity.query.options(
        db.joinedload(AdminActivity.admin)
    ).order_by(AdminActivity.timestamp.desc()).limit(100).all()
    return render_template('activity_monitor.html', activities=activities)

# Socket.IO Handlers
@socketio.on('connect', namespace='/activities')
def handle_activity_connect():
    try:
        if not current_user.is_authenticated or current_user.role != 'admin':
            raise ConnectionRefusedError('Unauthorized')
        
        join_room('admin_activities')
        emit('status_update', {'status': 'connected'})
        
    except Exception as e:
        app.logger.error(f"Connection failed: {str(e)}")
        emit('error', {'message': str(e)})
        disconnect()

# Activity Logger
def log_admin_activity(action, target_type=None, target_id=None):
    try:
        admin_id = getattr(current_user, 'id', None)
        admin_mobile = getattr(current_user, 'mobile', 'Unknown')

        if not admin_id:
            raise Exception("Admin not authenticated")

        # Parse User-Agent info
        from user_agents import parse
        ua_string = request.headers.get('User-Agent')
        ua = parse(ua_string)

        os_name = ua.os.family
        os_version = ua.os.version_string
        browser_name = ua.browser.family
        browser_version = ua.browser.version_string
        device_brand = ua.device.brand or "Unknown Brand"
        device_family = ua.device.family or "Unknown Device"
        device_model = ua.device.model or ""

        device_info = f"{device_brand} {device_family} {device_model}".strip()
        user_agent_details = f"{os_name} {os_version} ({device_info}) - {browser_name} {browser_version}"

        activity = AdminActivity(
            admin_id=admin_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            ip_address=request.headers.get('X-Forwarded-For', request.remote_addr),
            user_agent=user_agent_details
        )

        db.session.add(activity)
        db.session.commit()

        socketio.emit('new_activity', {
            'timestamp': activity.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'admin': admin_mobile,
            'action': action,
            'target_type': target_type or 'system',
            'target_id': target_id,
            'ip': activity.ip_address,
            'device': activity.user_agent
        }, namespace='/activities', room='admin_activities')

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"[ActivityLog] Failed: {str(e)}")

def cleanup_old_activities():
    with app.app_context():
        try:
            cutoff = datetime.utcnow() - timedelta(days=app.config['ACTIVITY_RETENTION_DAYS'])
            
            AdminActivity.query.filter(AdminActivity.timestamp < cutoff).delete()
            db.session.commit()
            app.logger.info(f"Cleaned up activities older than {app.config['ACTIVITY_RETENTION_DAYS']} days")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Activity cleanup failed: {str(e)}")

scheduler = BackgroundScheduler(timezone="UTC")
scheduler.add_job(cleanup_old_activities, 'interval', days=1)
scheduler.start()

# Register Shutdown Cleanup
atexit.register(lambda: scheduler.shutdown())

@app.route('/cleanup', methods=['GET'])
def manual_cleanup():
    cleanup_old_activities()
    return "Admin activity cleanup executed successfully!"
#----------------------------------------------------
@app.route('/admin/activities/clean')
@admin_required
def clear_old_activities():
    days = int(request.form.get('days', 7))
    cutoff = datetime.utcnow() - timedelta(days=days)

    deleted = AdminActivity.query.filter(AdminActivity.timestamp < cutoff).delete()
    db.session.commit()

    flash(f"Deleted {deleted} activity logs older than {days} days.", "success")
    log_admin_activity("[ADMIN CLEAN LOGS] Deleted logs older than 7 days")
    return redirect(url_for('admin_dashboard'))
    
@app.route('/admin/activities/clean_hourly/not_allowed')
@admin_required
def clear_hourly_logs():
    if current_user.role != 'superadmin':
        return render_template("403.html"),  403
        log_admin_activity("[ADMIN TRY CLEAN] Tried to clean logs > 3hrs")
    actual_time = datetime.utcnow() + timedelta(hours=3)
    cutoff = actual_time - timedelta(hours=3)
    deleted = AdminActivity.query.filter(AdminActivity.timestamp < cutoff).delete()
    log_admin_activity("[SUPERADMIN CLEAN LOGS] Cleaned old logs <3 hrs>")
    db.session.commit()

    flash(f"Deleted {deleted} logs older than 3 hour.", "success")
    return redirect(url_for('admin_dashboard'))  
#---------------------------------------------------

CLIENT_ID = "3c32eed857d210b"

@app.route('/admin/backup_imgur_fallbacks')
@admin_required
def backup_imgur_fallbacks():
    uploads_folder = app.config['UPLOAD_FOLDER']
    products = Product.query.all()
    backed_up = 0
    skipped = 0

    im = pyimgur.Imgur(CLIENT_ID)

    for product in products:
        if product.imgur_url:
            skipped += 1
            continue  # already backed up

        filename = os.path.basename(product.image_url)
        local_path = os.path.join(uploads_folder, filename)

        if os.path.exists(local_path):
            try:
                uploaded = im.upload_image(local_path, title=f"Backup: {filename}")
                product.imgur_url = uploaded.link
                backed_up += 1
            except Exception as e:
                print(f"[✗] Failed to upload {filename}: {e}")
        else:
            print(f"[!] File not found: {local_path}")

    db.session.commit()
    flash(f"Backed up {backed_up} product image(s) to Imgur. Skipped {skipped} already backed up.", "success")
    return redirect(url_for('admin_dashboard'))  # Replace if needed
                    
#---------------------------------------------------
@app.context_processor
def inject_csrf_token():
    from flask_wtf.csrf import generate_csrf
    return dict(csrf_token=generate_csrf)
#---------------------------------------------------
#                   ____ERROR HANDLERS____

@app.errorhandler(404)
@csrf.exempt
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(403)
@csrf.exempt
def forbidden_error(error):
    return render_template('403.html'), 403

@app.errorhandler(500)
@csrf.exempt
def internal_error(error):
    app.logger.error(f'Internal Server Error: {error}', exc_info=True)
    flash('Request cannot be completed', 'error'), 500
    return redirect(request.referrer or url_for('home'))

@app.errorhandler(CSRFError)
@csrf.exempt
def handle_csrf_error(e):
    flash("csrf missing", "error"), 400
    return redirect(request.referrer or url_for('home'))

#---------------------------------------------------
#                ____RUNNING THE APP____

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=47947, debug=False)   