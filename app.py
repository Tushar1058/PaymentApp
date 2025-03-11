from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
from io import BytesIO
import base64
import os
import sys
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Print environment variables for debugging (excluding sensitive data)
logger.info("Environment variables:")
for key in os.environ:
    if not any(sensitive in key.lower() for sensitive in ['secret', 'password', 'key']):
        logger.info(f"{key}: {os.environ[key]}")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')

try:
    # Update database configuration
    basedir = os.path.abspath(os.path.dirname(__file__))
    logger.info(f"Base directory: {basedir}")
    
    # Configure database URI based on environment
    if os.getenv('RAILWAY_VOLUME_MOUNT_PATH'):
        # We're on Railway with a volume mount
        db_dir = os.path.join(os.getenv('RAILWAY_VOLUME_MOUNT_PATH'), 'database')
        logger.info(f"Using Railway volume mount path: {db_dir}")
    else:
        # Local development
        db_dir = os.path.join(basedir, 'database')
        logger.info(f"Using local database path: {db_dir}")
    
    # Create database directory if it doesn't exist
    if not os.path.exists(db_dir):
        logger.info(f"Creating database directory: {db_dir}")
        os.makedirs(db_dir, exist_ok=True)
    
    # Set the database URI
    db_path = os.path.join(db_dir, 'wallet.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    logger.info(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Update static file handling
    UPLOAD_FOLDER = os.path.join(basedir, 'static')
    logger.info(f"Upload folder: {UPLOAD_FOLDER}")
    
    # Create required directories with error handling
    for folder in ['screenshots', 'qr_codes']:
        folder_path = os.path.join(UPLOAD_FOLDER, folder)
        try:
            if not os.path.exists(folder_path):
                logger.info(f"Creating directory: {folder_path}")
                os.makedirs(folder_path, exist_ok=True)
        except Exception as e:
            logger.error(f"Error creating directory {folder_path}: {str(e)}")
            # Continue even if directory creation fails
            pass
            
except Exception as e:
    logger.error(f"Error during app initialization: {str(e)}")
    raise

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))  # Made nullable temporarily for migration
    balance = db.Column(db.Float, default=0.0)
    is_admin = db.Column(db.Boolean, default=False)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # 'deposit' or 'withdrawal'
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    upi_approved = db.Column(db.Boolean, default=False)
    payment_done = db.Column(db.Boolean, default=False)
    screenshot = db.Column(db.String(200))
    upi_id = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    rejection_reason = db.Column(db.Text)  # New field for rejection reason
    user = db.relationship('User', backref='transactions')

class UPISettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    upi_id = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100))
    merchant_code = db.Column(db.String(20))  # Optional for merchant payments

def handle_db_migration():
    with app.app_context():
        inspector = db.inspect(db.engine)
        
        # Check if tables exist
        if not inspector.has_table('user'):
            db.create_all()
            return
        
        # Get existing columns in transaction table
        columns = [col['name'] for col in inspector.get_columns('transaction')]
        
        # Add rejection_reason column if it doesn't exist
        if 'rejection_reason' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(db.text('ALTER TABLE "transaction" ADD COLUMN rejection_reason TEXT'))
                    conn.commit()
            except Exception as e:
                print(f"Error adding rejection_reason column: {e}")
                # Try alternative approach for SQLite
                with db.engine.connect() as conn:
                    conn.execute(db.text('BEGIN TRANSACTION'))
                    conn.execute(db.text('''
                        CREATE TABLE "transaction_new" (
                            id INTEGER NOT NULL PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            type VARCHAR(20) NOT NULL,
                            amount FLOAT NOT NULL,
                            status VARCHAR(20),
                            upi_approved BOOLEAN,
                            payment_done BOOLEAN,
                            screenshot VARCHAR(200),
                            upi_id VARCHAR(100),
                            timestamp DATETIME,
                            rejection_reason TEXT,
                            FOREIGN KEY(user_id) REFERENCES "user" (id)
                        )
                    '''))
                    conn.execute(db.text('''
                        INSERT INTO "transaction_new" (
                            id, user_id, type, amount, status, upi_approved, payment_done,
                            screenshot, upi_id, timestamp
                        )
                        SELECT id, user_id, type, amount, status, upi_approved, payment_done,
                               screenshot, upi_id, timestamp
                        FROM "transaction"
                    '''))
                    conn.execute(db.text('DROP TABLE "transaction"'))
                    conn.execute(db.text('ALTER TABLE "transaction_new" RENAME TO "transaction"'))
                    conn.execute(db.text('COMMIT'))
                    conn.commit()
        
        # Handle migration from password to password_hash
        if 'password' in columns and 'password_hash' not in columns:
            # Create new password_hash column
            with db.engine.connect() as conn:
                conn.execute(db.text('ALTER TABLE "user" ADD COLUMN password_hash VARCHAR(256)'))
                conn.commit()
            
            # Migrate existing passwords
            users = db.session.query(User).all()
            for user in users:
                # Get the old password value
                with db.engine.connect() as conn:
                    result = conn.execute(
                        db.text('SELECT password FROM "user" WHERE id = :id'),
                        {"id": user.id}
                    ).fetchone()
                    old_password = result[0] if result else None
                
                if old_password:
                    # Update with hashed password
                    user.password = old_password  # This will use the password setter
                    db.session.add(user)
            
            db.session.commit()
            
            # Drop old password column
            with db.engine.connect() as conn:
                conn.execute(db.text('ALTER TABLE "user" DROP COLUMN password'))
                conn.commit()

def init_db():
    try:
        with app.app_context():
            logger.info("Starting database initialization")
            
            # Handle database migration
            handle_db_migration()
            
            # Create tables if they don't exist
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Create default UPI settings if not exists
            if not UPISettings.query.first():
                logger.info("Creating default UPI settings")
                default_upi = UPISettings(upi_id="your-upi-id@upi", name="Your Name")
                db.session.add(default_upi)
                try:
                    db.session.commit()
                    logger.info("Default UPI settings created successfully")
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Error creating default UPI settings: {str(e)}")
            
            # Create default admin user if not exists
            admin_user = User.query.filter_by(username="tushar77").first()
            if not admin_user:
                logger.info("Creating default admin user")
                admin_user = User(
                    username="tushar77",
                    password="tushar@123",
                    is_admin=True,
                    balance=0.0
                )
                db.session.add(admin_user)
                try:
                    db.session.commit()
                    logger.info("Default admin user created successfully")
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Error creating default admin user: {str(e)}")
    
    except Exception as e:
        logger.error(f"Error during database initialization: {str(e)}")
        raise

# Initialize database with error handling
try:
    init_db()
except Exception as e:
    logger.error(f"Failed to initialize database: {str(e)}")
    # Don't raise here, let the app continue to start

def generate_upi_qr(upi_id, amount, name=None):
    # Generate UPI payment URL
    upi_url = f"upi://pay?pa={upi_id}&pn={name or ''}&am={amount}&cu=INR"
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(upi_url)
    qr.make(fit=True)
    
    # Create QR image
    img_buffer = BytesIO()
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img.save(img_buffer, format="PNG")
    img_buffer.seek(0)
    
    # Convert to base64 for embedding in HTML
    img_str = base64.b64encode(img_buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
    return render_template('dashboard.html', user=current_user, transactions=transactions)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))
        
        # Make tushar77 an admin user automatically
        is_admin = (username == "tushar77" and password == "tushar@123")
        
        user = User(
            username=username,
            password=password,  # This will use the password setter
            is_admin=is_admin
        )
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('Error during registration!')
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/get_transaction_status/latest')
@login_required
def get_latest_transaction_status():
    # Get the user's most recent pending transaction
    transaction = Transaction.query.filter_by(
        user_id=current_user.id,
        status='pending'
    ).order_by(Transaction.timestamp.desc()).first()
    
    if transaction:
        return jsonify({
            'has_pending': True,
            'transaction': {
                'id': transaction.id,
                'type': transaction.type,
                'amount': float(transaction.amount),
                'status': transaction.status,
                'upi_approved': transaction.upi_approved,
                'payment_done': transaction.payment_done
            }
        })
    
    return jsonify({'has_pending': False})

@app.route('/deposit', methods=['GET', 'POST'])
@login_required
def deposit():
    # Check for pending transactions
    pending_transaction = Transaction.query.filter_by(
        user_id=current_user.id,
        status='pending'
    ).first()
    
    if pending_transaction:
        flash('You have a pending transaction. Please wait for it to complete.', 'warning')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            
            # Validate amount
            if amount < 10:
                flash('Minimum deposit amount is ₹10', 'error')
                return redirect(url_for('deposit'))
            if amount > 10000:
                flash('Maximum deposit amount is ₹10,000', 'error')
                return redirect(url_for('deposit'))
            
            if 'screenshot' not in request.files:
                flash('Payment screenshot is required', 'error')
                return redirect(url_for('deposit'))
                
            screenshot = request.files['screenshot']
            
            if screenshot.filename == '':
                flash('Payment screenshot is required', 'error')
                return redirect(url_for('deposit'))
            
            # Validate file type
            allowed_extensions = {'png', 'jpg', 'jpeg'}
            if not ('.' in screenshot.filename and \
                   screenshot.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
                flash('Invalid file type. Only PNG, JPG, and JPEG files are allowed.', 'error')
                return redirect(url_for('deposit'))
            
            # Save screenshot
            filename = f"static/screenshots/{datetime.now().timestamp()}_{screenshot.filename}"
            screenshot.save(filename)
            
            # Create transaction
            transaction = Transaction(
                user_id=current_user.id,
                type='deposit',
                amount=amount,
                screenshot=filename
            )
            db.session.add(transaction)
            db.session.commit()
            
            flash('Deposit request submitted successfully', 'success')
            return redirect(url_for('index'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error processing deposit request. Please try again.', 'error')
            return redirect(url_for('deposit'))
    
    # Get UPI settings
    upi_settings = UPISettings.query.first()
    if not upi_settings:
        flash('UPI settings not configured. Please contact support.', 'error')
        return redirect(url_for('index'))
        
    return render_template('deposit.html', upi_settings=upi_settings)

@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    # Check for pending transactions
    pending_transaction = Transaction.query.filter_by(
        user_id=current_user.id,
        status='pending'
    ).first()
    
    if pending_transaction:
        flash('You have a pending transaction. Please wait for it to complete.', 'warning')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            upi_id = request.form['upi_id']
            
            # Validate amount
            if amount < 10:
                flash('Minimum withdrawal amount is ₹10', 'error')
                return redirect(url_for('withdraw'))
            if amount > 10000:
                flash('Maximum withdrawal amount is ₹10,000', 'error')
                return redirect(url_for('withdraw'))
            if amount > current_user.balance:
                flash('Insufficient balance', 'error')
                return redirect(url_for('withdraw'))
            
            # Validate UPI ID
            if not upi_id or len(upi_id) < 5:
                flash('Please enter a valid UPI ID', 'error')
                return redirect(url_for('withdraw'))
            
            if 'qr_code' not in request.files:
                flash('UPI QR code is required', 'error')
                return redirect(url_for('withdraw'))
                
            qr_image = request.files['qr_code']
            
            if qr_image.filename == '':
                flash('UPI QR code is required', 'error')
                return redirect(url_for('withdraw'))
            
            # Validate file type
            allowed_extensions = {'png', 'jpg', 'jpeg'}
            if not ('.' in qr_image.filename and \
                   qr_image.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
                flash('Invalid file type. Only PNG, JPG, and JPEG files are allowed.', 'error')
                return redirect(url_for('withdraw'))
            
            # Save QR code image
            filename = f"static/qr_codes/{datetime.now().timestamp()}_{qr_image.filename}"
            qr_image.save(filename)
            
            # Create transaction
            transaction = Transaction(
                user_id=current_user.id,
                type='withdrawal',
                amount=amount,
                upi_id=upi_id,
                screenshot=filename
            )
            db.session.add(transaction)
            db.session.commit()
            
            flash('Withdrawal request submitted successfully', 'success')
            return redirect(url_for('withdraw', transaction_id=transaction.id))
            
        except Exception as e:
            db.session.rollback()
            flash('Error processing withdrawal request. Please try again.', 'error')
            return redirect(url_for('withdraw'))
    
    return render_template('withdraw.html')

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    # Get UPI settings
    upi_settings = UPISettings.query.first()
    
    # Get pending transactions
    transactions = Transaction.query.filter_by(status='pending').order_by(Transaction.timestamp.desc()).all()
    
    # Get all transactions for history
    all_transactions = Transaction.query.order_by(Transaction.timestamp.desc()).all()
    
    return render_template('admin.html', 
                         transactions=transactions,
                         all_transactions=all_transactions,
                         upi_settings=upi_settings)

@app.route('/admin/upi-settings', methods=['POST'])
@login_required
def update_upi_settings():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    upi_id = request.form.get('upi_id')
    name = request.form.get('name')
    
    settings = UPISettings.query.first()
    if settings:
        settings.upi_id = upi_id
        settings.name = name
    else:
        settings = UPISettings(upi_id=upi_id, name=name)
        db.session.add(settings)
    
    try:
        db.session.commit()
        flash('UPI settings updated successfully', 'success')
    except:
        db.session.rollback()
        flash('Error updating UPI settings', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/approve_transaction/<int:transaction_id>')
@login_required
def approve_transaction(transaction_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    transaction = Transaction.query.get(transaction_id)
    if transaction:
        transaction.status = 'approved'
        user = User.query.get(transaction.user_id)
        
        if transaction.type == 'deposit':
            user.balance += transaction.amount
        elif transaction.type == 'withdrawal' and transaction.payment_done:
            user.balance -= transaction.amount
        
        try:
            db.session.commit()
            flash('Transaction approved successfully', 'success')
        except:
            db.session.rollback()
            flash('Error approving transaction', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/reject_transaction/<int:transaction_id>', methods=['GET', 'POST'])
@login_required
def reject_transaction(transaction_id):
    if not current_user.is_admin:
        if request.method == 'GET':
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('index'))
        return jsonify({'error': 'Unauthorized'}), 403
    
    transaction = Transaction.query.get(transaction_id)
    if transaction:
        transaction.status = 'rejected'
        if request.method == 'POST':
            data = request.get_json()
            transaction.rejection_reason = data.get('reason', 'Transaction rejected by admin.')
        
        try:
            db.session.commit()
            if request.method == 'GET':
                flash('Transaction rejected successfully', 'success')
                return redirect(url_for('admin'))
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            if request.method == 'GET':
                flash('Error rejecting transaction', 'danger')
                return redirect(url_for('admin'))
            return jsonify({'error': str(e)}), 500
    
    if request.method == 'GET':
        return redirect(url_for('admin'))
    return jsonify({'error': 'Transaction not found'}), 404

@app.route('/generate-qr', methods=['POST'])
def generate_qr():
    amount = request.form.get('amount')
    if not amount:
        return jsonify({'error': 'Amount is required'}), 400
    
    upi_settings = UPISettings.query.first()
    if not upi_settings:
        return jsonify({'error': 'UPI settings not configured'}), 400
    
    qr_code = generate_upi_qr(upi_settings.upi_id, amount, upi_settings.name)
    return jsonify({
        'qr_code': qr_code,
        'upi_id': upi_settings.upi_id
    })

@app.route('/approve_upi/<int:transaction_id>')
@login_required
def approve_upi(transaction_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    transaction = Transaction.query.get(transaction_id)
    if transaction:
        transaction.upi_approved = True
        try:
            db.session.commit()
            return jsonify({
                'success': True,
                'message': 'UPI approved successfully'
            })
        except:
            db.session.rollback()
            return jsonify({'error': 'Error approving UPI'}), 500
    return jsonify({'error': 'Transaction not found'}), 404

@app.route('/mark_payment_done/<int:transaction_id>')
@login_required
def mark_payment_done(transaction_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    transaction = Transaction.query.get(transaction_id)
    if transaction:
        transaction.payment_done = True
        if transaction.type == 'withdrawal':
            transaction.status = 'approved'
            user = User.query.get(transaction.user_id)
            user.balance -= transaction.amount
        try:
            db.session.commit()
            return jsonify({
                'success': True,
                'message': 'Payment marked as done'
            })
        except:
            db.session.rollback()
            return jsonify({'error': 'Error marking payment as done'}), 500
    return jsonify({'error': 'Transaction not found'}), 404

@app.route('/get_transaction_status/<int:transaction_id>')
@login_required
def get_transaction_status(transaction_id):
    transaction = Transaction.query.get(transaction_id)
    if transaction and (current_user.id == transaction.user_id or current_user.is_admin):
        return jsonify({
            'status': transaction.status,
            'upi_approved': transaction.upi_approved,
            'payment_done': transaction.payment_done,
            'amount': float(transaction.amount),
            'type': transaction.type,
            'rejection_reason': transaction.rejection_reason
        })
    return jsonify({'error': 'Transaction not found'}), 404

@app.route('/get_upi_settings')
def get_upi_settings():
    settings = UPISettings.query.first()
    if settings:
        return jsonify({
            'upi_id': settings.upi_id,
            'name': settings.name
        })
    return jsonify({'error': 'UPI settings not configured'}), 404

@app.route('/get_all_transactions')
@login_required
def get_all_transactions():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    transactions = Transaction.query.order_by(Transaction.timestamp.desc()).all()
    return jsonify({
        'transactions': [{
            'id': t.id,
            'timestamp': t.timestamp.isoformat(),
            'username': t.user.username,
            'type': t.type,
            'amount': float(t.amount),
            'status': t.status,
            'upi_id': t.upi_id,
            'screenshot': t.screenshot,
            'upi_approved': t.upi_approved,
            'payment_done': t.payment_done
        } for t in transactions]
    })

@app.route('/get_pending_transactions')
@login_required
def get_pending_transactions():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    transactions = Transaction.query.filter_by(status='pending').order_by(Transaction.timestamp.desc()).all()
    return jsonify({
        'transactions': [{
            'id': t.id,
            'timestamp': t.timestamp.isoformat(),
            'username': t.user.username,
            'type': t.type,
            'amount': float(t.amount),
            'status': t.status,
            'upi_id': t.upi_id,
            'screenshot': t.screenshot,
            'upi_approved': t.upi_approved,
            'payment_done': t.payment_done
        } for t in transactions]
    })

@app.route('/clear_transaction_history', methods=['POST'])
@login_required
def clear_transaction_history():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        # Only delete completed (approved/rejected) transactions
        Transaction.query.filter(
            Transaction.status.in_(['approved', 'rejected'])
        ).delete(synchronize_session=False)
        
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"Internal Server Error: {str(error)}")
    return render_template('error.html', error=error), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error=error), 404

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port) 