import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    referral = db.Column(db.String(150))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database tables and default admin user
with app.app_context():
    db.create_all()
    # Create default admin user if not exists
    admin_user = User.query.filter_by(username='hoangvanhuy').first()
    if not admin_user:
        hashed_password = generate_password_hash('tothichcau', method='sha256')
        admin_user = User(name='Admin', username='hoangvanhuy', password=hashed_password, referral=None)
        db.session.add(admin_user)
        db.session.commit()

@app.route('/')
@login_required
def index():
    return redirect(url_for('user'))

@app.route('/user')
@login_required
def user():
    return render_template('index.html')

@app.route('/user/nhiem-vu')
@login_required
def nhiem_vu():
    return render_template('nhiem-vu.html')

@app.route('/user/menu')
@login_required
def menu():
    return render_template('menu.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        referral = request.form.get('referral')

        if password != password_confirm:
            flash('Mật khẩu xác nhận không khớp!')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Tên đăng nhập đã tồn tại!')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(name=name, username=username, password=hashed_password, referral=referral)
        db.session.add(new_user)
        db.session.commit()
        flash('Đăng ký thành công!')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('user'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return f'Hello, {current_user.username}!'

@app.route('/hoangvanhuy', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'hoangvanhuy' and password == 'tothichcau':
            session['admin'] = True
            users = User.query.all()
            return render_template('admin.html', users=users)
        else:
            flash('Invalid admin credentials!')
            return redirect(url_for('admin'))
    if session.get('admin'):
        users = User.query.all()
        return render_template('admin.html', users=users)
    return render_template('admin_login.html')

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('admin'):
        flash('Access denied!')
        return redirect(url_for('admin'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted!')
    return redirect(url_for('admin'))

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin'))

@app.route('/export_data')
def export_data():
    if not session.get('admin'):
        flash('Access denied!')
        return redirect(url_for('admin'))
    users = User.query.all()
    data = []
    for user in users:
        data.append({
            'id': user.id,
            'name': user.name,
            'username': user.username,
            'password': user.password,  # hashed
            'referral': user.referral
        })
    json_data = json.dumps(data, indent=4, ensure_ascii=False)
    response = Response(json_data, mimetype='application/json')
    response.headers['Content-Disposition'] = 'attachment; filename=users_backup.json'
    return response

@app.route('/import_data', methods=['POST'])
def import_data():
    if not session.get('admin'):
        flash('Access denied!')
        return redirect(url_for('admin'))
    file = request.files.get('file')
    if not file:
        flash('No file selected!')
        return redirect(url_for('admin'))
    try:
        data = json.load(file)
        for item in data:
            # Check if user exists
            existing = User.query.filter_by(username=item['username']).first()
            if not existing:
                new_user = User(
                    name=item['name'],
                    username=item['username'],
                    password=item['password'],  # assume hashed
                    referral=item.get('referral')
                )
                db.session.add(new_user)
        db.session.commit()
        flash('Data imported successfully!')
    except Exception as e:
        flash(f'Import failed: {str(e)}')
    return redirect(url_for('admin'))
