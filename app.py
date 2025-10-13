import os
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = '247'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    drinks = db.relationship('Log', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    drink = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.datetime.now(datetime.UTC))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    drink_options = {}
    current_brand = None
    with open(os.path.join(basedir, 'drinks.txt'), 'r') as file:
        for line in file:
            line = line.strip()
            if not line: continue
            if line.startswith('-'):
                current_brand = line[15:].strip()
                drink_options[current_brand] = []
            elif current_brand: drink_options[current_brand].append(line)
    if request.method == 'POST':
        brand = request.form.get('brand')
        flavour = request.form.get('flavour')
        if brand and flavour:
            new_drink = Log(drink=f'{brand} {flavour}', user_id=current_user.id)
            db.session.add(new_drink)
            db.session.commit()
            flash('Energy drink logged successfully!', 'success')
        else:
            flash('Please select a drink.', 'error')
        return redirect(url_for('dashboard'))

    user_drinks = Log.query.filter_by(user_id=current_user.id).order_by(Log.timestamp.desc()).all()
    return render_template('dashboard.html', drinks=user_drinks, drink_options=drink_options)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another one.', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True)