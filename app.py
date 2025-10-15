import os
import pytz
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = '247'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# temp fix for me lololol
LOCAL_TZ = pytz.timezone('Australia/Adelaide')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='pending')  # pending, accepted, declined

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    coins = db.Column(db.Integer, default=0)
    #avatar = db.Column(db.String(200), default='default_avatar.png')??? TO DO ADD AVATAR SELECTION N STUFF

    drinks = db.relationship('Log', backref='user', lazy=True)
    sent_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.sender_id', backref='sender', lazy='dynamic')
    received_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.receiver_id', backref='receiver', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def friends(self):
        sent = FriendRequest.query.filter_by(sender_id=self.id, status='accepted').all()
        received = FriendRequest.query.filter_by(receiver_id=self.id, status='accepted').all()
        friend_ids = [req.receiver_id for req in sent] + [req.sender_id for req in received]
        return User.query.filter(User.id.in_(friend_ids)).all()

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    drink = db.Column(db.String(100), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    code = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.now(LOCAL_TZ))
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
            elif current_brand: 
                drink_options[current_brand].append(line)
    if request.method == 'POST':
        brand = request.form.get('brand')
        flavour = request.form.get('flavour')
        size = request.form.get('size')
        code = request.form.get('code')
        if brand and flavour:
            new_drink = Log(drink=f'{brand} {flavour}', size=int(size), code=int(code), user_id=current_user.id)
            db.session.add(new_drink)
            current_user.coins += 10
            db.session.commit()
            flash('Energy drink logged successfully!', 'success')
        else:
            flash('Please select a drink.', 'error')
        return redirect(url_for('dashboard'))

    user_drinks = Log.query.filter_by(user_id=current_user.id).order_by(Log.timestamp.desc()).all()
    return render_template('dashboard.html', drinks=user_drinks, drink_options=drink_options)

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        if 'new_password' in request.form:
            new_pw = request.form['new_password']
            current_user.set_password(new_pw)
            db.session.commit()
            flash('Password updated.', 'success')
        elif 'delete' in request.form:
            user_id = current_user.id
            logout_user()
            User.query.filter_by(id=user_id).delete()
            db.session.commit()
            flash('Account deleted.', 'success')
            return redirect(url_for('index'))
    return render_template('account.html')

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    results = []
    friends_list = current_user.friends()
    if request.method == 'POST':
        query = request.form.get('username', '')
        results = User.query.filter(User.username.contains(query), User.id != current_user.id).all()
    return render_template('search.html', results=results, friends_list=friends_list)

@app.route('/user/<int:user_id>')
@login_required
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    drinks = Log.query.filter_by(user_id=user.id).order_by(Log.timestamp.desc()).all()
    existing = FriendRequest.query.filter(
        ((FriendRequest.sender_id == current_user.id) & (FriendRequest.receiver_id == user.id)) |
        ((FriendRequest.sender_id == user.id) & (FriendRequest.receiver_id == current_user.id))
    ).first()
    return render_template('profile.html', user=user, drinks=drinks, request_status=existing)

@app.route('/send_request/<int:user_id>')
@login_required
def send_request(user_id):
    if user_id == current_user.id:
        flash("You can't send a friend request to yourself.", 'error')
    else:
        existing = FriendRequest.query.filter_by(sender_id=current_user.id, receiver_id=user_id).first()
        if existing:
            flash('Friend request already sent.', 'error')
        else:
            req = FriendRequest(sender_id=current_user.id, receiver_id=user_id)
            db.session.add(req)
            db.session.commit()
            current_user.coins += 5
            flash('Friend request sent!', 'success')
    return redirect(url_for('search'))

@app.route('/friends')
@login_required
def friends():
    pending = FriendRequest.query.filter_by(receiver_id=current_user.id, status='pending').all()
    accepted = current_user.friends()
    return render_template('friends.html', pending=pending, friends=accepted)

@app.route('/accept_request/<int:req_id>')
@login_required
def accept_request(req_id):
    req = FriendRequest.query.get_or_404(req_id)
    if req.receiver_id == current_user.id:
        req.status = 'accepted'
        db.session.commit()
        current_user.coins += 20
        flash('Friend request accepted!', 'success')
    return redirect(url_for('friends'))

@app.route('/decline_request/<int:req_id>')
@login_required
def decline_request(req_id):
    req = FriendRequest.query.get_or_404(req_id)
    if req.receiver_id == current_user.id:
        req.status = 'declined'
        db.session.commit()
        flash('Friend request declined.', 'info')
    return redirect(url_for('friends'))

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
            current_user.coins += 1
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
            flash('Username already exists.', 'error')
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
    with app.app_context(): db.create_all()
    app.run(host='0.0.0.0', debug=True)
