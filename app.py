from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a real secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # SQLite database URI

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Set login route

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

# Message Model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

# Create the database and add users if not exists
with app.app_context():
    db.create_all()
    
    # Check if users already exist
    if User.query.count() == 0:
        # Create three users with hashed passwords
        user1 = User(username='user1', password=bcrypt.generate_password_hash('password1').decode('utf-8'))
        user2 = User(username='user2', password=bcrypt.generate_password_hash('password2').decode('utf-8'))
        user3 = User(username='user3', password=bcrypt.generate_password_hash('password3').decode('utf-8'))
        db.session.add(user1)
        db.session.add(user2)
        db.session.add(user3)
        db.session.commit()

# Home Route
@app.route('/')
def home():
    return render_template('home.html')

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))  # Redirect to the dashboard
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

# Logout Route
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# Dashboard (Protected Route)
@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch messages involving the current user
    messages = Message.query.filter(
        (Message.sender_id == current_user.id) | (Message.receiver_id == current_user.id)
    ).order_by(Message.timestamp).all()

    # Organize messages with user info
    formatted_messages = []
    for message in messages:
        formatted_messages.append({
            'id': message.id,
            'sender': 'You' if message.sender_id == current_user.id else message.sender.username,
            'receiver': 'You' if message.receiver_id == current_user.id else message.receiver.username,
            'content': message.content,
            'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })

    return render_template('dashboard.html', messages=formatted_messages)

# Route to send messages
@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    data = request.get_json()
    content = data.get('content')
    receiver_id = data.get('receiver_id')

    if content and receiver_id:
        new_message = Message(sender_id=current_user.id, receiver_id=receiver_id, content=content)
        db.session.add(new_message)
        db.session.commit()
        
        # Return success and the message data
        return jsonify(success=True, message={
            'sender': 'You',
            'receiver': User.query.get(receiver_id).username,
            'content': content,
            'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })
    return jsonify(success=False), 400

# Route to add a new contact
@app.route('/add_contact', methods=['POST'])
@login_required
def add_contact():
    data = request.get_json()
    username_to_add = data.get('username')

    user_to_add = User.query.filter_by(username=username_to_add).first()
    
    if user_to_add:
        # Return success and the username of the added contact
        return jsonify(success=True, username=user_to_add.username, id=user_to_add.id)
    
    return jsonify(success=False, message="User not found."), 404

# Route to get all users for displaying as contacts, excluding the current user
@app.route('/get_users', methods=['GET'])
@login_required
def get_users():
    users = User.query.filter(User.id != current_user.id).all()
    return jsonify([{'id': user.id, 'username': user.username} for user in users])

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
