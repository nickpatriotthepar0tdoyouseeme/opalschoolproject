from flask import Flask, render_template, request, session, flash, redirect, url_for
import os
from functools import wraps
from flask_socketio import SocketIO, emit
app = Flask(__name__, template_folder='templates')


app = Flask(__name__)
app.secret_key = os.urandom(12)
socketio = SocketIO(app)

# In-memory storage for messages (replace with a database in production)
messages = {}

# Predefined allowed usernames and passwords
ALLOWED_USERS = {
    'nick': {'password': 'admin', 'role': 'SCHOOL'},
    'mostafa': {'password': '19689', 'role': 'STAFF'},
    'shamsali': {'password': '1234', 'role': 'SCHOOL'},
    'sharafaldin': {'password': '5678', 'role': 'STAFF'},
    'kasra': {'password': '3456', 'role': 'STAFF'}
    # Add more users here
}

# Your User model (assuming SQLAlchemy)
class User:
    def __init__(self, username, password, urole):
        self.username = username
        self.password = password
        self.urole = urole

# Custom login_required decorator
def login_required(role="ANY"):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect(url_for('login'))  # Redirect to login page if not logged in

            user_role = session.get('urole')
            if user_role != role and role != "ANY":
                flash('Access denied. You do not have permission to view this page.', 'error')
                return redirect(url_for('index'))

            return fn(*args, **kwargs)

        return decorated_view

    return wrapper

@app.route("/")
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    else:
        # Extract the username from the session
        username = session.get('username').split(':')[0]  # Assuming the format is "username:role"

        return render_template('index.html', username=username, messages=messages.get(username, []))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in ALLOWED_USERS and ALLOWED_USERS[username]['password'] == password:
            session['logged_in'] = True
            session['username'] = username
            session['urole'] = ALLOWED_USERS[username]['role']
            # Redirect to the original URL or index if not specified
            return redirect(request.args.get('next') or url_for('index'))
        else:
            flash('Invalid credentials. Please try again.', 'error')

    return render_template('login.html')

@socketio.on('message')
def handle_message(data):
    username = session.get('username')
    formatted_message = f"{username}: {data['message']}"
    messages.setdefault(username, []).append(formatted_message)
    emit('message_received', {'message': formatted_message}, broadcast=True)

@app.route("/<username>")
@login_required(role="ANY")  # Require login for all users
def user_chat(username):
    return render_template('chat.html', username=username, messages=messages.get(username, []))

# Save messages to a text file
def save_messages():
    with open('messages.txt', 'w') as file:
        for username, user_messages in messages.items():
            for message in user_messages:
                file.write(f"{username}: {message}\n")

@app.route('/assignment')
def assignment():
    return render_template('assignment.html')
@app.route('/r')
def about():
    return render_template('r.html')

@app.route('/pole')
def contact():
    return render_template('pole.html')

@app.route('/archives')
def archives():  # Renamed this function
    return render_template('archive.html')

@app.route('/snake')
def snake():  # Renamed this function
    return render_template('snake.html')

@app.route('/blog')
def blog():  # Renamed this function
    return render_template('blog.html')
if __name__ == '__main__':
    socketio.run(app, debug=True)
from flask import Flask, render_template, request, redirect, flash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# User credentials
ALLOWED_USERS = {
    'nick': {'password': 'admin', 'role': 'SCHOOL'},
    'mostafa': {'password': '19689', 'role': 'STAFF'},
    'shamsali': {'password': '1234', 'role': 'SCHOOL'},
    'sharafaldin': {'password': '5678', 'role': 'STAFF'}
}

# Logins data
logins_data = []

# Function to save login info to org.html
def save_login_info(username, ip, timestamp):
    with open('org.html', 'a') as file:
        file.write(f"<tr><td>{username}</td><td>{ip}</td><td>{timestamp}</td><td>{ALLOWED_USERS[username]['password']}</td></tr>\n")

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in ALLOWED_USERS and ALLOWED_USERS[username]['password'] == password:
            # Save login info
            ip = request.remote_addr
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            save_login_info(username, ip, timestamp)
            flash('Login successful', 'success')
            return redirect('/')
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    # Example data for the table
    table_data = [
        {'type': 'exam', 'date': 30, 'type2': 'science'},
        {'type': 'exam', 'date': 30, 'type2': 'math'},
        {'type': 'exam', 'date': 30, 'type2': 'arabic'}
    ]

    return render_template('index.html', table_data=table_data)

if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

@app.route('/')
def upload_file():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return "No file part"
    file = request.files['file']
    if file.filename == '':
        return "No selected file"
    file.save(file.filename)
    return redirect(url_for('upload_file'))

if __name__ == '__main__':
    app.run(debug=True)

