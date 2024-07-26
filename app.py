from flask import Flask, render_template, request, redirect, url_for, current_app
from flask_login import LoginManager, UserMixin, logout_user, login_required
import sqlite3
import secrets
from flask import Blueprint, render_template, request, flash, redirect, url_for


from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
import bcrypt
import random
 

app = Flask(__name__)
secret_key = secrets.token_hex()
app.secret_key = secret_key
login_manager = LoginManager()
login_manager.init_app(app)
app.app_context().push()

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

class Website:
    def __init__(self, id, user_id, name, url):
        self.id = id
        self.user_id = user_id
        self.url = url
        self.name = name

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

with open('schema.sql', 'r') as f:
    cursor.executescript(f.read())

conn.commit()
conn.close()        

def get_user_by_id(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = {}'.format(int(user_id)))
    user_data = cursor.fetchone()
    conn.close()
    if user_data:
        return User(user_data[0], user_data[1], user_data[2])
    else:
        return None
    
def check_user_exists(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT EXISTS (SELECT 1 FROM users WHERE username = ?)", (username,))
    return cursor.fetchone()[0] == 1


def add_user(username, password):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()

def add_website(user_id, name, url):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO websites (user_id, name, url) VALUES (?, ?, ?)", (user_id, name, url))
    conn.commit()




def hash_password(password):
    # Generate a random salt
    salt = bcrypt.gensalt()
    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def get_current_user_id():
    if current_user.is_authenticated:
        return current_user.id
    else:
        return None  

    
# Callback to reload the user object
@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)

# Routes
@app.route('/')
def index():
    return render_template('index.html', user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    # TODO 1: Implement the user registration.
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']


        if check_user_exists(username):
            flash('This username already exists', category='error')
        elif password != confirm_password:
            flash('Passwords do not match', category='error')
        elif len(password) < 8:  
            flash('Password must be at least 8 characters', category='error')
        
        else:
            password = generate_password_hash(password, method='sha256' )
            add_user(username, password)

            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            id = cursor.fetchone()[0]  # Extract the user ID
            conn.close()
            # Create a User object
            new_user = User(id, username, password)
            login_user(new_user, remember=True)
            
            return redirect(url_for('index'))

    return render_template('register.html', user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # TODO 2: Implement the user login.
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if check_user_exists(username):
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            id = cursor.fetchone()[0]  # Extract the user ID
            cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
            passw = cursor.fetchone()[0]  # Extract the password
            conn.close()

            user = User(id, username, passw)
            if check_password_hash(passw, password):
                login_user(user, remember=True)
                flash('Logged in successfully!', category='success')
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect password, try again', category='error')
        else:
            flash('username does not exist', category='error')

    return render_template('login.html', user=current_user, error=error)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # TODO 3: Implement the function for adding websites to user profiles.
    if request.method == 'POST':
        websitename = request.form['website_name']
        websiteurl = request.form['website_url']
        user_id = get_current_user_id()
        add_website(user_id, websitename, websiteurl)

    # Fetch the websites for the current user
    user_id = get_current_user_id()
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, url FROM websites WHERE user_id = ?", (user_id,))
    websites = cursor.fetchall()
    conn.close()

    # Convert the fetched websites into a list of Website objects
    website_objects = [Website(id=row[0], user_id=user_id, name=row[1], url=row[2]) for row in websites]

    return render_template('dashboard.html', user=current_user, websites=website_objects)

@app.route('/dashboard/<int:website_id>/delete', methods=['POST'])
@login_required
def delete(website_id):

    # TODO 4: Implement the function for deleting websites from user profiles.
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM websites WHERE id = ?", (website_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("dashboard"))

def create_tables():
    # Creates new tables in the database.db database if they do not already exist.
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    with current_app.open_resource("schema.sql") as f:
        c.executescript(f.read().decode("utf8"))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)
