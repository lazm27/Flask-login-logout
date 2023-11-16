from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, user_id, full_name, email, username, password):
        self.id = user_id
        self.full_name = full_name
        self.email = email
        self.username = username
        self.password = password

users = {
    1: User(1, 'Lazeen Manasia', 'lazeen@gmail.com', 'lazeen', bcrypt.generate_password_hash('Lazeen').decode('utf-8')),
    2: User(2, 'admin', 'admin@gmail.com', 'admin', bcrypt.generate_password_hash('admin').decode('utf-8'))
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = next((user for user in users.values() if user.username.lower() == username.lower()), None)
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user_id = max(users.keys()) + 1
        new_user = User(user_id, full_name, email, username, hashed_password)
        users[user_id] = new_user

        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
