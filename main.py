from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# Init Flask_login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login" # Redirect to login page if not logged in



class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CREATE TABLE IN DB

# UserMixin, Flask-Login (is_authenticated, active, annoymous and get_id)
class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))
    salt: Mapped[str] = mapped_column(String(100)) # add the salt column


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")

# Generating a random salt
def generate_salt(length=9):
    return os.urandom(length).hex()


@app.route('/register', methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form.get('email')
        # Check if the email already exist
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already exists. Please use a different email")
            return redirect(url_for("register"))

        salt = generate_salt()
        new_user = User(
            email=email,
            name = request.form.get('name'),
            # Good practice not to store password in plaintext
            password = generate_password_hash(request.form.get('password') + salt),
            salt = salt # Store the salt in the db 
        )
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))
    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            # Combine entered password with the stored salt
            salted_password = password + user.salt
            if check_password_hash(user.password, salted_password):
                login_user(user)
                return redirect(url_for("secrets", name=user.name))
            else:
                print("Flashing invalid password")
                flash("Invalid password. Please try again", "danger")
        else:
            print("Flashing invalid email")
            flash("Invalid email or password, please try again.", "danger")
    return render_template("login.html")


@app.route('/secrets')
@login_required # Decorator to protect it
def secrets():
    name = request.args.get('name')
    return render_template("secrets.html", name= name)

# Load user from database by their ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# https://flask.palletsprojects.com/en/stable/api/#flask.send_from_directory
# To send file from directory using flask func
@app.route('/download_file')
def download_file():
    # Path to the directory containing the files
    directory = 'static'
    try:
        # use send_from_directory to serve the file
        return send_from_directory(directory, path='files/dummy.pdf')
    except Exception as e:
        return str(e), 404
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
