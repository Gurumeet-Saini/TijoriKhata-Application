from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, ValidationError
import bcrypt
import time
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)
db = SQLAlchemy(app)

customers = []

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Registration Form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different one.')
        
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = User(username=username, email=email, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash("Registration Successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html', time=int(time.time()))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if email:
            user = User.query.filter_by(email=email).first()
        else:
            user = None
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['last_active'] = int(time.time())
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')

    return render_template('login.html', time=int(time.time()))

@app.route('/')
def main():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))  # Redirect logged-in user to Dashboard
    return render_template('MainPage.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        last_active = session.get('last_active', 0)
        if time.time() - last_active > 60:  # Check if session is older than 1 min
            session.clear()
            flash('Session expired. Please log in again.', 'warning')
            return redirect(url_for('login'))

        session['last_active'] = int(time.time())  # Reset last active time
        return render_template('dashboard.html', username=session['username'], customers=customers)
    
    return redirect(url_for('login'))

@app.route('/add_customer', methods=['POST'])
def add_customer():
    name = request.form['name']
    phone = request.form['phone']
    sr = request.form['sr']
    money = request.form['money']
    customer_id = len(customers) + 1
    customers.append({'id': customer_id, 'name': name, 'phone': phone, 'sr': sr, 'money': money})
    return redirect(url_for('dashboard'))

@app.route('/delete_customer/<int:customer_id>')
def delete_customer(customer_id):
    global customers
    # Remove customer by matching ID
    customers = [customer for customer in customers if customer['id'] != customer_id]
    
    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)