from flask import Flask, render_template, request, redirect, session, send_file, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
import bcrypt
from datetime import datetime
from bs4 import BeautifulSoup
import requests
import re
from flask_share import Share
from werkzeug.utils import secure_filename
import os
from flask_bcrypt import Bcrypt

from functools import wraps
from flask import abort
from flask_login import current_user
from flask_migrate import Migrate

UPLOAD_FOLDER = './static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ADMINUSER = 'admin'
ADMINPASSWORD = 'password12'


share = Share()
app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


share.init_app(app)
db = SQLAlchemy(app)
migrate = Migrate(app,db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/admin/login'


app.secret_key = 'secret_key'
bcrypt = Bcrypt()
app.app_context().push()

@login_manager.user_loader
def load_user(user_id):
    return AdminUser.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/about_us')
def about_us():
    return render_template('about_us.html')


@app.route('/register', methods=['Get', 'POST'])
def register():
    if request.method == 'POST':
        # handle request
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/admin/login', methods=['Get', 'POST'])
def adminLogin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = AdminUser.query.filter_by(username=username).first()
        print(user)
        if user:
            if password == user.password:
                login_user(user)
                next = request.args.get('next')
                print(next)
                return redirect(next or url_for('playersAdd'))
            else:
                return render_template('admin-login.html', errorMsg='Invalid Admin Credentials')
        else:
            return render_template('admin-login.html', errorMsg='Invalid Admin Credentials')
    return render_template('admin-login.html', errorMsg='')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = email
            return redirect('/dashboard')
        else:
            flash('Invalid email or password', 'error')

    return render_template('login.html')

@login_required
@app.route('/dashboard')
def dashboard():
    if session['email']:
        user = User.query.filter_by(email=session['email']).first()
        return render_template('dashboard.html', user=user)

    return redirect('/login')


@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')


@app.route('/admin/logout', methods=['GET', 'POST'])
@login_required
def adminLogout():
    logout_user()
    return redirect('/admin/login')

