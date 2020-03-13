from flask import render_template, flash, redirect, url_for, request
from app import app
from app.forms import LoginForm, FileForm
from werkzeug.utils import secure_filename
from werkzeug.urls import url_parse
import os
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User

@app.route('/')
@app.route('/index')
@app.route('/filepage')
@login_required
def index():
    return render_template('filepage.html', title='My Files')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    # if get or bad form it retuns false
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = FileForm()
    if form.validate_on_submit():
        f = form.user_file.data
        filename = secure_filename(f.filename)
        f.save(os.path.join(
            app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('index'))

    return render_template('uploadform.html', title='Upload', form=form)
