import os
from flask import render_template, flash, redirect, url_for, request
from app import app
from app import forms
from app import db
from werkzeug.utils import secure_filename
from werkzeug.urls import url_parse
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User

# Dev note
# I put the form into front page in its modal
# remember redirect looks for function name not route url

@app.route('/')
@app.route('/index')
@app.route('/filepage', methods=['GET', 'POST'] )
@login_required
def index():
    form = forms.FileForm()
    uname = current_user.username
    upath = app.config['UPLOAD_FOLDER_ROOT']+uname
    walkedlist = []
    if form.validate_on_submit():
        f = form.userfile.data
        filename = secure_filename(f.filename)
        f.save(os.path.join(upath, filename))
        return redirect(url_for('index'))
    osg = os.walk(upath)
    for _,_,walkedlist in osg:
        pass
    return render_template('filepage.html',title='My Files', form=form, walkedlist=walkedlist)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = forms.LoginForm()
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

@login_required
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = forms.RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        upath = app.config['UPLOAD_FOLDER_ROOT']+user.username
        os.mkdir(upath)
        flash('Registration complete! Welcome to Wirehound.')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@login_required
@app.route('/filter/<string:file>', methods=['GET', 'POST'])
def filter(file=None):
    form = forms.FilterForm()
    if form.validate_on_submit():
        targetfile = app.config['UPLOAD_FOLDER_ROOT']+ current_user.username + "/" + file
        # TODO
        # remember to add file to result page
        return redirect(url_for('index'))

    return render_template('filterpage.html', title='Select Filter', form=form, file=file)

@login_required
@app.route('/result/<string:file>')
def result():
    returngrapoh_path = "/static/mygraph.html"
    return render_template('resultpage.html',filepath=filepath, ret_gpath = returngrapoh_path)


# @app.route('/upload', methods=['GET', 'POST'])
# @login_required
# def upload():
    # form = FileForm()
    # if form.validate_on_submit():
        # f = form.userfile.data
        # filename = secure_filename(f.filename)
        # f.save(os.path.join(
            # app.config['UPLOAD_FOLDER'], filename))
        # return redirect(url_for('index'))

    # return render_template('uploadform.html', title='Upload', form=form)
