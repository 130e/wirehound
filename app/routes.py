from flask import render_template, flash, redirect, url_for
from app import app
from app.forms import LoginForm, FileForm
from werkzeug.utils import secure_filename
import os

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', title='Home')

@app.route('/graph')
def graph():
    return render_template('graph.html', title='Graph')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        flash('Login requested for user {}, remember_me={}'.format(
            form.username.data, form.remember_me.data))
        return redirect(url_for('index'))
    return render_template('testform.html', title='Sign In', form=form)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    form = FileForm()
    if form.validate_on_submit():
        f = form.user_file.data
        filename = secure_filename(f.filename)
        f.save(os.path.join(
            app.config['UPLOAD_FOLDER'], filename
        ))
        return redirect(url_for('index'))

    return render_template('uploadform.html', title='Upload', form=form)
