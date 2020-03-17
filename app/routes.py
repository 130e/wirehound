import os
import re
from pathlib import Path
from flask import render_template, flash, redirect, url_for, request, send_file, send_from_directory, make_response
from app import app
from app import forms
from app import db
from app import tdg
from werkzeug.utils import secure_filename
from werkzeug.urls import url_parse
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User

def getFileList():
    uname = current_user.username
    upath = app.config['UPLOAD_FOLDER_ROOT']+uname
    dirs = []
    for fname in os.listdir(upath):
        tpath = os.path.join(upath, fname)
        if not os.path.isdir(tpath):
            dirs.append(fname)

    return dirs

@app.route('/')
@app.route('/index')
@app.route('/filepage', methods=['GET', 'POST'] )
@login_required
def index():
    # init 2 forms
    upform = forms.UploadForm()
    fl = getFileList()
    deform = forms.DeleteFormBuilder(fl)

    return render_template('filepage.html',title='My Files', upform=upform, deform=deform)

@app.route('/upload', methods=['POST'] )
@login_required
def upload():
    upform = forms.UploadForm()

    uname = current_user.username
    upath = app.config['UPLOAD_FOLDER_ROOT']+uname

    if upform.validate_on_submit():
        f = upform.userfile.data
        filename = secure_filename(f.filename)
        f.save(os.path.join(upath, filename))
    return redirect(url_for('index'))
    #return render_template('filepage.html',title='My Files', upform=upform, deform=deform)

@app.route('/delete', methods=['POST'] )
@login_required
def delete():
    fl = getFileList()
    deform = forms.DeleteFormBuilder(fl)

    uname = current_user.username
    upath = app.config['UPLOAD_FOLDER_ROOT']+uname

    if deform.validate_on_submit():
        for f in deform:
            if 'file' in f.name and f.data == True:
                os.remove(os.path.join(upath, f.label.text))

    return redirect(url_for('index'))
    #return render_template('filepage.html',title='My Files', upform=upform, deform=deform)

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
def filter(file):
    form = forms.FilterForm()
    if form.validate_on_submit():
        def convertInt(listinput):
            listoutput = []
            if len(listinput) ==0 :
                return None
            for i in listinput:
                if len(i) != 0:
                    listoutput.append(int(i))
            if len(listoutput) == 2:
                return tuple(listoutput)
            elif len(listoutput) == 1:
                listoutput.append(-1)
                return tuple(listoutput)
            elif len(listoutput) >2 :
                return tuple(listoutput[:2])
            else:
                return None
        t_ipFt = form.ipfilter.data
        t_portFt = form.portfilter.data
        t_timeFt = convertInt(form.sizefilter.data.split(','))
        t_sizeFt = convertInt(form.timefilter.data.split(','))
        t_protoFt = []
        if form.tcp.data == True : 
            t_protoFt.append('TCP')
        if form.udp.data == True :
            t_protoFt.append('UDP')
        if form.icmp.data == True :
            t_protoFt.append('ICMP')
        rpath = app.config['UPLOAD_FOLDER_ROOT']+current_user.username+'/'+file + '_result'
        #os.mkdir(rpath)
        Path(rpath).mkdir(parents=True, exist_ok=True)
        targetfile = app.config['UPLOAD_FOLDER_ROOT']+ current_user.username + "/" + file
        tdg_filteredpacket = tdg.Graphware_ReadNFilter(targetfile, ipFilter=t_ipFt, portFilter=t_portFt, timeFilter=t_timeFt,lengthFilter=t_sizeFt,protoFilter=t_protoFt)
        tdg_resultpath = tdg.Graphware_Generate(tdg_filteredpacket, rpath)
        return  redirect(url_for('result', file=file))
    return render_template('filterpage.html', title='Select Filter', form=form, file=file)

@login_required
@app.route('/result/<string:file>')
def result(file=None):
    return render_template('resultpage.html', file=file)

@login_required
@app.route('/download/<string:file>/<string:rettype>')
def download(file,rettype):
    if rettype not in ['json','html','data']:
        return '<h1>Format Not Supported</h1> '

    rdir = os.getcwd() + '/app/userfiles/'+current_user.username+'/'+file + '_result/' 
    rfile = 'efp.' + rettype
    resp = make_response(send_from_directory(rdir,rfile,as_attachment=True))
    resp.headers["Content-Disposition"] = "attachment;filename="+rfile+";"
    return resp

@login_required
@app.route('/display/<string:file>')
def display(file):
    rdir = os.getcwd() + '/app/userfiles/'+current_user.username+'/'+file + '_result/' 
    rfile = 'efp.html' 
    resp = make_response(send_from_directory(rdir,rfile,as_attachment=False))
    return resp

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
