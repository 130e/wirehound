from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired

from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo

from app.models import User

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class UploadForm(FlaskForm):
    userfile = FileField('Traffic file', validators=[FileRequired()])
    submit = SubmitField('Upload')

class DeleteForm(FlaskForm):
    fname = BooleanField("")
    submit = SubmitField("Delete")

class FilterForm(FlaskForm):
   ipfilter = StringField('IP Filter') 
   portfilter = StringField('Port Filter')
   tcp = BooleanField('TCP')
   udp = BooleanField('UDP')
   icmp = BooleanField('ICMP')
   timefilter = StringField('Time Filter')
   sizefilter = StringField('Size Filter')
   submit = SubmitField('Confirm')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')
   
