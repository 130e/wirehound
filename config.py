import os

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or '130E028'
    UPLOAD_FOLDER = './user_file/'
