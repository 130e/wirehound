import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or \
            b'\xc7>\x1b\x16\x97\xf5\xd5q\x99\xfa\xeb\xfd-\xa2\xb0\xff'
    UPLOAD_FOLDER_ROOT = 'app/userfiles/'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
