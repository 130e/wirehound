from flask import Flask
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from config import Config

app = Flask(__name__, static_url_path='/static')
Bootstrap(app)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
# add the login view
# so @login_required could find it
login.login_view = 'login'

from app import routes, models

if __name__ == '__main__':
    app.run(debug=true)
