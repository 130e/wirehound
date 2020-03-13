from app import app, db
from app.models import User, Folder

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Folder': Folder}
