from flask import Flask
from config import Config
from .authentication.routes import auth
from .site.routes import site
from .models import db, User, login_manager
from flask_migrate import Migrate

app = Flask(__name__)

app.config.from_object(Config)
db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = 'auth.signin'

migrate = Migrate(app, db)

app.register_blueprint(site)
app.register_blueprint(auth)

