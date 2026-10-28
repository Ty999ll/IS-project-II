"""
App factory. create_app() builds and wires up the whole Flask application:
config, the database, login handling, and all the blueprints (the groups of
routes). run.py calls this once to get the app object it serves.

I used the "application factory" pattern (a function that returns the app)
instead of a global app so the tests can build their own fresh copy.
"""
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# These are created here but not tied to an app yet - init_app() below attaches
# them. db is the SQLAlchemy handle every model and query uses; login_manager
# keeps track of who's logged in.
db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    app = Flask(__name__)
    # SECRET_KEY signs the login session cookie and the password-reset tokens.
    # It comes from the environment; the fallback is only for local dev.
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
    # The database is a single SQLite file created at instance/cfds.db.
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cfds.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False  # off to avoid a warning

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"  # where @login_required sends guests

    from . import models  # noqa: F401  (need to import this so db.create_all() can find the tables)

    # Flask-Login uses this to turn the id stored in the cookie back into a User.
    @login_manager.user_loader
    def load_user(user_id):
        return models.User.query.get(int(user_id))

    # Each feature lives in its own blueprint (a mini set of routes); register
    # them all so their pages become reachable.
    from .auth.routes import auth_bp
    from .scan.routes import scan_bp
    from .report.routes import report_bp
    from .sandbox.routes import sandbox_bp
    app.register_blueprint(auth_bp)      # register / login / logout / password reset
    app.register_blueprint(scan_bp)      # dashboard, new scan, results
    app.register_blueprint(report_bp)    # view / download the report
    app.register_blueprint(sandbox_bp)   # training challenges

    # Create any tables that don't exist yet. NOTE: this only CREATES missing
    # tables, it never ALTERS existing ones - so after changing a model you have
    # to delete instance/cfds.db and restart to pick up the change.
    with app.app_context():
        db.create_all()

    return app
