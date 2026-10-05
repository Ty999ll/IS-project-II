import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cfds.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    from . import models  # noqa: F401  (import so db.create_all() sees the tables)

    @login_manager.user_loader
    def load_user(user_id):
        return models.User.query.get(int(user_id))

    from .auth.routes import auth_bp
    from .scan.routes import scan_bp
    from .report.routes import report_bp
    from .sandbox.routes import sandbox_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(sandbox_bp)

    with app.app_context():
        db.create_all()

    return app
