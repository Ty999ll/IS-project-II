from flask import (Blueprint, render_template, redirect, url_for, request, flash, session,
                   current_app)
from flask_login import login_user, logout_user, login_required
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from .. import db
from ..models import User, Organization

auth_bp = Blueprint("auth", __name__)

# How long a password-reset link stays valid.
RESET_MAX_AGE = 3600  # one hour, in seconds


def _reset_serializer():
    """Signs/reads password-reset tokens with the app's SECRET_KEY. Using a
    signed, time-limited token means no reset table or column is needed, so the
    models (which must match the design diagrams) don't change."""
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="password-reset")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        org_name = request.form["org_name"].strip()
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        role = request.form.get("role", "IT_GENERALIST")

        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
            return render_template("register.html")

        # if the org doesn't exist yet the first person to register makes it,
        # anyone after that with the same org name just gets added to it
        org = Organization.query.filter_by(name=org_name).first()
        if org is None:
            org = Organization(name=org_name)
            db.session.add(org)
            db.session.flush()  # flush so we have org.org_id before committing

        user = User(org_id=org.org_id, name=name, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Account created — please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()
        if user is None or not user.check_password(password):
            flash("Invalid email or password.", "error")
            return render_template("login.html")
        login_user(user)
        return redirect(url_for("scan.dashboard"))

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("target_sessions", None)  # forget saved logins to target sites too
    return redirect(url_for("auth.login"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Step 1 of reset: the user enters their email and gets a reset link.

    There's no mail server in this project, so the link is shown on screen (and
    printed to the server log) instead of emailed - a documented simplification.
    The confirmation message is the same whether or not the email is on file, so
    the page can't be used to find out which emails have accounts."""
    reset_link = None
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        user = User.query.filter_by(email=email).first()
        if user is not None:
            token = _reset_serializer().dumps(str(user.user_id))
            reset_link = url_for("auth.reset_password", token=token, _external=True)
            current_app.logger.info("Password reset link for %s: %s", email, reset_link)
        flash("If that email has an account, a password reset link has been generated below.",
              "info")
        return render_template("forgot_password.html", reset_link=reset_link)

    return render_template("forgot_password.html", reset_link=None)


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """Step 2 of reset: validate the token and set a new password."""
    try:
        user_id = _reset_serializer().loads(token, max_age=RESET_MAX_AGE)
    except SignatureExpired:
        flash("That reset link has expired. Please request a new one.", "error")
        return redirect(url_for("auth.forgot_password"))
    except BadSignature:
        flash("That reset link isn't valid. Please request a new one.", "error")
        return redirect(url_for("auth.forgot_password"))

    user = User.query.get(int(user_id))
    if user is None:
        flash("That account no longer exists.", "error")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        password = request.form["password"]
        confirm = request.form.get("confirm", "")
        if len(password) < 6:
            flash("Choose a password of at least 6 characters.", "error")
            return render_template("reset_password.html", token=token)
        if password != confirm:
            flash("The two passwords don't match.", "error")
            return render_template("reset_password.html", token=token)
        user.set_password(password)
        db.session.commit()
        flash("Your password has been reset — please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html", token=token)
