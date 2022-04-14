from flask import Blueprint, render_template, request, flash, redirect, url_for
from sqlalchemy.exc import IntegrityError
from . import db
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint("auth", __name__)


@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        print(email)
        print(password)
        user = User.query.filter_by(email=email).first()
        print(user.password)
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in Successfully", category="success")
                login_user(user, remember=True)
                return redirect(url_for("views.landing_page"))
            else:
                flash("Incorrect Password, try again", category ="error")
        else:
            flash("Email doesn't exist.", category="error")

    return render_template("login.html", user = current_user)

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))

@auth.route("/sign-up", methods =["GET", "POST"])
def sign_up():
    if request.method == "POST":
        email = request.form.get("email")
        first_name = request.form.get("firstName")
        lastName = request.form.get("lastName")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        user = User.query.filter_by(email=email).first()

        if user:
            flash("Email already exists!", category="error")

        elif len(email) < 4:
            flash("Email must be greater than 4 Characters", category="error")
        elif len(first_name) < 2:
            flash("First Name must be longer than 2 Characters", category="error")
        elif len(password1) < 7:
            flash("Password must be longer than 7 Characters", category="error")
        elif password1 != password2:
            flash("Passwords don't match.", category="error")
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1,"sha256"))
            try:
                db.session.add(new_user)
                db.session.commit()
                login_user(user, remember=True)
                print("did work")
            except IntegrityError:
                db.session.rollback()
                print("didn't work")

            return redirect(url_for("views.home"))


    return render_template("sign_up.html", user = current_user)



