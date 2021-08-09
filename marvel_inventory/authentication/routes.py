from flask import Blueprint, render_template, request, redirect, url_for, flash
from marvel_inventory.forms import UserLoginForm
from marvel_inventory.models import User, db, check_password_hash
from flask_login import login_user, logout_user, login_required

auth = Blueprint('auth', __name__, template_folder='auth_templates')

@auth.route('/signup', methods = ['GET', 'POST'])
def signup():
    form = UserLoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        print([email, password])
        new_user = User(email, password)
        db.session.add(new_user)
        db.session.commit()
        flash(f'You "{email}" now part of the prestigious Hero portal, dont mess this up kid', 'create-success')
        return redirect(url_for('auth.signin'))

    return render_template('signup.html', form = form)

@auth.route('/signin', methods = ['GET', 'POST'])
def signin():
    form = UserLoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        print([email, password])
        logged_user = User.query.filter(User.email == email).first()
        if logged_user and check_password_hash(logged_user.password, password):
            login_user(logged_user)
            flash('You have successfully logged in!', 'auth-success')
            return redirect(url_for('site.home'))
        else:
            flash('Incorrect email/password. Please try again, if you are worthy', 'auth-fail')
            return redirect(url_for('auth.signin'))


    return render_template('signin.html', form = form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have successfully logged out.', 'auth-success')
    return redirect(url_for('site.home'))