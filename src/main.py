import ConfigParser
import logging
import hashlib
import os
import random
import time
import uuid

from database import db_create, db_match_password, db_register, db_user_exists
from flask import abort, flash, Flask, g, json, make_response, redirect, render_template, request, session, url_for
from logging.handlers import RotatingFileHandler


# Flask app and secret key
app = Flask(__name__)
app.secret_key = os.urandom(64)
app_name = "PixlHaven"


def get_user():
    if 'username' in session:
        return session['username']
    return None


# App routing
@app.route('/')
def home():
    user = get_user()

    return render_template('home.html', pagetitle=app_name, user=user)


@app.route('/browse/')
def browse():
    user = get_user()

    return render_template('browse.html', pagetitle=app_name, user=user)


@app.route('/search/', methods=['POST'])
def search():
    query = request.form['search']
    return redirect(url_for('searchterm', urlquery=query))


@app.route('/search/<urlquery>')
def searchterm(urlquery=None):
    user = get_user()

    if urlquery == None:
        return redirect(url_for('.home'))
    else:
        return render_template('home.html', pagetitle=urlquery, user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if get_user():
        return redirect(url_for('home'))

    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # SALT PASSWORD
        if not db_user_exists(username):
            error = 'User does not exist.'
        elif not db_match_password(username, password):
            error = 'Invalid password.'
        else:
            session['username'] = username
            return redirect(url_for('home'))
    return render_template('login.html', pagetitle='Log in', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if get_user():
        return redirect(url_for('home'))

    error = None
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password1 = request.form['password1']
        password2 = request.form['password2']

        if db_user_exists(username):
            error = 'Username already taken.'
        elif password1 != password2:
            error = 'Passwords do not match.'
        else:
            # SALT PASSWORD
            db_register(email, username, password1)
            session['username'] = username
            return redirect(url_for('home'))
    return render_template('register.html', pagetitle='Register', error=error)


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if get_user():
        return redirect(url_for('home'))

    return render_template('reset.html', pagetitle='Reset')


@app.route('/logout')
def logout():
    if 'username' in session:
        session.pop('username', None)

    return redirect(url_for('home'))


@app.route('/<urluser>')
def user(urluser=None):
    user = get_user()

    return render_template('user.html', pagetitle=urluser, user=user)


@app.route('/<urluser>/gallery/')
def gallery(urluser=None):
    user = get_user()

    return render_template('gallery.html', pagetitle=urluser, user=user)


@app.route('/<urluser>/favourites/')
def favourites(urluser=None):
    user = get_user()

    return render_template('gallery.html', pagetitle=urluser, user=user)


@app.route('/<urluser>/<urltitle>')
def picture(urluser=None, urltitle=None):
    user = get_user()

    return render_template('picture.html', pagetitle=urltitle, user=user)


@app.route('/<urluser>/<urltitle>/edit')
def edit(urluser=None, urltitle=None):
    user = get_user()

    if not user or user != urluser:
        return redirect(url_for('picture', urluser=urluser, urltitle=urltitle))

    return render_template('edit.html', pagetitle='Edit', user=user)


@app.route('/upload')
def upload():
    user = get_user()

    if not user:
        return redirect(url_for('login'))

    return render_template('upload.html', pagetitle='Upload', user=user)


@app.route('/settings')
def settings():
    user = get_user()

    if not user:
        return redirect(url_for('login'))

    return render_template('settings.html', pagetitle='Settings', user=user)


@app.route('/error/<int:status>')
def error(status=404):
    user = get_user()

    message = ''
    if status == 404:
        message = 'Sorry, the page you requested is not available.'
    if status == 405:
        message = 'Sorry, you cannot access this page this way.'
    if status == 418:
        message = 'Sorry, this page has not been added yet.'
    return render_template('error.html', pagetitle=status, message=message, user=user)


# Error handling
@app.errorhandler(404)
def error404(error):
    return redirect(url_for('.error', status=404))


@app.errorhandler(405)
def error405(error):
    return redirect(url_for('.error', status=405))


@app.errorhandler(418)
def error418(error):
    return redirect(url_for('.error', status=418))


# Initialisation
def init(app):
    config = ConfigParser.ConfigParser()
    try:
        config_location = 'etc/defaults.cfg'
        config.read(config_location)

        app.config['DEBUG'] = config.get('config', 'debug')
        app.config['ip_address'] = config.get('config', 'ip_address')
        app.config['port'] = config.get('config', 'port')
        app.config['url'] = config.get('config', 'url')

        app.config['log_file'] = config.get('logging', 'name')
        app.config['log_location'] = config.get('logging', 'location')
        app.config['log_level'] = config.get('logging', 'level')
    except:
        print 'Could not read configs from ', config_location


# Logging
def logs(app):
    log_pathname = app.config['log_location'] + app.config['log_file']
    file_handler = RotatingFileHandler(
        log_pathname,
        maxBytes=1024 * 1024 * 10,
        backupCount=1024
    )
    file_handler.setLevel(app.config['log_level'])
    formatter = logging.Formatter(
        "%(levelname)s | %(asctime)s | %(module)s | %(funcName)s | %(message)s")
    file_handler.setFormatter(formatter)
    app.logger.setLevel(app.config['log_level'])
    app.logger.handlers.append(file_handler)


# Run app
if __name__ == '__main__':
    init(app)
    logs(app)
    db_create()
    app.run(
        host=app.config['ip_address'],
        port=int(app.config['port']),
        ssl_context=('cert.pem', 'key.pem')
    )
