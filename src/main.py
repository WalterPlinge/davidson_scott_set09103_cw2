import ConfigParser
import logging
import hashlib
import os
import random
import sqlite3
import uuid

from flask import abort, flash, Flask, g, json, make_response, redirect, render_template, request, session, url_for
from logging.handlers import RotatingFileHandler


# Flask app and secret key
app = Flask(__name__)
app.secret_key = os.urandom(64)
app_name = "PixlHaven"


# Database
db_connection = sqlite3.connect("data/data.db")


def db_create():
    db_cursor = db_connection.cursor()
    table_create_users = """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT NOT NULL,
            password TEXT NOT NULL, 
            email TEXT,
            date DATETIME NOT NULL,
            bio TEXT,
            PRIMARY KEY (username)
        ); """
    table_create_gallery = """
        CREATE TABLE IF NOT EXISTS gallery (
            username TEXT NOT NULL,
            date DATETIME NOT NULL,
			title TEXT NOT NULL,
			description TEXT,
            PRIMARY KEY (username, date),
            FOREIGN KEY (username) REFERENCES users (username)
        ); """
    table_create_favourites = """
        CREATE TABLE IF NOT EXISTS favourites (
			username TEXT NOT NULL,
			target TEXT NOT NULL,
			date DATETIME NOT NULL,
            PRIMARY KEY (username, target, date),
            FOREIGN KEY (username) REFERENCES users (username),
            FOREIGN KEY (target) REFERENCES users (username),
            FOREIGN KEY (target) REFERENCES gallery (username),
            FOREIGN KEY (date) REFERENCES gallery (date)
        ); """
    table_create_comments = """
        CREATE TABLE IF NOT EXISTS comments (
			username TEXT NOT NULL,
			date DATETIME NOT NULL,
			title TEXT NOT NULL,
			message TEXT NOT NULL,
            PRIMARY KEY (username, date),
            FOREIGN KEY (username) REFERENCES users (username),
            FOREIGN KEY (username) REFERENCES gallery (username),
            FOREIGN KEY (date) REFERENCES gallery (date)
        ); """

    db_cursor.execute(table_create_users)
    db_cursor.execute(table_create_gallery)
    db_cursor.execute(table_create_favourites)
    db_cursor.execute(table_create_comments)

    db_connection.commit()


# App routing
@app.route('/')
def home():
    return render_template('home.html', pagetitle=app_name)


@app.route('/browse/')
def browse():
    return render_template('browse.html', pagetitle=app_name)


@app.route('/search/', methods=['POST'])
def search():
    query = request.form['search']
    return redirect(url_for('searchterm', urlquery=query))


@app.route('/search/<urlquery>')
def searchterm(urlquery=None):
    if urlquery == None:
        return redirect(url_for('.home'))
    else:
        return render_template('home.html', pagetitle=urlquery)


@app.route('/categories/')
@app.route('/categories/<urlcategory>')
def categories(urlcategory=None):
    if urlcategory == None:
        return render_template('categories.html', pagetitle=app_name)
    else:
        return render_template('browse.html', pagetitle=urlcategory)


@app.route('/login', methods=['POST'])
def login():
    return render_template('login.html')


@app.route('/register', methods=['POST'])
def register():
    return render_template('register.html')


@app.route('/reset')
def reset():
    return render_template('reset.html')


@app.route('/logout')
def logout():
    return redirect(url_for('.home'))


@app.route('/<urluser>')
def user(urluser=None):
    return render_template('user.html', pagetitle=urluser)


@app.route('/<urluser>/gallery/')
def gallery(urluser=None):
    return render_template('gallery.html', pagetitle=urluser)


@app.route('/<urluser>/favourites/')
def favourites(urluser=None):
    return render_template('gallery.html', pagetitle=urluser)


@app.route('/<urluser>/<urltitle>')
def picture(urluser=None, urltitle=None):
    return render_template('picture.html', pagetitle=urltitle)


@app.route('/<urluser>/<urltitle>/edit')
def edit(urluser=None, urltitle=None):
    return render_template('edit.html')


@app.route('/<urluser>/upload')
def upload(urluser=None):
    return render_template('upload.html')


@app.route('/<urluser>/settings')
def settings(urluser=None):
    return render_template('settings.html')


@app.route('/error/<int:status>')
def error(status=404):
    message = ''
    if status == 404:
        message = 'Sorry, the page you requested is not available.'
    if status == 405:
        message = 'Sorry, you cannot access this page this way.'
    if status == 418:
        message = 'Sorry, this page has not been added yet.'
    return render_template('error.html', message=message)


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
    db_connection.close()
