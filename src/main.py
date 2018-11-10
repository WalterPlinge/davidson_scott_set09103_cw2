import ConfigParser
import logging
import os
import random
import sqlite3

from flask import abort, flash, Flask, g, json, make_response, redirect, render_template, request, session, url_for
from logging.handlers import RotatingFileHandler


app = Flask(__name__)
app.secret_key = os.urandom(64)

global_pagetitle = "PixlHaven"


@app.route('/')
def home():
    return render_template('home.html', pagetitle=global_pagetitle)


@app.route('/browse/')
def browse():
    return render_template('browse.html', pagetitle=global_pagetitle)


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
        return render_template('categories.html', pagetitle=global_pagetitle)
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
        message = 'Sorry, the page does not support such a request.'
    if status == 418:
        message = 'Sorry, this page has not been added yet.'
    return render_template('error.html', message=message)


@app.errorhandler(404)
def error404(error):
    return redirect(url_for('.error', status=404))


@app.errorhandler(405)
def error405(error):
    return redirect(url_for('.error', status=405))


@app.errorhandler(418)
def error418(error):
    return redirect(url_for('.error', status=418))


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


if __name__ == 'main':
    init(app)
    logs(app)
    app.run(
        host=app.config['ip_address'],
        port=int(app.config['port'])
    )
