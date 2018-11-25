import bcrypt
import ConfigParser
import database
import datetime
import logging
import hashlib
import os
import random
import shutil
import time
import uuid

from datetime import datetime
from flask import abort, flash, Flask, g, json, make_response, redirect, render_template, request, session, url_for
from logging.handlers import RotatingFileHandler
from werkzeug.utils import secure_filename


# Flask app and secret key
app = Flask(__name__)
app.secret_key = os.urandom(64)
app_name = "PixlHaven"


def get_time(etime):
    return datetime.utcfromtimestamp(etime).strftime('%Y%m%d%H%M%S')


def get_formatted_time(etime):
    return datetime.utcfromtimestamp(etime).strftime('%H:%M %d-%m-%Y')


def get_epoch_time(ftime):
    return time.mktime(time.strptime(ftime, '%Y%m%d%H%M%S'))


def logged_in():
    return 'username' in session


def get_user(username=None):
    user = None
    if username:
        user = database.get_user(username)
    elif logged_in():
        user = database.get_user(session['username'])
    else:
        return None

    if not user:
        return None

    file = app.config['upload_folder'] + user['username'] + '/' + user['username'] + '.png'
    avatar = None
    if os.path.isfile(file):
        avatar = url_for('static', filename='uploads/' + user['username'] + '/' + user['username'] + '.png')
    else:
        avatar = url_for('static', filename='img/default_avatar.png')

    return {
        'username': user['username'],
        'password': user['password'],
        'email': user['email'],
        'date_joined': user['date_joined'],
        'date_joined_formatted': get_formatted_time(get_epoch_time(user['date_joined'])),
        'rank': user['rank'],
        'description': user['description'],
        'avatar': avatar,
    }


def get_picture(user, date):
    picture = database.get_picture(user, date)
    if not picture:
        return None

    file = url_for('static', filename='uploads/' + picture['author'] + '/' + picture['date_uploaded'] + '.png')
    return {
        'file': file,
        'author': picture['author'],
        'date_uploaded': picture['date_uploaded'],
        'date_uploaded_formatted': get_formatted_time(get_epoch_time(picture['date_uploaded'])),
        'title': picture['title'],
        'description': picture['description'],
    }


def get_pictures(user=None):
    pictures = database.get_pictures(user)

    if not pictures:
        return None

    output = []
    for p in pictures:
        output.append({
            'file': url_for('static', filename=p['author'] + '/' + p['date_uploaded'] + '.png'),
            'author': p['author'],
            'date_uploaded': p['date_uploaded'],
            'date_uploaded_formatted': get_formatted_time(get_epoch_time(p['date_uploaded'])),
            'title': p['title'],
            'description': p['description']
        })

    return output


def get_friends_pictures(user=None):
    pictures = database.get_friends_pictures(user)

    if not pictures:
        return None

    output = []
    for p in pictures:
        output.append({
            'file': url_for('static', filename=p['author'] + '/' + p['date_uploaded'] + '.png'),
            'author': p['author'],
            'date_uploaded': p['date_uploaded'],
            'date_uploaded_formatted': get_formatted_time(get_epoch_time(p['date_uploaded'])),
            'title': p['title'],
            'description': p['description']
        })

    return output


def get_favourites(user=None):
    if not user and logged_in():
        user = session['username']

    favourites = database.get_favourites(user)

    if not favourites:
        return None

    output = []
    for f in favourites:
        output.append({
            'file': url_for('static', filename=f['author'] + '/' + f['date_uploaded'] + '.png'),
            'username': f['username'],
            'title': database.get_picture(f['author'], f['date_uploaded'])['title'],
            'author': f['author'],
            'date_uploaded': f['date_uploaded'],
            'date_uploaded_formatted': get_formatted_time(get_epoch_time(f['date_uploaded'])),
            'date_added': f['date_added'],
            'date_added_formatted': get_formatted_time(get_epoch_time(f['date_added']))
        })

    return output


def get_comments(user, title):
    if not user or not title:
        return None

    comments = database.get_comments(user, title)

    if not comments:
        return None

    output = []
    for c in comments:
        output.append({
            'username': c['username'],
            'author': c['author'],
            'date_uploaded': c['date_uploaded'],
            'date_uploaded_formatted': get_formatted_time(get_epoch_time(c['date_uploaded'])),
            'date_added': c['date_added'],
            'date_added_formatted': get_formatted_time(get_epoch_time(c['date_added'])),
            'message': c['message']
        })

    return output


def get_friends(user=None):
    if not user and logged_in():
        user = session['username']

    return database.get_friends(user)


# App routing
@app.route('/')
def home():
    return render_template('home.html', pagetitle=app_name, user=get_user())


@app.route('/browse/')
def browse():
    return render_template('gallery.html', pagetitle=app_name, user=get_user(), pictures=get_pictures())


@app.route('/search/', methods=['POST'])
def search():
    query = request.form['search']
    user = get_user()
    if user:
        app.logger.info(user['username'] + ' searched for ' + query)
    return redirect(url_for('searchterm', urlquery=query))


@app.route('/search/<urlquery>')
def searchterm(urlquery=None):
    if urlquery == None:
        return redirect(url_for('.home'))
    else:
        return render_template('search.html', pagetitle=urlquery, user=get_user(), pictures=database.search_pictures(urlquery))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if logged_in():
        return redirect(url_for('home'))

    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        if not user:
            error = 'User does not exist.'
        elif not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            app.logger.info(username + ' used invalid password at login')
            error = 'Invalid password.'
        else:
            session['username'] = username
            app.logger.info(username + ' logged in')
            return redirect(url_for('home'))
    return render_template('login.html', pagetitle='Log in', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if logged_in():
        return redirect(url_for('home'))

    error = None
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password1 = request.form['password1']
        password2 = request.form['password2']

        if database.get_user(username):
            error = 'Username already taken.'
        elif password1 != password2:
            error = 'Passwords do not match.'
        else:
            database.add_user(email, username, bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt()), get_time(time.time()))
            if not os.path.isdir(app.config['upload_folder'] + username + '/'):
                os.mkdir(app.config['upload_folder'] + username + '/')
            session['username'] = username
            app.logger.info(username + ' account created')
            return redirect(url_for('home'))
    return render_template('register.html', pagetitle='Register', error=error)


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if logged_in():
        return redirect(url_for('home'))

    message = None
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password1 = request.form['password1']
        password2 = request.form['password2']

        user = database.get_user(username)
        if not user:
            message = 'User does not exist.'
        elif password1 != password2:
            message = 'Passwords do not match'
        elif not user['email'] != email:
            app.logger.info(username + ' used invalid email at reset')
            message = 'Incorrect email'
        else:
            database.update_user(username, bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt()), email, user['description'])
            session['username'] = username
            app.logger.info(username + ' password reset successful')
            return redirect(url_for('home'))

    return render_template('reset.html', pagetitle='Reset', message=message)


@app.route('/logout')
def logout():
    if logged_in():
        app.logger.info(session['username'] + ' logged out')
        session.pop('username', None)

    return redirect(url_for('home'))


@app.route('/user/<urluser>')
def user(urluser=None):
    page_user = get_user(urluser)

    if not page_user:
        return redirect(url_for('home'))

    friends = None
    if logged_in():
        friends = database.get_friends(get_user()['username'])

    return render_template('user.html', pagetitle=urluser, user=get_user(), page_user=page_user, pictures=get_pictures(urluser), friends=friends)


@app.route('/user/<urluser>/gallery/')
def gallery(urluser=None):
    if not get_user(urluser):
        return redirect(url_for('home'))

    return render_template('gallery.html', pagetitle=urluser, user=get_user(), pictures=get_pictures(urluser))


@app.route('/user/<urluser>/favourites/')
def favourites(urluser=None):
    if not get_user(urluser):
        return redirect(url_for('home'))

    return render_template('gallery.html', pagetitle=urluser, user=get_user(), pictures=get_favourites(urluser))


@app.route('/user/<urluser>/friends')
def friends(urluser=None):
    if not get_user(urluser):
        return redirect(url_for('home'))

    user = get_user()
    if not logged_in() or user['username'] != urluser:
        return redirect(url_for('user', urluser=urluser))

    pictures = get_friends_pictures(user['username'])

    return render_template('gallery.html', pagetitle='Friends', user=user, pictures=pictures)


@app.route('/user/<urluser>/<urltitle>', methods=['GET', 'POST'])
def picture(urluser=None, urltitle=None):
    picture = get_picture(urluser, urltitle)

    if not picture:
        return redirect(url_for('user', urluser=urluser))

    if request.method == 'POST':
        if not logged_in():
            return redirect(url_for('login'))
        username = get_user()['username']
        author = urluser
        date_uploaded = urltitle
        date_added = get_time(time.time())
        message = request.form['message']
        database.add_comment(username, author, date_uploaded, date_added, message)
        app.logger.info(username + ' posted a comment on /' + urluser + '/' + urltitle)
        return redirect(url_for('picture', urluser=urluser, urltitle=urltitle))

    comments = get_comments(urluser, urltitle)
    favourites = []
    if logged_in():
        fav = get_favourites(get_user()['username'])
        if fav:
            for f in fav:
                favourites.append(f['author'] + f['date_uploaded'])

    return render_template('picture.html', pagetitle=urltitle, user=get_user(), picture=picture, comments=comments, favourites=favourites)


@app.route('/user/<urluser>/<urltitle>/edit', methods=['GET', 'POST'])
def edit(urluser=None, urltitle=None):
    user = get_user()

    if not user or user['username'] != urluser:
        return redirect(url_for('picture', urluser=urluser, urltitle=urltitle))

    picture = get_picture(urluser, urltitle)

    message = None
    if request.method == 'POST':
        if not bcrypt.checkpw(request.form['password'].encode('utf-8'), user['password'].encode('utf-8')):
            message = 'Incorrect password'
        else:
            database.edit_picture(picture['author'], picture['date_uploaded'], request.form['title'], request.form['description'])
            message = 'Changes saved successfully'
            picture = get_picture(urluser, urltitle)
            app.logger.info(urluser + ' edited picture ' + urltitle)
            return redirect(url_for('picture', urluser=urluser, urltitle=urltitle))

    request.form.title = picture['title']
    request.form.description = picture['description']

    return render_template('edit.html', pagetitle='Edit', user=user, picture=picture, message=message)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    user = get_user()
    if not user:
        return redirect(url_for('login'))

    username = user['username']
    message = None
    if request.method == 'POST':
        if not bcrypt.checkpw(request.form['password'].encode('utf-8'), user['password'].encode('utf-8')):
            message = 'Invalid password.'
        elif 'image' not in request.files:
            message = 'No file found.'
        else:
            file = request.files['image']
            if file.filename == '':
                message = 'File not valid.'
            else:
                extension = os.path.splitext(file.filename)[1]
                if extension not in ['.png', '.jpg', '.jpeg']:
                    message = 'File extension not supported.'
                else:
                    date = get_time(time.time())
                    database.add_picture(username, date, request.form['title'], request.form['description'])
                    file.save(app.config['upload_folder'] + username + '/' + date + '.png')
                    app.logger.info(username + ' uploaded image ' + date)
                    return redirect(url_for('picture', urluser=username, urltitle=date))

    return render_template('upload.html', pagetitle='Upload', user=user, message=message)


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if not logged_in():
        return redirect(url_for('login'))

    user = get_user()
    message = None
    if request.method == 'POST':
        username = user['username']
        if not bcrypt.checkpw(request.form['password'].encode('utf-8'), user['password'].encode('utf-8')):
            message = "Incorrect password."
        else:
            app.logger.info(username + ' changed their settings')
            database.update_user(username, user['password'], request.form['email'], request.form['description'])
            message = "Changes saved successfully."
            if 'image' not in request.files:
                message = 'File not found.'
            else:
                file = request.files['image']
                if file.filename == '':
                    message = 'Invalid file name.'
                else:
                    extension = os.path.splitext(file.filename)[1]
                    if extension not in ['.png', '.jpg', '.jpeg']:
                        message = 'Invalid file type.'
                    else:
                        file.save(app.config['upload_folder'] + username + '/' + username + '.png')
                        user = get_user()
    else:
        request.form.email = user['email']
        request.form.description = user['description']

    return render_template('settings.html', pagetitle='Settings', user=user, message=message)


@app.route('/addfriend/<urluser>')
def add_friend(urluser=None):
    if not logged_in():
        return redirect(url_for('login'))

    user = get_user()
    friend = get_user(urluser)
    if user and friend and user['username'] != friend['username']:
        friends = database.get_friends(user['username'])
        if not friends or friend['username'] not in friends:
            app.logger.info(user['username'] + ' added ' + friend['username'] + ' as a friend')
            database.add_friend(user['username'], friend['username'], get_time(time.time()))

    return redirect(url_for('user', urluser=urluser))


@app.route('/removefriend/<urluser>')
def remove_friend(urluser=None):
    if not logged_in():
        return redirect(url_for('login'))

    user = get_user()
    friends = database.get_friends(user['username'])
    if urluser and user and friends and get_user(urluser) and urluser in friends:
        app.logger.info(user['username'] + ' removed ' + friend['username'] + ' as a friend')
        database.remove_friend(user['username'], urluser)

    return redirect(url_for('user', urluser=urluser))


@app.route('/favourite/<urluser>/<urltitle>')
def add_favourite(urluser=None, urltitle=None):
    if not logged_in():
        return redirect(url_for('login'))

    user = get_user()
    favourites = get_favourites(user['username'])
    pictures = []
    if favourites:
        for f in favourites:
            pictures.append(f['authors'] + f['date_uploaded'])

    if urluser and urltitle and not pictures or pictures and not urluser + urltitle in pictures:
        app.logger.info(user['username'] + ' added ' + urluser + urltitle + ' to their favourites')
        database.add_favourite(user['username'], urluser, urltitle, get_time(time.time()))

    return redirect(url_for('picture', urluser=urluser, urltitle=urltitle))


@app.route('/unfavourite/<urluser>/<urltitle>')
def remove_favourite(urluser=None, urltitle=None):
    if not logged_in():
        return redirect(url_for('login'))

    user = get_user()
    favourites = get_favourites(user['username'])
    pictures = []
    for f in favourites:
        pictures.append(f['author'] + f['date_uploaded'])

    if urluser and urltitle and pictures and urluser + urltitle in pictures:
        app.logger.info(user['username'] + ' removed ' + urluser + urltitle + ' to their favourites')
        database.remove_favourite(user['username'], urluser, urltitle)

    return redirect(url_for('picture', urluser=urluser, urltitle=urltitle))


@app.route('/removecomment/<urluser>/<urltitle>/<urlcommenter>/<urldate>')
def remove_comment(urluser, urltitle, urlcommenter, urldate):
    if urluser and urltitle and urlcommenter and urldate:
        user = get_user()
        author = get_user(urluser)
        commenter = get_user(urlcommenter)
        if user and author and commenter:
            if user['username'] == author['username'] or user['username'] == commenter['username'] or user['rank'] > 0:
                app.logger.info(user['username'] + ' removed comment by ' + urlcommenter + ' from ' + urluser + urltitle)
                database.remove_comment(urlcommenter, urluser, urltitle, urldate)

    return redirect(url_for('picture', urluser=urluser, urltitle=urltitle))


@app.route('/remove/<urluser>/<urltitle>')
def remove_picture(urluser=None, urltitle=None):
    user = get_user()
    other = get_user(urluser)
    picture = get_picture(urluser, urltitle)

    if user and other and picture:
        if user['username'] == other['username'] or user['rank'] >= 1:
            app.logger.info(user['username'] + ' removed ' + urluser + urltitle)
            database.remove_picture(urluser, urltitle)
            os.remove(app.config['upload_folder'] + urluser + '/' + urltitle + '.png')

    return redirect(url_for('user', urluser=urluser))


@app.route('/remove/<urluser>')
def remove_user(urluser=None):
    user = get_user()
    other = get_user(urluser)

    if user and other:
        if user['username'] == other['username'] or user['rank'] == 2:
            app.logger.info(user['username'] + ' removed account ' + urluser)
            database.remove_user(urluser)
            shutil.rmtree(app.config['upload_folder'] + urluser + '/')

    return redirect(url_for('home'))


# Error handling
@app.route('/error/<int:status>')
def error(status=404):
    message = ''
    if status == 404:
        message = 'Sorry, the page you requested is not available.'
    if status == 405:
        message = 'Sorry, you cannot access this page this way.'
    if status == 418:
        message = 'Sorry, this page has not been added yet.'
    return render_template('error.html', pagetitle=status, message=message, user=get_user())


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
        app.config['upload_folder'] = config.get('config', 'upload_folder')

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
    database.create()
    app.run(
        host=app.config['ip_address'],
        port=int(app.config['port']),
        ssl_context=('cert.pem', 'key.pem')
    )
