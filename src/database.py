# Create
# Add user
# Get user
# Update user
# Remove user
# Add friend
# Get friends
# Remove friend
# Add picture
# Get picture
# Edit picture
# Remove picture
# Add favourite
# Get favourites
# Remove favourite
# Add comment
# Get comments
# Update comment
# Remove comment
# Match password

import bcrypt
import sqlite3

from datetime import datetime
from time import time


db_file = 'var/data.db'


def create():
    create_users_table = '''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            date_joined TEXT NOT NULL,
            rank INTEGER DEFAULT 0,
            description TEXT,
            PRIMARY KEY (username)
        );
    '''
    create_friends_table = '''
        CREATE TABLE IF NOT EXISTS friends (
            username TEXT NOT NULL,
            friend TEXT NOT NULL,
            date_added TEXT NOT NULL,
            PRIMARY KEY (username, friend),
            FOREIGN KEY (username) REFERENCES users (username),
            FOREIGN KEY (friend) REFERENCES users (username)
        );
    '''
    create_gallery_table = '''
        CREATE TABLE IF NOT EXISTS gallery (
            username TEXT NOT NULL,
            date_uploaded TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            PRIMARY KEY (username, date_uploaded),
            FOREIGN KEY (username) REFERENCES users (username)
        );
    '''
    create_favourites_table = '''
        CREATE TABLE IF NOT EXISTS favourites (
            username TEXT NOT NULL,
            author TEXT NOT NULL,
            date_uploaded TEXT NOT NULL,
            date_added TEXT NOT NULL,
            PRIMARY KEY (username, author, date_uploaded),
            FOREIGN KEY (username) REFERENCES users (username),
            FOREIGN KEY (author) REFERENCES users (username),
            FOREIGN KEY (author, date_uploaded) REFERENCES gallery (username, date_uploaded)
        );
    '''
    create_comments_table = '''
        CREATE TABLE IF NOT EXISTS comments (
            username TEXT NOT NULL,
            author TEXT NOT NULL,
            date_uploaded TEXT NOT NULL,
            date_added TEXT NOT NULL,
            message TEXT NOT NULL,
            PRIMARY KEY (username, author, date_uploaded, date_added),
            FOREIGN KEY (username) REFERENCES users (username),
            FOREIGN KEY (author) REFERENCES users (username),
            FOREIGN KEY (author, date_uploaded) REFERENCES gallery (username, date_uploaded)
        );
    '''

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()

    cur.execute(create_users_table)
    cur.execute(create_friends_table)
    cur.execute(create_gallery_table)
    cur.execute(create_favourites_table)
    cur.execute(create_comments_table)

    conn.commit()
    cur.close()
    conn.close()


def add_user(email, username, password, date_joined):
    table_add_user = '''
        INSERT INTO users (
            username,
            password,
            email,
            date_joined
        ) VALUES (
            ?,
            ?,
            ?,
            ?
        );
    '''

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_add_user, [username, password, email, date_joined])

    cur.close()
    conn.commit()
    conn.close()


def get_user(username):
    table_get_user = 'SELECT username, password, email, date_joined, rank, description FROM users WHERE username = ?;'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_get_user, [username])

    u = cur.fetchone()

    cur.close()
    conn.commit()
    conn.close()

    if not u:
        return None

    return {
        'username': u[0],
        'password': u[1],
        'email': u[2],
        'date_joined': u[3],
        'rank': u[4],
        'description': u[5]
    }


def update_user(username, password, email, description):
    table_update_user = 'UPDATE users SET password = ?, email = ?, description = ? WHERE username = ?;'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()

    cur.execute(table_update_user, [password, email, description, username])

    cur.close()
    conn.commit()
    conn.close()


def remove_user(username):
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()

    cur.execute('DELETE FROM users WHERE username = ?;', [username])
    cur.execute('DELETE FROM friends WHERE username = ?;', [username])
    cur.execute('DELETE FROM friends WHERE friend = ?;', [username])
    cur.execute('DELETE FROM gallery WHERE username = ?;', [username])
    cur.execute('DELETE FROM favourites WHERE username = ?;', [username])
    cur.execute('DELETE FROM favourites WHERE author = ?;', [username])
    cur.execute('DELETE FROM comments WHERE username = ?;', [username])
    cur.execute('DELETE FROM comments WHERE author = ?;', [username])

    cur.close()
    conn.commit()
    conn.close()


def add_friend(username, friend, date_added):
    table_add_friend = 'INSERT INTO friends (username, friend, date_added) VALUES (?, ?, ?);'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_add_friend, [username, friend, date_added])

    cur.close()
    conn.commit()
    conn.close()


def get_friends(username):
    table_get_friends = 'SELECT friend FROM friends WHERE username = ? ORDER BY date_added;'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_get_friends, [username])

    friends = cur.fetchall()

    cur.close()
    conn.commit()
    conn.close()

    if not friends:
        return None

    output = []
    for f in friends:
        output.append(f[0])

    return output


def remove_friend(username, friend):
    table_remove_friend = 'DELETE FROM friends WHERE username = ? AND friend = ?;'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_remove_friend, [username, friend])

    cur.close()
    conn.commit()
    conn.close()


def add_picture(username, date_uploaded, title, description):
    if not description:
        description = ''

    table_upload_file = '''
        INSERT INTO gallery (
            username,
            date_uploaded,
            title,
            description
        ) VALUES (
            ?,
            ?,
            ?,
            ?
        );
    '''

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_upload_file, [username, date_uploaded, title, description])

    cur.close()
    conn.commit()
    conn.close()


def get_picture(username, date):
    table_get_picture = 'SELECT username, date_uploaded, title, description FROM gallery WHERE username = ? AND date_uploaded = ?;'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_get_picture, [username, date])

    p = cur.fetchone()

    cur.close()
    conn.commit()
    conn.close()

    if not p:
        return None

    return {
        'username': p[0],
        'date_uploaded': p[1],
        'title': p[2],
        'description': p[3]
    }


def get_pictures(username=None):
    table_get_pictures = 'SELECT username, date_uploaded, title, description FROM gallery '
    if username:
        table_get_pictures += 'WHERE username = ? '
    table_get_pictures += 'ORDER BY date_uploaded LIMIT 50;'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    if username:
        cur.execute(table_get_pictures, [username])
    else:
        cur.execute(table_get_pictures)

    pictures = cur.fetchall()

    cur.close()
    conn.commit()
    conn.close()

    if not pictures:
        return None

    output = []
    for p in pictures:
        output.append({
            'author': p[0],
            'date_uploaded': p[1],
            'title': p[2],
            'description': p[3]
        })

    return output


def search_pictures(text):
    table_search_pictures = 'SELECT username, date_uploaded, title, description FROM gallery WHERE username LIKE "%?%" OR date_uploaded LIKE "%?%" OR title LIKE "%?%" OR description LIKE "%?%" ORDER BY date_uploaded;'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_search_pictures)

    pictures = cur.fetchall()

    cur.close()
    conn.commit()
    conn.close()

    if not pictures:
        return None

    output = []
    for p in pictures:
        output.append({
            'author': p[0],
            'date_uploaded': p[1],
            'title': p[2],
            'description': p[3]
        })

    return output


def edit_picture(username, date, title, description):
    table_update_gallery = 'UPDATE gallery SET title = ?, description = ? WHERE username = ? AND date_uploaded = ?;'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()

    cur.execute(table_update_gallery, [title, description, username, date])

    cur.close()
    conn.commit()
    conn.close()


def remove_picture(username, date):
    table_remove_picture = 'DELETE FROM gallery WHERE username = ? AND date = ?;'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_remove_picture, [username, date])

    cur.close()
    conn.commit()
    conn.close()


def add_favourite(username, author, date_uploaded, date_added):
    table_add_favourites = '''
        INSERT INTO favourites (
            username,
            author,
            date_uploaded,
            date_added
        ) VALUES (
            ?,
            ?,
            ?,
            ?
        );
    '''

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_add_favourites, [username, author, date_uploaded, date_added])

    cur.close()
    conn.commit()
    conn.close()


def get_favourites(username):
    table_get_favourites = 'SELECT username, author, date_uploaded, date_added FROM favourites WHERE username = ? ORDER BY date_added;'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_get_favourites, [username])

    favourites = cur.fetchall()

    cur.close()
    conn.commit()
    conn.close()

    if not favourites:
        return None

    output = []
    for f in favourites:
        output.append({
            'username': f[0],
            'author': f[1],
            'date_uploaded': f[2],
            'date_added': f[3]
        })
    return output


def remove_favourite(username, author, date_uploaded):
    table_remove_favourite = 'DELETE FROM favourites WHERE username = ? AND author = ? AND date = ?;'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_remove_favourite, [username, author, date_uploaded])

    cur.close()
    conn.commit()
    conn.close()


def add_comment(username, author, date_uploaded, date_added, message):
    table_add_comment = '''
        INSERT INTO comments (
            username,
            author,
            date_uploaded,
            date_added,
            message
        ) VALUES (
            ?,
            ?,
            ?,
            ?,
            ?
        );
    '''

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_add_comment, [username, author, date_uploaded, date_added, message])

    cur.close()
    conn.commit()
    conn.close()


def get_comments(author, date_uploaded):
    table_get_comments = 'SELECT username, author, date_uploaded, date_added, message FROM comments WHERE author = ? AND date_uploaded = ? ORDER BY date_added;'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_get_comments, [author, date_uploaded])

    comments = cur.fetchall()

    cur.close()
    conn.commit()
    conn.close()

    if not comments:
        return None

    output = []
    for c in comments:
        output.append({
            'username': c[0],
            'author': c[1],
            'date_uploaded': c[2],
            'date_added': c[3],
            'message': c[4]
        })
    return output


def edit_comment(username, author, date_uploaded, date_added, message):
    table_edit_comment = 'UPDATE comments SET message = ? WHERE username = ? AND author = ? AND date_uploaded = ? AND date_added = ?;'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()

    cur.execute(table_edit_comment, [message, username, author, date_uploaded, date_added])

    cur.close()
    conn.commit()
    conn.close()


def delete_comment(username, author, date_uploaded, date_added):
    table_remove_comment = 'DELETE FROM comments WHERE username = ? AND author = ? AND date_uploaded = ? AND date_added = ?;'

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute(table_remove_comment, [username, author, date_uploaded, date_added])

    cur.close()
    conn.commit()
    conn.close()
