import sqlite3
from time import time


db_file = 'data/data.db'


def db_create():
    create_users_table = '''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            date_joined REAL NOT NULL,
            description TEXT,
            PRIMARY KEY (username)
        );
    '''
    create_friends_table = '''
        CREATE TABLE IF NOT EXISTS friends (
            username TEXT NOT NULL,
            friend TEXT NOT NULL,
            date_added REAL NOT NULL,
            PRIMARY KEY (username, friend),
            FOREIGN KEY (username) REFERENCES users (username),
            FOREIGN KEY (friend) REFERENCES users (username)
        );
    '''
    create_gallery_table = '''
        CREATE TABLE IF NOT EXISTS gallery (
            username TEXT NOT NULL,
            date_uploaded REAL NOT NULL,
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
            date_uploaded REAL NOT NULL,
            date_added REAL NOT NULL,
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
            date_uploaded REAL NOT NULL,
            date_added REAL NOT NULL,
            message TEXT NOT NULL,
            PRIMARY KEY (username, author, date_uploaded, date_added),
            FOREIGN KEY (username) REFERENCES users (username),
            FOREIGN KEY (author) REFERENCES users (username),
            FOREIGN KEY (author, date_uploaded) REFERENCES gallery (username, date_uploaded)
        );
    '''

    db_connection = sqlite3.connect(db_file)
    db_cursor = db_connection.cursor()

    db_cursor.execute(create_users_table)
    db_cursor.execute(create_friends_table)
    db_cursor.execute(create_gallery_table)
    db_cursor.execute(create_favourites_table)
    db_cursor.execute(create_comments_table)

    db_connection.commit()
    db_cursor.close()
    db_connection.close()


def db_register(email, username, password):
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

    db_connection = sqlite3.connect(db_file)
    db_cursor = db_connection.cursor()
    db_cursor.execute(table_add_user, [username, password, email, time()])

    db_cursor.close()
    db_connection.commit()
    db_connection.close()


def db_user_exists(username):
    table_find_user = '''
        SELECT username
        FROM users
        WHERE username = ?;
    '''

    db_connection = sqlite3.connect(db_file)
    db_cursor = db_connection.cursor()
    db_cursor.execute(table_find_user, [username])
    response = db_cursor.fetchall()

    db_cursor.close()
    db_connection.commit()
    db_connection.close()

    return len(response) > 0


def db_match_password(username, password):
    table_find_user = '''
        SELECT password
        FROM users
        WHERE username = ?;
    '''

    db_connection = sqlite3.connect(db_file)
    db_cursor = db_connection.cursor()
    db_cursor.execute(table_find_user, [username])
    response = db_cursor.fetchone()[0]

    db_cursor.close()
    db_connection.commit()
    db_connection.close()

    return password == response
