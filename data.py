import sqlite3
from contextlib import closing

connection = None

def connect_database():
    global connection

    if not connection:
        connection = sqlite3.connect("./data.sqlite", check_same_thread=False)
        connection.row_factory = sqlite3.Row

def register_user(name, username, email, password):
    query = "INSERT INTO users (name, username, email, password) VALUES (?, ?, ?, ?)"

    with closing(connection.cursor()) as cursor:
        cursor.execute(query, (name, username, email, password))

def fetch_data(username):
    
    with closing(connection.cursor()) as cursor:
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?;", (username, ))
        result = cursor.fetchone()
        
        if result['COUNT(*)'] > 0:
            cursor.execute("SELECT * FROM users WHERE username = ?;", (username, ))
            user_data = cursor.fetchone()
            return user_data
        else:
            return None

def create_article(title, body, author):
    query = "INSERT INTO articles (title, body, author, date_of_creation) VALUES (?, ?, ?, datetime('now'))"

    with closing(connection.cursor()) as cursor:
        cursor.execute(query, (title, body, author))
       
def get_articles(author):
    connect_database()
    query = "SELECT * FROM articles WHERE author = ?;"

    with closing(connection.cursor()) as cursor:
        cursor.execute(query, (author,))
        result = cursor.fetchall()
        
        if len(result) > 0:
            articles = [dict(x) for x in result]
            return articles
        else:
            return None

def get_article(id):
    connect_database()
    query = "SELECT * FROM articles WHERE id = ?;"

    with closing(connection.cursor()) as cursor:
        cursor.execute(query, (id,))
        article = cursor.fetchone()
        
        return dict(article)
        

def update_article(id, title, body):
    query = "UPDATE articles SET title = ?, body = ? WHERE id = ?"

    with closing(connection.cursor()) as cursor:
        cursor.execute(query, (title, body, id))
        

def delete_article(article_id):
    query = "DELETE FROM articles WHERE id = ?"

    with closing(connection.cursor()) as cursor:
        cursor.execute(query, (article_id,))



def close_connection():
    if connection:
        connection.close()

