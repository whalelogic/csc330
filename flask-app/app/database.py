import sqlite3
from flask import g
import os

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'population.db')

def get_db():
    """Get database connection"""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def close_connection(exception):
    """Close database connection"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize the database"""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                city TEXT NOT NULL UNIQUE,
                population INTEGER NOT NULL,
                country TEXT NOT NULL UNIQUE
            )
        ''')
        conn.commit()

def query_db(query, args=(), one=False):
    """Query the database"""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def insert_city(city, population, country):
    """Insert or update a city, population, and country"""
    db = get_db()
    try:
        db.execute('INSERT INTO cities (city, country, population) VALUES (?, ?, ?)', (city, country, population))
        db.commit()
        return True
    except sqlite3.IntegrityError:
        # City already exists, update it
        db.execute('UPDATE cities SET population = ?, country = ? WHERE city = ?', (population, country, city))
        db.commit()
        return True
    except Exception as e:
        print(f"Error inserting city: {e}")
        return False

def delete_city(city_id):
    """Delete a city by id"""
    db = get_db()
    try:
        db.execute('DELETE FROM cities WHERE id = ?', (city_id,))
        db.commit()
        return True
    except Exception as e:
        print(f"Error deleting city: {e}")
        return False


def insert_country(country):
    """Insert a country"""
    db = get_db()
    try:
        db.execute('INSERT INTO countries (country) VALUES (?)', (country,))
        db.commit()
        return True
    except sqlite3.IntegrityError:
        # Country already exists, ignore
        return True
    except Exception as e:
        print(f"Error inserting country: {e}")
        return False

def get_all_cities():
    """Get all cities"""
    return query_db('SELECT id, city, country, population FROM cities ORDER BY city')
