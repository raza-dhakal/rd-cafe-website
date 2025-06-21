import os
from dotenv import load_dotenv

load_dotenv() # .env file bata environment variables load garcha

DB_CONFIG = {
    'host': os.getenv('MYSQL_HOST'),
    'user': os.getenv('MYSQL_USER'),
    'password': os.getenv('MYSQL_PASSWORD'),
    'database': os.getenv('MYSQL_DB'),
    'cursorclass': 'DictCursor' # Result lai dictionary format ma dina
}