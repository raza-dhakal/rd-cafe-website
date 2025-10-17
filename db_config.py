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
app.config.from_object('config.Config')
#यसले अब स्वतः PostgreSQL डेटाबेस प्रयोग गर्न सुरु गर्नेछ। के तपाईंलाई `app.py` मा यो कन्फिगरेसन लोड गर्ने कोड थप्न मद्दत चाहिएको छ?