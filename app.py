# app.py (Temporary Simple Version for Deployment Test)
from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return "<h1>RD Cafe is successfully deployed on Render!</h1><p>We will now reconnect the database.</p>"

# We have removed all other routes, models, and configurations for this test.