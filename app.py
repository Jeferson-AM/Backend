import os
from api import create_api
from config import Config
from utils.setup import init_database, init_directories
from db_sqlite import close_connection
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config.from_object(Config)
init_directories()
init_database()

create_api(app)

@app.teardown_appcontext
def teardown_db(exception):
    close_connection(exception)

@app.after_request
def csp_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline';"
    return response

@app.route('/')
def hello_world():
    return 'Hello World!'
# Agrega este fragmento en tu archivo principal de Flask (app.py o donde configuras Flask)
@app.after_request
def add_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    return response

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)