import os
from api import create_api
from config import Config
from utils.setup import init_database, init_directories
from db_sqlite import close_connection
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Configuración de archivo de Base de Datos JSON
app.config.from_object(Config)
init_directories()
init_database()
# -----------------------------------------------

create_api(app)

@app.teardown_appcontext
def teardown_db(exception):
    close_connection(exception)

# ---- AGREGADO: POLÍTICA DE SEGURIDAD CSP ----
@app.after_request
def csp_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline';"
    return response
# ---------------------------------------------

# Ruta de prueba
@app.route('/')
def hello_world():
    return 'Hello World!'

if __name__ == '__main__':
    # app.run(debug=True)

    # Modo Producción
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)