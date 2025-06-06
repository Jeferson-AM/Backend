import os
from config import Config
import json

def init_directories():
    os.makedirs(Config.DATA_FOLDER, exist_ok=True)

def init_database():
    if not os.path.exists(Config.DATABASE_FILE):
        with open(Config.DATABASE_FILE, 'w') as f:
            # Cambiar json.dumps por json.dump
            json.dump({"images": []}, f, indent=2)  # Contenido de la base de datos JSON al inicio