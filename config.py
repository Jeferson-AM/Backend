import os

class Config:
    DATA_FOLDER = './data'
    DATABASE_FILE = os.path.join(DATA_FOLDER, 'database.json') # ./data/database.json
    SQLITE_DB = os.path.join(DATA_FOLDER, 'users.db') # ./data/users_db