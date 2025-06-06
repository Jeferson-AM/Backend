import sqlite3
import os
import bcrypt
import datetime

# Ruta donde se guardará la base de datos
db_path = './data/users.db'

# Crear la carpeta si no existe
os.makedirs('./data', exist_ok=True)

# Conexión a SQLite
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Crear tabla 'users' si no existe
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        profile_photo TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

# Verificar columnas existentes
cursor.execute("PRAGMA table_info(users)")
columns = [column[1] for column in cursor.fetchall()]

# Agregar columnas si no existen (sin DEFAULT para evitar errores)
if 'profile_photo' not in columns:
    cursor.execute('ALTER TABLE users ADD COLUMN profile_photo TEXT')

if 'created_at' not in columns:
    cursor.execute('ALTER TABLE users ADD COLUMN created_at TIMESTAMP')

# Usuarios iniciales (LOS DE A1)
init_users = [
    ('Jeferson', '1234'),    # id: 1
    ('Alexander', '123'),    # id: 2
    ('Oscar', '789'),        # id: 3
    ('Graciela', '123456'),  # id: 4 
]

# Verificar si ya existen usuarios
cursor.execute('SELECT COUNT(*) FROM users')
user_count = cursor.fetchone()[0]

# Solo insertar usuarios iniciales si la tabla está vacía
if user_count == 0:
    print("Insertando usuarios iniciales...")
    for username, password in init_users:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        created_at = datetime.datetime.now()
        cursor.execute('''
            INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)
        ''', (username, hashed_password.decode('utf-8'), created_at))
    print("Usuarios iniciales insertados correctamente")
else:
    print(f"Ya existen {user_count} usuarios en la base de datos")

# Guardar y cerrar conexión
conn.commit()
conn.close()

print("Base de datos y tabla 'users' creadas/actualizadas correctamente")
