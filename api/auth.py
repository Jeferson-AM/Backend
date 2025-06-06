from flask import Blueprint, request, jsonify
import bcrypt
import base64
from db_sqlite import query_db, modify_db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=["POST"])
def login():
    data = request.json
    user = query_db('SELECT * FROM users WHERE username = ?', (data['username'],), one=True)
    if user:
        stored_hash = user['password']
        password = data['password']
        # Validar que el hash exista, sea string, y tenga formato bcrypt
        if isinstance(stored_hash, str) and stored_hash.startswith("$2b$"):
            try:
                password_bytes = password.encode('utf-8')
                stored_hash_bytes = stored_hash.encode('utf-8')
                if bcrypt.checkpw(password_bytes, stored_hash_bytes):
                    return jsonify({'mensaje': 'Login exitoso', 'user_id': user['id']}), 200
            except Exception as e:
                return jsonify({'error': 'Error al verificar la contraseña.'}), 401
        # Si el hash no es válido, no intentes login
        return jsonify({'error': 'Credenciales inválidas o usuario dañado. Contacta al administrador.'}), 401
    return jsonify({'error': 'Credenciales inválidas'}), 401

@auth_bp.route('/register', methods=["POST"])
def register():
    try:
        data = request.json
        
        # Validaciones básicas
        if not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username y password son requeridos'}), 400
            
        if len(data['username'].strip()) < 3:
            return jsonify({'error': 'El username debe tener al menos 3 caracteres'}), 400
            
        if len(data['password']) < 6:
            return jsonify({'error': 'La password debe tener al menos 6 caracteres'}), 400
        
        # Verifica si el usuario ya existe
        existing_user = query_db(
            'SELECT * FROM users WHERE username = ?',
            (data['username'].strip(),), one=True
        )

        if existing_user:
            return jsonify({'error': 'El usuario ya existe'}), 400
        
        # Hashear la contraseña antes de guardarla
        password_bytes = data['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

        # Procesar foto de perfil si se proporciona
        profile_photo_data = None
        if data.get('profile_photo'):
            try:
                # Validar que sea una imagen válida en base64
                profile_photo_data = data['profile_photo']
                # Intentar decodificar para validar
                base64.b64decode(profile_photo_data)
            except Exception:
                return jsonify({'error': 'Foto de perfil inválida'}), 400

        # Insertar nuevo usuario en la base de datos
        if profile_photo_data:
            modify_db(
                'INSERT INTO users (username, password, profile_photo) VALUES (?, ?, ?)',
                (data['username'].strip(), hashed_password.decode('utf-8'), profile_photo_data)
            )
        else:
            modify_db(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (data['username'].strip(), hashed_password.decode('utf-8'))
            )

        # Obtener el ID del nuevo usuario
        new_user = query_db(
            'SELECT id FROM users WHERE username = ?',
            (data['username'].strip(),), one=True
        )

        return jsonify({
            'success': True,
            'message': 'Usuario registrado exitosamente',
            'user_id': new_user['id']
        }), 201
        
    except Exception as e:
        print(f"Error en registro: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@auth_bp.route('/users', methods=["GET"])
def get_users():
    users = query_db('SELECT id, username FROM users')
    return jsonify([dict(user) for user in users]), 200

@auth_bp.route('/profile/<int:user_id>', methods=["GET"])
def get_profile(user_id):
    user = query_db(
        'SELECT username, profile_photo FROM users WHERE id = ?',
        (user_id,), one=True
    )
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    return jsonify({
        'username': user['username'],
        'photo': user['profile_photo']  # Esto es base64 o None
    }), 200

@auth_bp.route('/profile/<int:user_id>/photo', methods=['PUT'])
def update_profile_photo(user_id):
    data = request.json
    new_photo = data.get('profile_photo')
    if not new_photo:
        return jsonify({'error': 'Falta la imagen'}), 400
    try:
        base64.b64decode(new_photo)
    except Exception:
        return jsonify({'error': 'Imagen inválida'}), 400

    modify_db(
        'UPDATE users SET profile_photo = ? WHERE id = ?',
        (new_photo, user_id)
    )

    # Devuelve los datos actualizados del usuario
    user = query_db(
        'SELECT username, profile_photo FROM users WHERE id = ?',
        (user_id,), one=True
    )
    return jsonify({
        'success': True,
        'message': 'Foto de perfil actualizada',
        'username': user['username'],
        'photo': user['profile_photo']
    }), 200