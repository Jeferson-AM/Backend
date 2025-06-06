from flask import Blueprint, request, jsonify
import bcrypt
import base64
from db_sqlite import query_db, modify_db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Falta usuario o contraseña'}), 400

    user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'error': 'Contraseña incorrecta'}), 401

    return jsonify({'success': True, 'user_id': user['id']}), 200

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Falta usuario o contraseña'}), 400

        existing_user = query_db(
            'SELECT * FROM users WHERE username = ?',
            (data['username'].strip(),), one=True
        )
        if existing_user:
            return jsonify({'error': 'El usuario ya existe'}), 400

        password_bytes = data['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

        profile_photo_data = None
        if data.get('profile_photo'):
            try:
                # Validar que sea una imagen válida en base64
                profile_photo_data = data['profile_photo']
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
        'SELECT id, username, profile_photo FROM users WHERE id = ?',
        (user_id,), one=True
    )
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    return jsonify({
        'id': user['id'],
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
        'SELECT id, username, profile_photo FROM users WHERE id = ?',
        (user_id,), one=True
    )
    return jsonify({
        'success': True,
        'message': 'Foto de perfil actualizada',
        'id': user['id'],
        'username': user['username'],
        'photo': user['profile_photo']
    }), 200