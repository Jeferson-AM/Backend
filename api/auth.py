from flask import Blueprint, current_app, request, jsonify, make_response
import json
import hashlib
import uuid

auth_bp = Blueprint('auth', __name__)

def load_db():
    with open(current_app.config['DATABASE_FILE']) as f:
        return json.load(f)

def save_db(data):
    with open(current_app.config['DATABASE_FILE'], 'w') as f:
        json.dump(data, f, indent=2)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'POST,OPTIONS,GET'
    return response

@auth_bp.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        resp = make_response('')
        resp.status_code = 200
        return add_cors_headers(resp)
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    db = load_db()
    user = next((u for u in db['users'] if u['username'] == username), None)
    if user and user['password'] == hash_password(password):
        resp = jsonify({
            'id': user['id'],
            'username': user['username'],
            'profile_pic': user.get('profile_pic', ''),
            'bio': user.get('bio', ''),
        })
        return add_cors_headers(resp), 200
    return add_cors_headers(jsonify({'error': 'Credenciales inválidas'})), 401

@auth_bp.route('/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        resp = make_response('')
        resp.status_code = 200
        return add_cors_headers(resp)
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    profile_pic = data.get('profile_pic', '')
    bio = data.get('bio', '')
    db = load_db()
    if any(u['username'] == username for u in db['users']):
        return add_cors_headers(jsonify({'error': 'El usuario ya existe'})), 400
    user_id = max([u['id'] for u in db['users']] or [0]) + 1
    new_user = {
        'id': user_id,
        'username': username,
        'password': hash_password(password),
        'profile_pic': profile_pic,
        'bio': bio,
    }
    db['users'].append(new_user)
    save_db(db)
    resp = jsonify({'message': 'Usuario registrado', 'id': user_id})
    return add_cors_headers(resp), 201

@auth_bp.route('/users', methods=['GET'])
def get_all_users():
    db = load_db()
    users = [
        {
            'id': u['id'],
            'username': u['username'],
            'profile_pic': u.get('profile_pic', ''),
            'bio': u.get('bio', ''),
        }
        for u in db['users']
    ]
    return jsonify(users)

@auth_bp.route('/users/<int:user_id>', methods=['GET'])
def get_user_profile(user_id):
    db = load_db()
    user = next((u for u in db['users'] if int(u['id']) == int(user_id)), None)
    if user:
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'profile_pic': user.get('profile_pic', ''),
            'bio': user.get('bio', ''),
        })
    return jsonify({"error": "Usuario no encontrado"}), 404

@auth_bp.route('/users/<int:user_id>', methods=['PUT'])
def update_user_profile(user_id):
    data = request.get_json()
    db = load_db()
    user = next((u for u in db['users'] if int(u['id']) == int(user_id)), None)
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404
    if 'username' in data:
        user['username'] = data['username']
    if 'profile_pic' in data:
        user['profile_pic'] = data['profile_pic']
    if 'bio' in data:
        user['bio'] = data['bio']
    save_db(db)
    return jsonify({'message': 'Perfil actualizado'})

@auth_bp.route('/users/<int:user_id>/change_password', methods=['POST', 'OPTIONS'])
def change_password(user_id):
    if request.method == 'OPTIONS':
        resp = make_response('')
        resp.status_code = 200
        return add_cors_headers(resp)
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    db = load_db()
    user = next((u for u in db['users'] if int(u['id']) == int(user_id)), None)
    if not user or user['password'] != hash_password(old_password):
        return add_cors_headers(jsonify({"error": "Credenciales inválidas"})), 401
    user['password'] = hash_password(new_password)
    save_db(db)
    return add_cors_headers(jsonify({'message': 'Contraseña cambiada'})), 200

@auth_bp.route('/whoami', methods=['GET'])
def whoami():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '')
    db = load_db()
    user = next((u for u in db['users'] if u.get('token') == token), None)
    if user:
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'profile_pic': user.get('profile_pic', ''),
            'bio': user.get('bio', ''),
        })
    return jsonify({"error": "No autenticado"}), 401

@auth_bp.route('/logout', methods=['POST', 'OPTIONS'])
def logout():
    if request.method == 'OPTIONS':
        resp = make_response('')
        resp.status_code = 200
        return add_cors_headers(resp)
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '')
    db = load_db()
    user = next((u for u in db['users'] if u.get('token') == token), None)
    if user:
        user['token'] = None
        save_db(db)
    return add_cors_headers(jsonify({'message': 'Sesión cerrada'})), 200

@auth_bp.route('/users/<int:user_id>/profile_pic', methods=['POST'])
def upload_profile_pic(user_id):
    db = load_db()
    user = next((u for u in db['users'] if int(u['id']) == int(user_id)), None)
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404
    file = request.files.get('profile_pic')
    if not file:
        return jsonify({"error": "Archivo no recibido"}), 400
    import base64
    file_data = file.read()
    encoded_data = base64.b64encode(file_data).decode('utf-8')
    user['profile_pic'] = encoded_data
    save_db(db)
    return jsonify({'message': 'Foto de perfil actualizada'})