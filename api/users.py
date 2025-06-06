from flask import Blueprint, jsonify, abort
from db_sqlite import get_db

users_bp = Blueprint('users', __name__)

@users_bp.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    db = get_db()
    user = db.execute('SELECT id, username, email, nombre, foto FROM users WHERE id = ?', (user_id,)).fetchone()
    if user is None:
        abort(404, description="Usuario no encontrado")
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'nombre': user['nombre'],
        'foto': user['foto']
    })