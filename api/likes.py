from flask import Blueprint, jsonify, request, g
import sqlite3
import os

likes_bp = Blueprint('likes', __name__)

def get_db():
    db_path = os.path.join(os.path.dirname(__file__), "../data/database.db")
    db_path = os.path.abspath(db_path)
    if 'db' not in g:
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
    return g.db

@likes_bp.route('/images/<int:image_id>/likes', methods=['GET'])
def get_likes(image_id):
    db = get_db()
    cur = db.execute('SELECT COUNT(*) as count FROM likes WHERE image_id = ?', (image_id,))
    count = cur.fetchone()['count']
    return jsonify({"count": count})

@likes_bp.route('/images/<int:image_id>/likes', methods=['POST'])
def add_like(image_id):
    db = get_db()
    data = request.get_json() or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id requerido"}), 400

    try:
        db.execute('INSERT INTO likes (image_id, user_id) VALUES (?, ?)', (image_id, user_id))
        db.commit()
    except sqlite3.IntegrityError:
        pass  # Ya existe

    cur = db.execute('SELECT COUNT(*) as count FROM likes WHERE image_id = ?', (image_id,))
    count = cur.fetchone()['count']
    return jsonify({"count": count})