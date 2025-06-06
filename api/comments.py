from flask import Blueprint, current_app, request, jsonify, make_response
import json

comments_bp = Blueprint('comments', __name__)

def load_db():
    with open(current_app.config['DATABASE_FILE']) as f:
        return json.load(f)

def save_db(data):
    with open(current_app.config['DATABASE_FILE'], 'w') as f:
        json.dump(data, f, indent=2)

def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'POST,OPTIONS,GET'
    return response

@comments_bp.route('/images/<int:image_id>/comments', methods=['POST', 'OPTIONS'])
def add_comment_compatible(image_id):
    if request.method == 'OPTIONS':
        resp = make_response('')
        resp.status_code = 200
        return add_cors_headers(resp)
    data = request.json
    db = load_db()
    for image in db['images']:
        if image['id'] == image_id:
            newComment = {
                "user_id": data.get("user_id"),
                "text": data.get("text") or data.get("comment")
            }
            image['comments'].append(newComment)
            save_db(db)
            resp = jsonify({'message': 'Comentario agregado'})
            return add_cors_headers(resp), 201
    resp = jsonify({'error': 'Imagen no encontrada'})
    return add_cors_headers(resp), 404

@comments_bp.route('/comments', methods=['GET', 'OPTIONS'])
def get_all_comments():
    if request.method == 'OPTIONS':
        resp = make_response('')
        resp.status_code = 200
        return add_cors_headers(resp)
    db = load_db()
    comments = []
    for img in db['images']:
        for c in img.get('comments', []):
            comments.append({
                'image_id': img['id'],
                'user_id': c['user_id'],
                'text': c['text']
            })
    resp = jsonify(comments)
    return add_cors_headers(resp)