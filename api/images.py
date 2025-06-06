from flask import Blueprint, current_app, request, jsonify
import json, base64

images_bp = Blueprint('images', __name__)

def load_db():
    with open(current_app.config['DATABASE_FILE']) as f:
        return json.load(f)

def save_db(data):
    with open(current_app.config['DATABASE_FILE'], 'w') as f:
        json.dump(data, f, indent=2)

@images_bp.route('/images', methods=["GET"])
def get_images():
    db = load_db()
    return jsonify(db["images"])

@images_bp.route('/images', methods=["POST"])
def upload_image():
    if request.is_json:
        data = request.get_json()
        filedata = data.get('filedata')
        filename = data.get('filename')
        user_id = data.get('user_id')
        if not all([filedata, filename, user_id]):
            return jsonify({"error": "Faltan datos"}), 400
        db = load_db()
        new_id = (max([img['id'] for img in db['images']] or [0]) + 1)
        new_image = {
            'id': new_id,
            'user_id': int(user_id),
            'filename': filename,
            'filedata': filedata,
            'comments': [],
            'likes': []
        }
        db['images'].append(new_image)
        save_db(db)
        return jsonify({'message': 'Imagen subida', 'id': new_id}), 201

    user_id = request.form.get('user_id')
    file = request.files.get('image')
    if file and user_id:
        file_data = file.read()
        encoded_data = base64.b64encode(file_data).decode('utf-8')
        db = load_db()
        new_id = (max([img['id'] for img in db['images']] or [0]) + 1)
        new_image = {
            'id': new_id,
            'user_id': int(user_id),
            'filename': file.filename,
            'filedata': encoded_data,
            'comments': [],
            'likes': []
        }
        db['images'].append(new_image)
        save_db(db)
        return jsonify({'message': 'Imagen subida', 'id': new_id}), 201

    return jsonify({'error': 'No se recibió la imagen'}), 400

@images_bp.route('/images/<int:image_id>/like', methods=['POST', 'OPTIONS'])
def like_image(image_id):
    if request.method == 'OPTIONS':
        response = jsonify({'ok': True})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        return response

    data = request.get_json()
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'error': 'Falta user_id'}), 400

    db = load_db()
    for image in db['images']:
        if image['id'] == image_id:
            if 'likes' not in image or not isinstance(image['likes'], list):
                image['likes'] = []
            if user_id in image['likes']:
                image['likes'].remove(user_id)
            else:
                image['likes'].append(user_id)
            save_db(db)
            response = jsonify({'likes': image['likes']})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response
    return jsonify({'error': 'Imagen no encontrada'}), 404