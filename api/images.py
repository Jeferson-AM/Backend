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
            # Like/unlike
            if user_id in image['likes']:
                image['likes'].remove(user_id)
            else:
                image['likes'].append(user_id)
            save_db(db)
            response = jsonify({'likes': image['likes']})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response
    return jsonify({'error': 'Imagen no encontrada'}), 404

@images_bp.route('/upload', methods=["POST"])
def upload():
    user_id = request.form['user_id']
    file = request.files['image']
    if file:
        file_data = file.read() # Leyendo como binario
        encoded_data = base64.b64encode(file_data).decode('utf-8')

        db = load_db()
        new_image = {
            'id': len(db['images']) + 1,
            'user_id': int(user_id),
            'filename': file.filename,
            'filedata': encoded_data,
            'comments': [],
            'likes': []  # Inicializa likes vacío
        }
        db['images'].append(new_image)
        save_db(db)
        return jsonify({ 'message': 'Imagen subida' }), 201
    
    return jsonify({ 'error': 'No se recibió la imagen' }), 400