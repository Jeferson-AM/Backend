from .auth import auth_bp
from .images import images_bp
from .comments import comments_bp

def create_api(app):
    # /api/login
    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(images_bp, url_prefix='/api')
    app.register_blueprint(comments_bp, url_prefix='/api')