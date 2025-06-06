from .auth import auth_bp
from .images import images_bp
from .comments import comments_bp
from .likes import likes_bp
from .users import users_bp 

def create_api(app):
    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(images_bp, url_prefix='/api')
    app.register_blueprint(comments_bp, url_prefix='/api')
    app.register_blueprint(likes_bp, url_prefix='/api')
    app.register_blueprint(users_bp, url_prefix='/api')  