from flask import Flask
from flask_login import LoginManager
import os
import json

login_manager = LoginManager()


def create_app():
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("FIREWALL_SECRET_KEY", "change-this-secret-key-in-production"),
        DEBUG=os.environ.get("FIREWALL_DEBUG", "False").lower() == "true",
    )

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."

    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.domains import domains_bp
    from app.routes.ips import ips_bp
    from app.routes.whitelist import whitelist_bp
    from app.routes.users import users_bp
    from app.routes.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(domains_bp)
    app.register_blueprint(ips_bp)
    app.register_blueprint(whitelist_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(api_bp)

    return app
