"""AccessMap application factory and entry point.

Run locally:      ``python app.py``            (http://127.0.0.1:5000)
Run in production: ``gunicorn 'app:create_app()'`` behind nginx
                   (see install.sh — it sets this up for you).

The threat map lives at ``/``; the admin panel at ``/admin/``.
First run: open ``/register`` once to create the first admin.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from flask import Flask, render_template, request

from accessmap import auth, db
from accessmap.config import Config
from accessmap.routes import admin_routes, api_routes, auth_routes, ingest_routes


def create_app(config: type[Config] | None = None) -> Flask:
    """Build and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder="accessmap/templates",
        static_folder="accessmap/static",
    )
    app.config.from_object(config or Config)
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
        seconds=app.config["PERMANENT_SESSION_LIFETIME"]
    )

    with app.app_context():
        db.init_db()

    app.register_blueprint(auth_routes.bp)
    app.register_blueprint(admin_routes.bp)
    app.register_blueprint(api_routes.bp)
    app.register_blueprint(ingest_routes.bp)
    app.teardown_appcontext(db.close_db)

    @app.context_processor
    def inject_globals() -> dict:
        """Expose CSRF token + current admin to every template."""
        return {"csrf_token": auth.csrf_token, "current_admin": auth.current_admin}

    @app.after_request
    def add_security_headers(response):
        """Baseline security headers (see docs/TESTING.md)."""
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        if not app.config.get("ALLOW_FRAME_EMBED", False):
            response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault(
            "Content-Security-Policy",
            # Leaflet + world GeoJSON are self-hosted; optional raster tiles
            # may load from OpenStreetMap or CARTO when online.
            "default-src 'self'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https://*.tile.openstreetmap.org https://*.basemaps.cartocdn.com; "
            "connect-src 'self'; font-src 'self' data:",
        )
        # strict-origin-when-cross-origin preserves origin Referer required by
        # OpenStreetMap's Tile Usage Policy without leaking paths or query params.
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response

    @app.route("/", methods=["GET"])
    def index():
        """Public threat-map page (FortiGuard-style live view)."""
        return render_template("index.html")

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(_error):
        return render_template("errors/500.html"), 500

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(
        host=application.config["HOST"],
        port=application.config["PORT"],
        debug=application.config["DEBUG"],
    )
