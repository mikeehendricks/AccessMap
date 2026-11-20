"""HTTP route blueprints: auth, admin, public API and ingest."""

from accessmap.routes import admin_routes, api_routes, auth_routes, ingest_routes

__all__ = ["auth_routes", "admin_routes", "api_routes", "ingest_routes"]
