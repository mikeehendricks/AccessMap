"""AccessMap — firewall threat-map application package.

A FortiGuard-style live threat map: enrolled Fortinet FortiGate and
Palo Alto Networks PAN-OS firewalls stream web-visit events; the app
resolves source/destination IPs to real-world locations and draws
source -> destination arcs on a world map.

Modules
-------
config   : environment-driven configuration
db       : SQLite data-access layer (parameterized queries only)
auth     : password hashing, sessions, CSRF, access control
geo      : IP -> location resolution (online lookup + offline fallback)
ingest   : firewall log parsing (FortiGate / PAN-OS / JSON)
threat   : rule-based threat scoring
seed     : demo-data seeder
routes   : HTTP route blueprints (auth, admin, API, ingest)
"""

from accessmap.config import Config

__all__ = ["Config"]
__version__ = "1.0.0"
