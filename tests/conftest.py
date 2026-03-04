"""
conftest.py — Configuración automática de pytest.
Añade backend/ y frontend/ al sys.path para que los tests
puedan importar 'app' tanto en local como en GitHub Actions.
"""
import os
import sys

# Raíz del proyecto (un nivel arriba de tests/)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Añadir backend y frontend al path
for folder in ("backend", "frontend"):
    path = os.path.join(ROOT, folder)
    if path not in sys.path:
        sys.path.insert(0, path)

# Variables de entorno por defecto para tests (si no están ya definidas)
defaults = {
    "SECRET_KEY":     "ci-test-secret-key-32bytes-xxxxx",
    "MYSQL_HOST":     "localhost",
    "MYSQL_DATABASE": "testdb",
    "MYSQL_USER":     "testuser",
    "MYSQL_PASSWORD": "testpass",
}
for key, val in defaults.items():
    os.environ.setdefault(key, val)
