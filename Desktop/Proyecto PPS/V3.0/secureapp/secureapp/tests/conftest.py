"""
conftest.py — Configuración automática de pytest.
Añade backend/ al sys.path ANTES que frontend/ para que
"import app" resuelva siempre al backend, no al frontend.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# IMPORTANTE: backend primero, luego frontend
# Si frontend va primero, "import app" importa frontend/app.py
for folder in ("backend", "frontend"):
    path = os.path.join(ROOT, folder)
    if path not in sys.path:
        sys.path.insert(0, path)

# Reordenar para garantizar que backend está ANTES que frontend
backend_path  = os.path.join(ROOT, "backend")
frontend_path = os.path.join(ROOT, "frontend")

# Eliminar ambos si existen y reinsertarlos en orden correcto
for p in [backend_path, frontend_path]:
    if p in sys.path:
        sys.path.remove(p)

sys.path.insert(0, frontend_path)  # frontend al fondo
sys.path.insert(0, backend_path)   # backend al principio → gana

# Variables de entorno por defecto para tests
defaults = {
    "SECRET_KEY":     "ci-test-secret-key-32bytes-xxxxx",
    "MYSQL_HOST":     "localhost",
    "MYSQL_DATABASE": "testdb",
    "MYSQL_USER":     "testuser",
    "MYSQL_PASSWORD": "testpass",
}
for key, val in defaults.items():
    os.environ.setdefault(key, val)
