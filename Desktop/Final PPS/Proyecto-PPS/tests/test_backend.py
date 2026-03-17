"""
=============================================================================
PRUEBAS BACKEND — Unitarias + Integración
=============================================================================
REQUISITO: "Se crearán tantos tipos de pruebas como se pueda, mínimo
de tipo unitarias como de integración."

Estrategia para MySQL en tests:
- MySQL real no disponible en CI → mockeamos el pool y las conexiones
  con unittest.mock para que los tests sean rápidos y reproducibles.
- Las pruebas unitarias verifican lógica pura (bcrypt, JWT) sin BD.
- Las pruebas de integración verifican los endpoints HTTP completos
  usando la app Flask en modo test con BD mockeada.
=============================================================================
"""

import os
import sys
import json
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

# Configurar variables de entorno ANTES de importar la app
os.environ["SECRET_KEY"]      = "test-secret-key-unit-tests"
os.environ["MYSQL_HOST"]      = "localhost"
os.environ["MYSQL_DATABASE"]  = "testdb"
os.environ["MYSQL_USER"]      = "testuser"
os.environ["MYSQL_PASSWORD"]  = "testpass"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))


# =============================================================================
# FIXTURES
# =============================================================================

def make_mock_cursor(rows=None, fetchone_val=None):
    """Crea un cursor MySQL mockeado con resultados predefinidos."""
    cur = MagicMock()
    cur.fetchone.return_value  = fetchone_val
    cur.fetchall.return_value  = rows or []
    cur.lastrowid              = 99
    return cur


def make_mock_db(cursor=None):
    """Crea una conexión MySQL mockeada."""
    db = MagicMock()
    db.is_connected.return_value = True
    db.cursor.return_value       = cursor or make_mock_cursor()
    return db


@pytest.fixture
def mock_pool(monkeypatch):
    """
    Mockea el pool de conexiones MySQL globalmente.
    Permite testear endpoints sin necesitar MySQL real.
    """
    pool = MagicMock()
    pool.get_connection.return_value = make_mock_db()

    import app as backend_app
    monkeypatch.setattr(backend_app, "_pool", pool)
    return pool


@pytest.fixture
def client(mock_pool):
    """Cliente de test Flask con pool mockeado."""
    import app as backend_app
    backend_app.app.config["TESTING"] = True

    # Mockear get_db para devolver conexión del pool mockeado
    mock_db = make_mock_db()
    with patch("app.get_db", return_value=mock_db):
        with backend_app.app.test_client() as c:
            yield c, mock_db


def admin_token():
    """Genera un token JWT de administrador para usar en tests."""
    import app as backend_app
    return backend_app.create_token(1, "admin", "admin")


def user_token():
    """Genera un token JWT de usuario normal para usar en tests."""
    import app as backend_app
    return backend_app.create_token(2, "usuario", "user")


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


# =============================================================================
# PRUEBAS UNITARIAS — bcrypt
# =============================================================================

class TestBcrypt:
    """
    Pruebas unitarias del hash de contraseñas con bcrypt.
    No necesitan BD ni red — verifican lógica pura.
    """

    def test_hash_is_not_plaintext(self):
        from app import hash_password
        h = hash_password("MiContraseña123!")
        assert h != "MiContraseña123!"
        assert len(h) > 20

    def test_hash_includes_bcrypt_prefix(self):
        """Los hashes bcrypt siempre empiezan con $2b$ o $2a$."""
        from app import hash_password
        h = hash_password("password")
        assert h.startswith("$2b$") or h.startswith("$2a$")

    def test_verify_correct_password(self):
        from app import hash_password, verify_password
        h = hash_password("Correcto123!")
        assert verify_password("Correcto123!", h) is True

    def test_verify_wrong_password(self):
        from app import hash_password, verify_password
        h = hash_password("Correcto123!")
        assert verify_password("Incorrecto!", h) is False

    def test_two_hashes_of_same_password_differ(self):
        """bcrypt genera salt aleatorio en cada llamada → hashes distintos."""
        from app import hash_password
        h1 = hash_password("misma")
        h2 = hash_password("misma")
        assert h1 != h2   # Salt diferente cada vez

    def test_both_hashes_verify_correctly(self):
        """Aunque los hashes difieran, ambos verifican correctamente."""
        from app import hash_password, verify_password
        h1 = hash_password("misma")
        h2 = hash_password("misma")
        assert verify_password("misma", h1)
        assert verify_password("misma", h2)


# =============================================================================
# PRUEBAS UNITARIAS — JWT
# =============================================================================

class TestJWT:
    """Pruebas unitarias del sistema de tokens JWT."""

    def test_create_and_verify_token(self):
        from app import create_token, verify_token
        token   = create_token(1, "admin", "admin")
        payload = verify_token(token)
        assert payload["user"] == "admin"
        assert payload["role"] == "admin"
        assert payload["sub"]  == "1"

    def test_user_token_has_user_role(self):
        from app import create_token, verify_token
        token   = create_token(2, "usuario", "user")
        payload = verify_token(token)
        assert payload["role"] == "user"

    def test_invalid_token_raises(self):
        import jwt
        from app import verify_token
        with pytest.raises(jwt.InvalidTokenError):
            verify_token("esto.no.es.un.jwt.valido")

    def test_tampered_token_raises(self):
        """Un token con firma modificada debe ser rechazado."""
        import jwt
        from app import create_token, verify_token
        token   = create_token(1, "admin", "admin")
        parts   = token.split(".")
        tampered = parts[0] + "." + parts[1] + ".firma_falsa"
        with pytest.raises(jwt.InvalidTokenError):
            verify_token(tampered)


# =============================================================================
# PRUEBAS UNITARIAS — Rate limiting
# =============================================================================

class TestRateLimit:
    def setup_method(self):
        """Limpiar intentos antes de cada test."""
        import app as backend_app
        backend_app._login_attempts.clear()

    def test_first_attempts_allowed(self):
        from app import check_rate_limit
        for _ in range(5):
            assert check_rate_limit("192.168.1.1") is True

    def test_sixth_attempt_blocked(self):
        from app import check_rate_limit
        for _ in range(5):
            check_rate_limit("10.0.0.1")
        assert check_rate_limit("10.0.0.1") is False

    def test_different_ips_independent(self):
        from app import check_rate_limit
        for _ in range(5):
            check_rate_limit("10.0.0.2")
        # IP diferente → no bloqueada
        assert check_rate_limit("10.0.0.3") is True


# =============================================================================
# PRUEBAS DE INTEGRACIÓN — Endpoints HTTP
# =============================================================================

class TestHealthEndpoint:
    def test_health_returns_200_when_db_ok(self, mock_pool):
        import app as backend_app
        backend_app.app.config["TESTING"] = True

        mock_cur = make_mock_cursor(fetchone_val=(1,))
        mock_db  = make_mock_db(mock_cur)

        with patch("app.get_db", return_value=mock_db):
            with backend_app.app.test_client() as c:
                resp = c.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["engine"] == "MySQL 8"


class TestLoginEndpoint:
    def test_login_success_admin(self, mock_pool):
        import app as backend_app
        import bcrypt as _bcrypt
        backend_app.app.config["TESTING"] = True

        pwd_hash = _bcrypt.hashpw(b"Admin1234!", _bcrypt.gensalt()).decode()
        mock_cur = make_mock_cursor(fetchone_val={
            "id": 1, "username": "admin",
            "password_hash": pwd_hash, "role": "admin", "active": 1
        })
        mock_db = make_mock_db(mock_cur)

        with patch("app.get_db", return_value=mock_db):
            with patch("app.check_rate_limit", return_value=True):
                with backend_app.app.test_client() as c:
                    resp = c.post("/api/login",
                                  json={"username": "admin", "password": "Admin1234!"},
                                  content_type="application/json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert "token" in data
        assert data["role"] == "admin"

    def test_login_wrong_password(self, mock_pool):
        import app as backend_app
        import bcrypt as _bcrypt
        backend_app.app.config["TESTING"] = True

        pwd_hash = _bcrypt.hashpw(b"Admin1234!", _bcrypt.gensalt()).decode()
        mock_cur = make_mock_cursor(fetchone_val={
            "id": 1, "username": "admin",
            "password_hash": pwd_hash, "role": "admin", "active": 1
        })
        mock_db = make_mock_db(mock_cur)

        with patch("app.get_db", return_value=mock_db):
            with patch("app.check_rate_limit", return_value=True):
                with patch("app.log_action"):
                    with backend_app.app.test_client() as c:
                        resp = c.post("/api/login",
                                      json={"username": "admin", "password": "WRONG"},
                                      content_type="application/json")
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, mock_pool):
        import app as backend_app
        backend_app.app.config["TESTING"] = True
        mock_cur = make_mock_cursor(fetchone_val=None)
        mock_db  = make_mock_db(mock_cur)

        with patch("app.get_db", return_value=mock_db):
            with patch("app.check_rate_limit", return_value=True):
                with patch("app.log_action"):
                    with backend_app.app.test_client() as c:
                        resp = c.post("/api/login",
                                      json={"username": "noexiste", "password": "x"},
                                      content_type="application/json")
        assert resp.status_code == 401

    def test_login_rate_limited(self, mock_pool):
        import app as backend_app
        backend_app.app.config["TESTING"] = True

        with patch("app.get_db", return_value=make_mock_db()):
            with patch("app.check_rate_limit", return_value=False):
                with backend_app.app.test_client() as c:
                    resp = c.post("/api/login",
                                  json={"username": "x", "password": "y"},
                                  content_type="application/json")
        assert resp.status_code == 429

    def test_login_empty_body(self, mock_pool):
        import app as backend_app
        backend_app.app.config["TESTING"] = True

        with patch("app.get_db", return_value=make_mock_db()):
            with patch("app.check_rate_limit", return_value=True):
                with backend_app.app.test_client() as c:
                    resp = c.post("/api/login", json={},
                                  content_type="application/json")
        assert resp.status_code == 400


class TestProtectedEndpoints:
    def _app_client(self, mock_pool, mock_db=None):
        import app as backend_app
        backend_app.app.config["TESTING"] = True
        return backend_app.app.test_client(), mock_db or make_mock_db()

    def test_profile_no_token(self, mock_pool):
        import app as backend_app
        backend_app.app.config["TESTING"] = True
        with patch("app.get_db", return_value=make_mock_db()):
            with backend_app.app.test_client() as c:
                resp = c.get("/api/profile")
        assert resp.status_code == 401

    def test_profile_with_admin_token(self, mock_pool):
        import app as backend_app
        backend_app.app.config["TESTING"] = True
        mock_cur = make_mock_cursor(fetchone_val={
            "id": 1, "username": "admin", "role": "admin", "created_at": "2024-01-01"
        })
        with patch("app.get_db", return_value=make_mock_db(mock_cur)):
            with backend_app.app.test_client() as c:
                resp = c.get("/api/profile", headers=auth_header(admin_token()))
        assert resp.status_code == 200

    def test_admin_users_blocked_for_user(self, mock_pool):
        import app as backend_app
        backend_app.app.config["TESTING"] = True
        with patch("app.get_db", return_value=make_mock_db()):
            with backend_app.app.test_client() as c:
                resp = c.get("/api/admin/users", headers=auth_header(user_token()))
        assert resp.status_code == 403

    def test_admin_users_accessible_for_admin(self, mock_pool):
        import app as backend_app
        backend_app.app.config["TESTING"] = True
        mock_cur = make_mock_cursor(rows=[
            {"id": 1, "username": "admin", "role": "admin",
             "active": 1, "created_at": "2024-01-01"}
        ])
        with patch("app.get_db", return_value=make_mock_db(mock_cur)):
            with patch("app.log_action"):
                with backend_app.app.test_client() as c:
                    resp = c.get("/api/admin/users", headers=auth_header(admin_token()))
        assert resp.status_code == 200
        data = resp.get_json()
        assert "users" in data

    def test_admin_logs_accessible_for_admin(self, mock_pool):
        import app as backend_app
        backend_app.app.config["TESTING"] = True
        mock_cur = make_mock_cursor(rows=[])
        with patch("app.get_db", return_value=make_mock_db(mock_cur)):
            with backend_app.app.test_client() as c:
                resp = c.get("/api/admin/logs", headers=auth_header(admin_token()))
        assert resp.status_code == 200

    def test_create_project_user_forbidden(self, mock_pool):
        import app as backend_app
        backend_app.app.config["TESTING"] = True
        with patch("app.get_db", return_value=make_mock_db()):
            with backend_app.app.test_client() as c:
                resp = c.post("/api/projects",
                              json={"name": "Test"},
                              headers=auth_header(user_token()),
                              content_type="application/json")
        assert resp.status_code == 403

    def test_create_project_admin_ok(self, mock_pool):
        import app as backend_app
        backend_app.app.config["TESTING"] = True
        mock_cur = make_mock_cursor()
        mock_db  = make_mock_db(mock_cur)
        with patch("app.get_db", return_value=mock_db):
            with patch("app.log_action"):
                with backend_app.app.test_client() as c:
                    resp = c.post("/api/projects",
                                  json={"name": "Nuevo", "status": "activo"},
                                  headers=auth_header(admin_token()),
                                  content_type="application/json")
        assert resp.status_code == 201


class TestSecurityHeaders:
    def test_security_headers_present(self, mock_pool):
        import app as backend_app
        backend_app.app.config["TESTING"] = True
        with patch("app.get_db", return_value=make_mock_db(
            make_mock_cursor(fetchone_val=(1,))
        )):
            with backend_app.app.test_client() as c:
                resp = c.get("/api/health")

        assert resp.headers.get("X-Frame-Options")        == "DENY"
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("Cache-Control")          == "no-store"
        assert "default-src" in resp.headers.get("Content-Security-Policy", "")
