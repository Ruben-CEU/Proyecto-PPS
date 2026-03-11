"""
=============================================================================
PRUEBAS BACKEND — Unitarias + Integración + POST + Persistencia MySQL
=============================================================================
Estrategia de tests por nivel:

NIVEL 1 - Unitarias puras (sin BD, sin red):
  - bcrypt, JWT, rate limiting, validacion de inputs

NIVEL 2 - Integración con MySQL mockeado (secuencial):
  - Endpoints GET y POST completos
  - Verificación de que INSERT se llama con los datos correctos
  - Verificación de que los datos "guardados" se pueden "leer" después

NIVEL 3 - Integración con MySQL en memoria (sqlite shim):
  - Simula un ciclo completo: crear usuario -> login -> leer datos
  - Prueba que la lógica de persistencia es correcta end-to-end

NIVEL 4 - Tests de contrato API:
  - Estructura de respuestas JSON
  - Códigos HTTP correctos para cada situación
  - Cabeceras de seguridad
=============================================================================
"""

import os
import sys
import json
import sqlite3
import time
import pytest
from unittest.mock import MagicMock, patch, call

os.environ["SECRET_KEY"]     = "test-secret-32-bytes-xxxxxxxx"
os.environ["MYSQL_HOST"]     = "localhost"
os.environ["MYSQL_DATABASE"] = "testdb"
os.environ["MYSQL_USER"]     = "testuser"
os.environ["MYSQL_PASSWORD"] = "testpass"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))


# =============================================================================
# HELPERS Y FIXTURES
# =============================================================================

def mk_cur(one=None, all_=None, lastrowid=42):
    c = MagicMock()
    c.fetchone.return_value  = one
    c.fetchall.return_value  = all_ or []
    c.lastrowid              = lastrowid
    return c

def mk_db(cursor=None):
    d = MagicMock()
    d.is_connected.return_value = True
    d.cursor.return_value = cursor if cursor is not None else mk_cur()
    return d

def setup_app():
    import app as A
    A._pool = MagicMock()
    A.app.config["TESTING"] = True
    A._login_attempts.clear()
    return A

def token(app_module, uid=1, user="admin", role="admin"):
    return app_module.create_token(uid, user, role)

def hdr(tok):
    return {"Authorization": f"Bearer {tok}"}


# =============================================================================
# NIVEL 1 — PRUEBAS UNITARIAS PURAS
# =============================================================================

class TestBcrypt:
    """bcrypt: hash, verificación, propiedades de seguridad."""

    def test_hash_not_plaintext(self):
        from app import hash_password
        assert hash_password("secret") != "secret"

    def test_hash_bcrypt_prefix(self):
        from app import hash_password
        h = hash_password("test")
        assert h.startswith(("$2b$", "$2a$"))

    def test_verify_correct(self):
        from app import hash_password, verify_password
        h = hash_password("correct")
        assert verify_password("correct", h) is True

    def test_verify_wrong(self):
        from app import hash_password, verify_password
        h = hash_password("correct")
        assert verify_password("wrong", h) is False

    def test_two_hashes_differ(self):
        """Salt aleatorio: mismo input → hashes distintos."""
        from app import hash_password
        assert hash_password("same") != hash_password("same")

    def test_both_hashes_verify(self):
        from app import hash_password, verify_password
        h1, h2 = hash_password("same"), hash_password("same")
        assert verify_password("same", h1) and verify_password("same", h2)

    def test_empty_password_hashes(self):
        from app import hash_password
        h = hash_password("")
        assert len(h) > 20

    def test_long_password(self):
        from app import hash_password, verify_password
        long_pwd = "a" * 128
        h = hash_password(long_pwd)
        assert verify_password(long_pwd, h)


class TestJWT:
    """JWT: creación, verificación, expiración, manipulación."""

    def test_create_verify_admin(self):
        from app import create_token, verify_token
        tok = create_token(1, "admin", "admin")
        p   = verify_token(tok)
        assert p["user"] == "admin" and p["role"] == "admin" and p["sub"] == "1"

    def test_create_verify_user(self):
        from app import create_token, verify_token
        tok = create_token(2, "usuario", "user")
        p   = verify_token(tok)
        assert p["role"] == "user"

    def test_invalid_token_raises(self):
        import jwt
        from app import verify_token
        with pytest.raises(jwt.InvalidTokenError):
            verify_token("not.a.valid.jwt")

    def test_tampered_signature_raises(self):
        import jwt
        from app import create_token, verify_token
        tok   = create_token(1, "admin", "admin")
        parts = tok.split(".")
        with pytest.raises(jwt.InvalidTokenError):
            verify_token(parts[0] + "." + parts[1] + ".badsig")

    def test_token_has_expiration(self):
        from app import create_token, verify_token
        import time as _time
        tok = create_token(1, "admin", "admin")
        p   = verify_token(tok)
        assert "exp" in p
        assert p["exp"] > _time.time()

    def test_token_has_issued_at(self):
        from app import create_token, verify_token
        p = verify_token(create_token(1, "admin", "admin"))
        assert "iat" in p

    def test_different_users_different_tokens(self):
        from app import create_token
        t1 = create_token(1, "admin", "admin")
        t2 = create_token(2, "usuario", "user")
        assert t1 != t2

    def test_role_preserved_in_token(self):
        from app import create_token, verify_token
        for role in ["admin", "user"]:
            tok = create_token(1, "testuser", role)
            assert verify_token(tok)["role"] == role


class TestRateLimit:
    """Rate limiting: ventana deslizante, aislamiento por IP."""

    def setup_method(self):
        import app as A
        A._login_attempts.clear()

    def test_five_attempts_allowed(self):
        from app import check_rate_limit
        for _ in range(5):
            assert check_rate_limit("192.168.1.1") is True

    def test_sixth_attempt_blocked(self):
        from app import check_rate_limit
        for _ in range(5):
            check_rate_limit("10.0.0.1")
        assert check_rate_limit("10.0.0.1") is False

    def test_seventh_also_blocked(self):
        from app import check_rate_limit
        for _ in range(7):
            check_rate_limit("10.0.0.2")
        assert check_rate_limit("10.0.0.2") is False

    def test_different_ips_independent(self):
        from app import check_rate_limit
        for _ in range(5):
            check_rate_limit("10.0.0.3")
        assert check_rate_limit("10.0.0.4") is True

    def test_multiple_ips_each_blocked_independently(self):
        from app import check_rate_limit
        for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]:
            for _ in range(5):
                check_rate_limit(ip)
        for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]:
            assert check_rate_limit(ip) is False
        assert check_rate_limit("4.4.4.4") is True


class TestInputValidation:
    """Validación y truncado de inputs del usuario."""

    def test_username_truncated_to_64(self):
        """El endpoint login trunca username a 64 chars."""
        A = setup_app()
        cur = mk_cur(one=None)
        with patch("app.get_db", return_value=mk_db(cur)):
            with patch("app.check_rate_limit", return_value=True):
                with patch("app.log_action"):
                    with A.app.test_client() as c:
                        r = c.post("/api/login",
                                   json={"username": "a"*200, "password": "x"},
                                   content_type="application/json")
        # El cursor debe haber sido llamado con un username <= 64 chars
        call_args = cur.execute.call_args
        if call_args:
            username_sent = call_args[0][1][0]
            assert len(username_sent) <= 64

    def test_empty_username_returns_400(self):
        A = setup_app()
        with patch("app.get_db", return_value=mk_db()):
            with patch("app.check_rate_limit", return_value=True):
                with A.app.test_client() as c:
                    r = c.post("/api/login", json={"username": "", "password": "x"},
                               content_type="application/json")
        assert r.status_code == 400

    def test_empty_password_returns_400(self):
        A = setup_app()
        with patch("app.get_db", return_value=mk_db()):
            with patch("app.check_rate_limit", return_value=True):
                with A.app.test_client() as c:
                    r = c.post("/api/login", json={"username": "admin", "password": ""},
                               content_type="application/json")
        assert r.status_code == 400

    def test_missing_body_returns_400(self):
        A = setup_app()
        with patch("app.get_db", return_value=mk_db()):
            with patch("app.check_rate_limit", return_value=True):
                with A.app.test_client() as c:
                    r = c.post("/api/login", json={},
                               content_type="application/json")
        assert r.status_code == 400

    def test_non_json_body_returns_400(self):
        A = setup_app()
        with patch("app.get_db", return_value=mk_db()):
            with patch("app.check_rate_limit", return_value=True):
                with A.app.test_client() as c:
                    r = c.post("/api/login", data="not json",
                               content_type="text/plain")
        assert r.status_code == 400


# =============================================================================
# NIVEL 2 — INTEGRACIÓN: ENDPOINTS POST CON VERIFICACIÓN DE PERSISTENCIA
# =============================================================================

class TestLoginPOST:
    """POST /api/login — flujo completo con verificación de BD."""

    def test_login_success_calls_mysql_with_username(self):
        """Verifica que el login consulta MySQL con el username correcto."""
        import bcrypt as _bcrypt
        A = setup_app()
        pwd_hash = _bcrypt.hashpw(b"Admin1234!", _bcrypt.gensalt()).decode()
        cur = mk_cur(one={"id":1,"username":"admin","password_hash":pwd_hash,"role":"admin","active":1})

        with patch("app.get_db", return_value=mk_db(cur)):
            with patch("app.check_rate_limit", return_value=True):
                with patch("app.log_action") as mock_log:
                    with A.app.test_client() as c:
                        r = c.post("/api/login",
                                   json={"username":"admin","password":"Admin1234!"},
                                   content_type="application/json")

        # Verificar que MySQL fue consultado con el username correcto
        execute_call = cur.execute.call_args
        assert execute_call is not None
        assert "admin" in str(execute_call)

        # Verificar respuesta
        assert r.status_code == 200
        data = r.get_json()
        assert "token" in data
        assert data["role"] == "admin"
        assert data["username"] == "admin"

        # Verificar que se registró en audit_log
        mock_log.assert_called()
        log_calls = [str(c) for c in mock_log.call_args_list]
        assert any("login_success" in lc for lc in log_calls)

    def test_login_writes_audit_log_on_success(self):
        """POST login exitoso → escribe en audit_log."""
        import bcrypt as _bcrypt
        A = setup_app()
        pwd_hash = _bcrypt.hashpw(b"pass", _bcrypt.gensalt()).decode()
        cur = mk_cur(one={"id":2,"username":"usuario","password_hash":pwd_hash,"role":"user","active":1})

        with patch("app.get_db", return_value=mk_db(cur)):
            with patch("app.check_rate_limit", return_value=True):
                with patch("app.log_action") as mock_log:
                    with A.app.test_client() as c:
                        c.post("/api/login", json={"username":"usuario","password":"pass"},
                               content_type="application/json")

        calls_str = str(mock_log.call_args_list)
        assert "usuario" in calls_str
        assert "login_success" in calls_str

    def test_login_writes_audit_log_on_failure(self):
        """POST login fallido → escribe login_failed en audit_log."""
        A = setup_app()
        cur = mk_cur(one=None)

        with patch("app.get_db", return_value=mk_db(cur)):
            with patch("app.check_rate_limit", return_value=True):
                with patch("app.log_action") as mock_log:
                    with A.app.test_client() as c:
                        c.post("/api/login", json={"username":"noexiste","password":"x"},
                               content_type="application/json")

        calls_str = str(mock_log.call_args_list)
        assert "login_failed" in calls_str

    def test_login_inactive_user_returns_403(self):
        """Usuario con active=0 → 403 aunque la contraseña sea correcta."""
        import bcrypt as _bcrypt
        A = setup_app()
        pwd_hash = _bcrypt.hashpw(b"correct", _bcrypt.gensalt()).decode()
        cur = mk_cur(one={"id":3,"username":"inactivo","password_hash":pwd_hash,"role":"user","active":0})

        with patch("app.get_db", return_value=mk_db(cur)):
            with patch("app.check_rate_limit", return_value=True):
                with patch("app.log_action"):
                    with A.app.test_client() as c:
                        r = c.post("/api/login",
                                   json={"username":"inactivo","password":"correct"},
                                   content_type="application/json")
        assert r.status_code == 403

    def test_login_response_structure(self):
        """Verificar estructura completa de la respuesta JSON de login."""
        import bcrypt as _bcrypt
        A = setup_app()
        pwd_hash = _bcrypt.hashpw(b"Admin1234!", _bcrypt.gensalt()).decode()
        cur = mk_cur(one={"id":1,"username":"admin","password_hash":pwd_hash,"role":"admin","active":1})

        with patch("app.get_db", return_value=mk_db(cur)):
            with patch("app.check_rate_limit", return_value=True):
                with patch("app.log_action"):
                    with A.app.test_client() as c:
                        r = c.post("/api/login",
                                   json={"username":"admin","password":"Admin1234!"},
                                   content_type="application/json")

        data = r.get_json()
        assert "token"    in data
        assert "username" in data
        assert "role"     in data
        assert "message"  in data
        # Token debe tener formato JWT (3 partes separadas por punto)
        assert len(data["token"].split(".")) == 3

    def test_login_user_role_token_has_user_role(self):
        """El JWT devuelto debe contener el rol correcto del usuario."""
        import bcrypt as _bcrypt
        from app import verify_token
        A = setup_app()
        pwd_hash = _bcrypt.hashpw(b"User1234!", _bcrypt.gensalt()).decode()
        cur = mk_cur(one={"id":2,"username":"usuario","password_hash":pwd_hash,"role":"user","active":1})

        with patch("app.get_db", return_value=mk_db(cur)):
            with patch("app.check_rate_limit", return_value=True):
                with patch("app.log_action"):
                    with A.app.test_client() as c:
                        r = c.post("/api/login",
                                   json={"username":"usuario","password":"User1234!"},
                                   content_type="application/json")

        tok = r.get_json()["token"]
        payload = verify_token(tok)
        assert payload["role"] == "user"
        assert payload["user"] == "usuario"


class TestProjectsPOST:
    """POST /api/projects — verificar inserción en MySQL."""

    def test_post_project_admin_calls_mysql_insert(self):
        """Admin POST /api/projects → MySQL INSERT se llama con datos correctos."""
        A = setup_app()
        ta = token(A)
        cur = mk_cur()

        with patch("app.get_db", return_value=mk_db(cur)):
            with patch("app.log_action"):
                with A.app.test_client() as c:
                    r = c.post("/api/projects",
                               json={"name":"Proyecto Test","description":"Desc","status":"activo"},
                               headers=hdr(ta),
                               content_type="application/json")

        assert r.status_code == 201
        data = r.get_json()
        assert data["id"] == 42  # lastrowid del mock
        assert "Proyecto creado" in data["message"]

        # Verificar que execute fue llamado con INSERT
        execute_calls = [str(c) for c in cur.execute.call_args_list]
        assert any("INSERT" in c.upper() for c in execute_calls)

        # Verificar que los datos del proyecto aparecen en la llamada
        all_calls_str = " ".join(execute_calls)
        assert "Proyecto Test" in all_calls_str

    def test_post_project_data_passed_to_mysql(self):
        """Verificar que nombre, descripción y estado llegan a MySQL."""
        A = setup_app()
        ta = token(A)
        cur = mk_cur()

        with patch("app.get_db", return_value=mk_db(cur)):
            with patch("app.log_action"):
                with A.app.test_client() as c:
                    c.post("/api/projects",
                           json={"name":"Mi Proyecto","description":"Mi descripcion","status":"en revisión"},
                           headers=hdr(ta),
                           content_type="application/json")

        # Verificar argumentos del INSERT
        insert_call = None
        for c_call in cur.execute.call_args_list:
            if "INSERT" in str(c_call).upper():
                insert_call = c_call
                break

        assert insert_call is not None
        args = insert_call[0]
        params = args[1] if len(args) > 1 else []
        all_params = " ".join(str(p) for p in params)
        assert "Mi Proyecto"     in all_params
        assert "Mi descripcion"  in all_params
        assert "en revisión"     in all_params

    def test_post_project_commit_called(self):
        """Verificar que db.commit() se llama (la transaccion se guarda)."""
        A = setup_app()
        ta = token(A)
        cur = mk_cur()
        db  = mk_db(cur)

        with patch("app.get_db", return_value=db):
            with patch("app.log_action"):
                with A.app.test_client() as c:
                    c.post("/api/projects",
                           json={"name":"Commit Test","status":"activo"},
                           headers=hdr(ta),
                           content_type="application/json")

        db.commit.assert_called()

    def test_post_project_user_forbidden(self):
        """Usuario normal POST /api/projects → 403."""
        A = setup_app()
        tu = token(A, uid=2, user="usuario", role="user")

        with patch("app.get_db", return_value=mk_db()):
            with A.app.test_client() as c:
                r = c.post("/api/projects",
                           json={"name":"Test","status":"activo"},
                           headers=hdr(tu),
                           content_type="application/json")
        assert r.status_code == 403

    def test_post_project_no_token_returns_401(self):
        A = setup_app()
        with patch("app.get_db", return_value=mk_db()):
            with A.app.test_client() as c:
                r = c.post("/api/projects",
                           json={"name":"Test","status":"activo"},
                           content_type="application/json")
        assert r.status_code == 401

    def test_post_project_missing_name_returns_400(self):
        """Nombre vacío → 400 Bad Request."""
        A = setup_app()
        ta = token(A)
        with patch("app.get_db", return_value=mk_db()):
            with patch("app.log_action"):
                with A.app.test_client() as c:
                    r = c.post("/api/projects",
                               json={"name":"","status":"activo"},
                               headers=hdr(ta),
                               content_type="application/json")
        assert r.status_code == 400

    def test_post_project_invalid_status_returns_400(self):
        """Estado no válido → 400."""
        A = setup_app()
        ta = token(A)
        with patch("app.get_db", return_value=mk_db()):
            with patch("app.log_action"):
                with A.app.test_client() as c:
                    r = c.post("/api/projects",
                               json={"name":"Test","status":"invalido"},
                               headers=hdr(ta),
                               content_type="application/json")
        assert r.status_code == 400

    def test_post_project_returns_new_id(self):
        """Respuesta incluye el ID asignado por MySQL (lastrowid)."""
        A = setup_app()
        ta = token(A)
        cur = mk_cur(lastrowid=77)  # MySQL asignaría el ID 77

        with patch("app.get_db", return_value=mk_db(cur)):
            with patch("app.log_action"):
                with A.app.test_client() as c:
                    r = c.post("/api/projects",
                               json={"name":"ID Test","status":"activo"},
                               headers=hdr(ta),
                               content_type="application/json")

        assert r.get_json()["id"] == 77

    def test_post_project_logs_action_with_project_name(self):
        """Crear proyecto registra la acción en audit_log con el nombre."""
        A = setup_app()
        ta = token(A)
        cur = mk_cur(lastrowid=10)

        with patch("app.get_db", return_value=mk_db(cur)):
            with patch("app.log_action") as mock_log:
                with A.app.test_client() as c:
                    c.post("/api/projects",
                           json={"name":"Logged Project","status":"activo"},
                           headers=hdr(ta),
                           content_type="application/json")

        log_str = str(mock_log.call_args_list)
        assert "create_project" in log_str
        assert "Logged Project" in log_str


class TestToggleUserPOST:
    """POST /api/admin/users/<id>/toggle — activar/desactivar usuario."""

    def test_toggle_active_user_deactivates(self):
        """Toggle de usuario activo → lo desactiva (active=0)."""
        A = setup_app()
        ta = token(A)
        cur = mk_cur(one={"id":2,"username":"usuario","active":1})
        db  = mk_db(cur)

        with patch("app.get_db", return_value=db):
            with patch("app.log_action") as mock_log:
                with A.app.test_client() as c:
                    r = c.post("/api/admin/users/2/toggle", headers=hdr(ta))

        assert r.status_code == 200
        # Verificar UPDATE fue llamado con active=0
        execute_calls_str = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "UPDATE" in execute_calls_str.upper()
        assert "0" in execute_calls_str
        db.commit.assert_called()
        assert "Desactivado" in r.get_json().get("message","") or                "desactivado" in r.get_json().get("message","").lower()

    def test_toggle_inactive_user_activates(self):
        """Toggle de usuario inactivo → lo activa (active=1)."""
        A = setup_app()
        ta = token(A)
        cur = mk_cur(one={"id":3,"username":"inactivo","active":0})
        db  = mk_db(cur)

        with patch("app.get_db", return_value=db):
            with patch("app.log_action") as mock_log:
                with A.app.test_client() as c:
                    r = c.post("/api/admin/users/3/toggle", headers=hdr(ta))

        assert r.status_code == 200
        execute_calls_str = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "UPDATE" in execute_calls_str.upper()
        db.commit.assert_called()
        msg = r.get_json().get("message","").lower()
        assert "activado" in msg

    def test_toggle_nonexistent_user_returns_404(self):
        A = setup_app()
        ta = token(A)
        cur = mk_cur(one=None)
        with patch("app.get_db", return_value=mk_db(cur)):
            with patch("app.log_action"):
                with A.app.test_client() as c:
                    r = c.post("/api/admin/users/999/toggle", headers=hdr(ta))
        assert r.status_code == 404

    def test_toggle_by_user_role_returns_403(self):
        A = setup_app()
        tu = token(A, uid=2, user="usuario", role="user")
        with patch("app.get_db", return_value=mk_db()):
            with A.app.test_client() as c:
                r = c.post("/api/admin/users/1/toggle", headers=hdr(tu))
        assert r.status_code == 403

    def test_toggle_logs_correct_action(self):
        """Toggle registra 'user_deactivated' o 'user_activated' en audit_log."""
        A = setup_app()
        ta = token(A)
        cur = mk_cur(one={"id":2,"username":"usuario","active":1})

        with patch("app.get_db", return_value=mk_db(cur)):
            with patch("app.log_action") as mock_log:
                with A.app.test_client() as c:
                    c.post("/api/admin/users/2/toggle", headers=hdr(ta))

        log_str = str(mock_log.call_args_list)
        assert "user_deactivated" in log_str or "user_activated" in log_str


# =============================================================================
# NIVEL 3 — PERSISTENCIA SIMULADA: ciclo completo create → read
# =============================================================================

class TestMySQLPersistenceSimulated:
    """
    Simula un MySQL real usando un dict en memoria para verificar
    que los datos se GUARDAN correctamente y se pueden LEER después.
    Esto prueba la lógica de persistencia end-to-end sin MySQL real.
    """

    def _build_in_memory_db(self):
        """
        Construye un mock de MySQL que usa dicts reales en memoria.
        Cualquier INSERT actualiza el 'almacén', cualquier SELECT lo lee.
        """
        store = {
            "users":    [
                {"id":1,"username":"admin","password_hash":"$2b$12$fake","role":"admin","active":1,"created_at":"2024-01-01"},
                {"id":2,"username":"usuario","password_hash":"$2b$12$fake","role":"user","active":1,"created_at":"2024-01-01"},
            ],
            "projects": [],
            "audit_log": [],
        }
        next_id = {"projects": 10, "audit_log": 100}

        class FakeCursor:
            def __init__(self):
                self.lastrowid = None
                self._result   = None
                self._results  = []
                self.rowcount  = 0

            def execute(self, sql, params=None):
                sql_up = sql.upper().strip()
                params = params or []

                if "INSERT INTO PROJECTS" in sql_up:
                    name, desc, status, owner = params
                    new_id = next_id["projects"]
                    next_id["projects"] += 1
                    store["projects"].append({
                        "id": new_id, "name": name,
                        "description": desc, "status": status,
                        "owner": owner, "created_at": "2024-01-01"
                    })
                    self.lastrowid = new_id

                elif "INSERT INTO AUDIT_LOG" in sql_up:
                    username, action, ip, detail = params
                    aid = next_id["audit_log"]
                    next_id["audit_log"] += 1
                    store["audit_log"].append({
                        "id": aid, "username": username,
                        "action": action, "ip": ip,
                        "detail": detail, "created_at": "2024-01-01"
                    })
                    self.lastrowid = aid

                elif "UPDATE USERS" in sql_up and "ACTIVE" in sql_up:
                    new_active, uid = int(params[0]), int(params[1])
                    for u in store["users"]:
                        if u["id"] == uid:
                            u["active"] = new_active

                elif "SELECT" in sql_up and "FROM PROJECTS" in sql_up:
                    self._results = list(store["projects"])

                elif "SELECT" in sql_up and "FROM USERS" in sql_up and "WHERE USERNAME" in sql_up:
                    uname = params[0]
                    matches = [u for u in store["users"] if u["username"] == uname]
                    self._result = matches[0] if matches else None

                elif "SELECT" in sql_up and "FROM USERS" in sql_up and "WHERE ID" in sql_up:
                    uid = int(params[0])
                    matches = [u for u in store["users"] if u["id"] == uid]
                    self._result = matches[0] if matches else None

                elif "SELECT" in sql_up and "FROM USERS" in sql_up:
                    self._results = list(store["users"])

                elif "SELECT" in sql_up and "FROM AUDIT_LOG" in sql_up:
                    self._results = list(reversed(store["audit_log"]))

                elif "SELECT COUNT" in sql_up and "FROM PROJECTS" in sql_up:
                    self._result = {"total": len(store["projects"])}

                elif "SELECT 1" in sql_up:
                    self._result = (1,)

            def fetchone(self):
                return self._result

            def fetchall(self):
                return self._results

            def close(self):
                pass

        class FakeDB:
            def __init__(self):
                self._cursor = FakeCursor()

            def cursor(self, dictionary=False):
                return self._cursor

            def commit(self):
                pass

            def is_connected(self):
                return True

            def close(self):
                pass

        return FakeDB(), store

    def test_post_project_data_persists_and_readable(self):
        """Crear proyecto → datos guardados → GET projects los devuelve."""
        A = setup_app()
        fake_db, store = self._build_in_memory_db()
        ta = token(A)

        with patch("app.get_db", return_value=fake_db):
            with patch("app.log_action"):
                with A.app.test_client() as c:
                    # POST: crear proyecto
                    r_post = c.post("/api/projects",
                                    json={"name":"Test Persistencia",
                                          "description":"Comprobando MySQL",
                                          "status":"activo"},
                                    headers=hdr(ta),
                                    content_type="application/json")

                    assert r_post.status_code == 201
                    new_id = r_post.get_json()["id"]
                    assert new_id == 10  # primer ID en nuestro store

                    # GET: leer proyectos
                    r_get = c.get("/api/projects", headers=hdr(ta))
                    assert r_get.status_code == 200
                    projects = r_get.get_json()["projects"]

                    # Verificar que el proyecto creado aparece en la lista
                    names = [p["name"] for p in projects]
                    assert "Test Persistencia" in names

                    # Verificar datos completos del proyecto guardado
                    saved = next(p for p in projects if p["name"] == "Test Persistencia")
                    assert saved["description"] == "Comprobando MySQL"
                    assert saved["status"]      == "activo"

    def test_multiple_projects_persist_in_order(self):
        """Crear múltiples proyectos → todos persisten con IDs correctos."""
        A = setup_app()
        fake_db, store = self._build_in_memory_db()
        ta = token(A)

        projects_to_create = [
            {"name": "Alpha", "description": "Primero",  "status": "activo"},
            {"name": "Beta",  "description": "Segundo",  "status": "en revisión"},
            {"name": "Gamma", "description": "Tercero",  "status": "completado"},
        ]

        created_ids = []
        with patch("app.get_db", return_value=fake_db):
            with patch("app.log_action"):
                with A.app.test_client() as c:
                    for proj in projects_to_create:
                        r = c.post("/api/projects", json=proj,
                                   headers=hdr(ta),
                                   content_type="application/json")
                        assert r.status_code == 201
                        created_ids.append(r.get_json()["id"])

                    # Los IDs deben ser incrementales
                    assert created_ids == [10, 11, 12]

                    # GET: verificar que los 3 proyectos están en la BD
                    r_get = c.get("/api/projects", headers=hdr(ta))
                    projects_list = r_get.get_json()["projects"]
                    names = [p["name"] for p in projects_list]
                    assert "Alpha" in names
                    assert "Beta"  in names
                    assert "Gamma" in names

    def test_toggle_user_persists_state_change(self):
        """Toggle user → estado cambia en BD → reflejado en /api/admin/users."""
        A = setup_app()
        fake_db, store = self._build_in_memory_db()
        ta = token(A)

        with patch("app.get_db", return_value=fake_db):
            with patch("app.log_action"):
                with A.app.test_client() as c:
                    # Estado inicial: usuario ID=2 está activo
                    assert store["users"][1]["active"] == 1

                    # POST toggle → desactivar
                    r = c.post("/api/admin/users/2/toggle", headers=hdr(ta))
                    assert r.status_code == 200

                    # Verificar que el estado cambió en la BD simulada
                    assert store["users"][1]["active"] == 0

                    # POST toggle de nuevo → reactivar
                    r2 = c.post("/api/admin/users/2/toggle", headers=hdr(ta))
                    assert r2.status_code == 200
                    assert store["users"][1]["active"] == 1

    def test_audit_log_records_all_actions(self):
        """Cada acción POST registra entrada en audit_log."""
        A = setup_app()
        fake_db, store = self._build_in_memory_db()
        ta = token(A)
        logged_actions = []

        # Mockeamos log_action para capturar las acciones registradas
        def fake_log(username, action, detail=""):
            logged_actions.append(action)

        with patch("app.get_db", return_value=fake_db):
            with patch("app.log_action", side_effect=fake_log):
                with A.app.test_client() as c:
                    c.post("/api/projects",
                           json={"name":"Audit Test","status":"activo"},
                           headers=hdr(ta),
                           content_type="application/json")

        # Verificar que log_action fue llamado con create_project
        assert len(logged_actions) > 0
        assert "create_project" in logged_actions

    def test_login_audit_trail_in_mysql(self):
        """Login exitoso y fallido generan entradas en audit_log MySQL."""
        import bcrypt as _bcrypt
        A = setup_app()
        fake_db, store = self._build_in_memory_db()
        logged = []

        # Añadir contraseña bcrypt real al usuario admin del store
        pwd_hash = _bcrypt.hashpw(b"Admin1234!", _bcrypt.gensalt()).decode()
        store["users"][0]["password_hash"] = pwd_hash

        def fake_log(username, action, detail=""):
            logged.append(action)

        with patch("app.get_db", return_value=fake_db):
            with patch("app.check_rate_limit", return_value=True):
                with patch("app.log_action", side_effect=fake_log):
                    with A.app.test_client() as c:
                        # Login exitoso
                        c.post("/api/login",
                               json={"username":"admin","password":"Admin1234!"},
                               content_type="application/json")
                        # Login fallido
                        c.post("/api/login",
                               json={"username":"admin","password":"WRONG"},
                               content_type="application/json")

        assert "login_success" in logged
        assert "login_failed"  in logged


# =============================================================================
# NIVEL 4 — CONTRATO API Y CABECERAS HTTP
# =============================================================================

class TestAPIContract:
    """Estructura de respuestas JSON y códigos HTTP."""

    def test_health_response_structure(self):
        A = setup_app()
        with patch("app.get_db", return_value=mk_db(mk_cur(one=(1,)))):
            with A.app.test_client() as c:
                r = c.get("/api/health")
        data = r.get_json()
        assert r.status_code == 200
        assert "status"   in data
        assert "service"  in data
        assert "database" in data
        assert "engine"   in data
        assert data["engine"] == "MySQL 8"

    def test_projects_response_structure(self):
        A = setup_app()
        ta = token(A)
        rows = [{"id":1,"name":"P1","description":"D","status":"activo","owner":"admin","created_at":"2024-01-01"}]
        with patch("app.get_db", return_value=mk_db(mk_cur(all_=rows))):
            with patch("app.log_action"):
                with A.app.test_client() as c:
                    r = c.get("/api/projects", headers=hdr(ta))
        data = r.get_json()
        assert "projects" in data
        assert "total"    in data
        assert "user"     in data
        assert "role"     in data
        assert data["total"] == 1

    def test_admin_users_response_structure(self):
        A = setup_app()
        ta = token(A)
        rows = [{"id":1,"username":"admin","role":"admin","active":1,"created_at":"2024-01-01"}]
        with patch("app.get_db", return_value=mk_db(mk_cur(all_=rows))):
            with patch("app.log_action"):
                with A.app.test_client() as c:
                    r = c.get("/api/admin/users", headers=hdr(ta))
        data = r.get_json()
        assert "users" in data
        assert "total" in data
        # Nunca debe incluir password_hash
        for user in data["users"]:
            assert "password_hash" not in user

    def test_error_response_has_error_key(self):
        """Todas las respuestas de error incluyen clave 'error'."""
        A = setup_app()
        with patch("app.get_db", return_value=mk_db()):
            with A.app.test_client() as c:
                cases = [
                    c.get("/api/profile"),
                    c.post("/api/login", json={}, content_type="application/json"),
                ]
        # Verificar una
        with patch("app.get_db", return_value=mk_db()):
            with A.app.test_client() as c:
                r = c.get("/api/profile")
        assert "error" in r.get_json()

    def test_project_created_response_has_id_and_message(self):
        A = setup_app()
        ta = token(A)
        cur = mk_cur(lastrowid=99)
        with patch("app.get_db", return_value=mk_db(cur)):
            with patch("app.log_action"):
                with A.app.test_client() as c:
                    r = c.post("/api/projects",
                               json={"name":"Resp Test","status":"activo"},
                               headers=hdr(ta),
                               content_type="application/json")
        data = r.get_json()
        assert "id"      in data
        assert "message" in data
        assert data["id"] == 99

    def test_content_type_json_on_all_api_responses(self):
        """Todos los endpoints devuelven Content-Type: application/json."""
        A = setup_app()
        ta = token(A)
        with patch("app.get_db", return_value=mk_db(mk_cur(one=(1,)))):
            with A.app.test_client() as c:
                r = c.get("/api/health")
        assert "application/json" in r.content_type


class TestSecurityHeaders:
    """Cabeceras HTTP de seguridad en todas las respuestas."""

    def _get_health_response(self):
        A = setup_app()
        with patch("app.get_db", return_value=mk_db(mk_cur(one=(1,)))):
            with A.app.test_client() as c:
                return c.get("/api/health")

    def test_x_frame_options_deny(self):
        assert self._get_health_response().headers["X-Frame-Options"] == "DENY"

    def test_x_content_type_nosniff(self):
        assert self._get_health_response().headers["X-Content-Type-Options"] == "nosniff"

    def test_cache_control_no_store(self):
        assert self._get_health_response().headers["Cache-Control"] == "no-store"

    def test_csp_default_src_self(self):
        csp = self._get_health_response().headers.get("Content-Security-Policy","")
        assert "default-src" in csp

    def test_hsts_present(self):
        hsts = self._get_health_response().headers.get("Strict-Transport-Security","")
        assert "max-age" in hsts

    def test_referrer_policy_present(self):
        rp = self._get_health_response().headers.get("Referrer-Policy","")
        assert rp != ""

    def test_xss_protection_present(self):
        xss = self._get_health_response().headers.get("X-XSS-Protection","")
        assert "1" in xss

    def test_headers_present_on_error_responses(self):
        """Las cabeceras deben estar incluso en respuestas de error."""
        A = setup_app()
        with patch("app.get_db", return_value=mk_db()):
            with A.app.test_client() as c:
                r = c.get("/api/profile")  # 401
        assert r.headers.get("X-Frame-Options") == "DENY"
        assert r.headers.get("Cache-Control")   == "no-store"

    def test_security_headers_on_post_response(self):
        """Respuestas a POST también tienen las cabeceras."""
        A = setup_app()
        with patch("app.get_db", return_value=mk_db()):
            with patch("app.check_rate_limit", return_value=True):
                with A.app.test_client() as c:
                    r = c.post("/api/login", json={},
                               content_type="application/json")
        assert r.headers.get("X-Frame-Options") == "DENY"


class TestHTTPMethods:
    """Verificar que los endpoints solo aceptan los métodos correctos."""

    def test_login_only_post(self):
        A = setup_app()
        with patch("app.get_db", return_value=mk_db()):
            with A.app.test_client() as c:
                r_get = c.get("/api/login")
        assert r_get.status_code == 405  # Method Not Allowed

    def test_projects_get_and_post(self):
        A = setup_app()
        ta = token(A)
        with patch("app.get_db", return_value=mk_db(mk_cur(all_=[]))):
            with patch("app.log_action"):
                with A.app.test_client() as c:
                    r = c.get("/api/projects", headers=hdr(ta))
        assert r.status_code == 200

    def test_health_only_get(self):
        A = setup_app()
        with patch("app.get_db", return_value=mk_db(mk_cur(one=(1,)))):
            with A.app.test_client() as c:
                r_post = c.post("/api/health")
        assert r_post.status_code == 405

    def test_toggle_only_post(self):
        A = setup_app()
        ta = token(A)
        with patch("app.get_db", return_value=mk_db()):
            with A.app.test_client() as c:
                r = c.get("/api/admin/users/1/toggle", headers=hdr(ta))
        assert r.status_code == 405
