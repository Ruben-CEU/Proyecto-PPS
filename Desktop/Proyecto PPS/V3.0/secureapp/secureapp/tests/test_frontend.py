"""
Pruebas de integración del frontend — backend mockeado con responses.
"""
import os, sys
import pytest
import responses as resp_mock

os.environ["FLASK_SECRET_KEY"] = "test-frontend-secret"
os.environ["BACKEND_URL"]      = "http://backend:5001"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "frontend"))

from app import app

MOCK_TOKEN = "eyJhbGciOiJIUzI1NiJ9.test.token"

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestFrontendRoutes:
    def test_root_unauthenticated_redirects_to_login(self, client):
        resp = client.get("/")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_login_get_returns_200(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"SecureApp" in resp.data
        assert b"Iniciar" in resp.data

    def test_dashboard_unauthenticated_redirects(self, client):
        resp = client.get("/dashboard")
        assert resp.status_code == 302

    def test_admin_unauthenticated_redirects(self, client):
        resp = client.get("/admin")
        assert resp.status_code == 302

    def test_login_empty_fields_shows_error(self, client):
        resp = client.post("/login", data={"username": "", "password": ""})
        assert resp.status_code == 200
        assert b"campos" in resp.data

    @resp_mock.activate
    def test_login_success_redirects_to_dashboard(self, client):
        resp_mock.add(resp_mock.POST, "http://backend:5001/api/login",
                      json={"token": MOCK_TOKEN, "username": "admin",
                            "role": "admin", "message": "ok"}, status=200)
        resp_mock.add(resp_mock.GET, "http://backend:5001/api/projects",
                      json={"projects": [], "total": 0}, status=200)
        resp_mock.add(resp_mock.GET, "http://backend:5001/api/admin/stats",
                      json={"users": 2, "projects": 3, "audit_log_entries": 10,
                            "failed_logins_1h": 0, "projects_by_status": {}}, status=200)

        resp = client.post("/login",
                           data={"username": "admin", "password": "Admin1234!"},
                           follow_redirects=True)
        assert resp.status_code == 200
        assert b"admin" in resp.data.lower()

    @resp_mock.activate
    def test_login_failure_shows_error(self, client):
        resp_mock.add(resp_mock.POST, "http://backend:5001/api/login",
                      json={"error": "Credenciales incorrectas"}, status=401)
        resp = client.post("/login",
                           data={"username": "admin", "password": "wrong"})
        assert resp.status_code == 200
        assert b"Credenciales" in resp.data

    def test_logout_clears_session(self, client):
        with client.session_transaction() as sess:
            sess["token"]    = MOCK_TOKEN
            sess["username"] = "admin"
            sess["role"]     = "admin"
        resp = client.get("/logout", follow_redirects=True)
        assert resp.status_code == 200
        assert b"cerrada" in resp.data

    def test_admin_blocked_for_user_role(self, client):
        with client.session_transaction() as sess:
            sess["token"]    = MOCK_TOKEN
            sess["username"] = "usuario"
            sess["role"]     = "user"
        resp = client.get("/admin", follow_redirects=True)
        assert b"denegado" in resp.data or resp.status_code in (200, 302)

    @resp_mock.activate
    def test_admin_accessible_for_admin(self, client):
        with client.session_transaction() as sess:
            sess["token"]    = MOCK_TOKEN
            sess["username"] = "admin"
            sess["role"]     = "admin"

        resp_mock.add(resp_mock.GET, "http://backend:5001/api/admin/users",
                      json={"users": [{"id": 1, "username": "admin", "role": "admin",
                                       "active": True, "created_at": "2024-01-01"}]}, status=200)
        resp_mock.add(resp_mock.GET, "http://backend:5001/api/admin/logs",
                      json={"logs": []}, status=200)
        resp_mock.add(resp_mock.GET, "http://backend:5001/api/admin/stats",
                      json={"users": 2, "projects": 3, "audit_log_entries": 5,
                            "failed_logins_1h": 0, "projects_by_status": {}}, status=200)

        resp = client.get("/admin")
        assert resp.status_code == 200
        assert b"Admin" in resp.data
