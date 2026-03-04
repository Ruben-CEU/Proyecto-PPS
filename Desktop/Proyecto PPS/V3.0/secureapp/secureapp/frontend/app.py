"""
=============================================================================
FRONTEND — Flask Web App
=============================================================================
Se comunica con el backend (Flask API + MySQL) mediante HTTP + JWT.
Renderiza la UI diferenciada por rol (admin → morado, user → azul).
=============================================================================
"""

import os
import requests
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)

app = Flask(__name__)

# Configuración segura de sesiones (OWASP A07)
app.secret_key                         = os.environ.get("FLASK_SECRET_KEY", "change_in_prod")
app.config["SESSION_COOKIE_HTTPONLY"]  = True      # No accesible por JS → mitiga XSS
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"     # Mitiga CSRF
app.config["SESSION_COOKIE_SECURE"]   = os.environ.get("HTTPS", "false") == "true"

BACKEND_URL = os.environ.get("BACKEND_URL", "http://backend:5001")


# =============================================================================
# UTILIDADES
# =============================================================================

def get_auth_headers():
    """Construye la cabecera JWT para llamadas al backend."""
    token = session.get("token")
    return {"Authorization": f"Bearer {token}"} if token else None


def call_backend(method: str, path: str, **kwargs):
    """
    Wrapper centralizado para llamadas HTTP al backend.
    timeout=8s: generoso para dejar tiempo a bcrypt (~250ms por verify)
    + consultas MySQL. Ajustar según SLA requerido.
    """
    try:
        return getattr(requests, method)(
            f"{BACKEND_URL}{path}", timeout=8, **kwargs
        )
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None


def login_required(f):
    """Decorador para rutas que requieren sesión activa."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "token" not in session:
            flash("Debes iniciar sesión.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def handle_backend_response(resp, session_required=True):
    """
    Maneja respuestas del backend de forma centralizada.
    Devuelve (data, error_response) — si error_response no es None, retornarlo.
    """
    if resp is None:
        return None, (None, "No se pudo conectar con el servidor.")
    if resp.status_code == 401:
        session.clear()
        return None, ("login", "Sesión expirada. Inicia sesión de nuevo.")
    if resp.status_code == 403:
        return None, ("dashboard", "Acceso denegado.")
    if not resp.ok:
        data = resp.json() if resp.content else {}
        return None, (None, data.get("error", "Error del servidor."))
    return resp.json(), None


# =============================================================================
# RUTAS
# =============================================================================

@app.route("/")
def index():
    return redirect(url_for("dashboard") if "token" in session else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "token" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()[:64]
        password = request.form.get("password", "")[:128]

        if not username or not password:
            flash("Por favor completa todos los campos.", "error")
            return render_template("login.html")

        resp = call_backend("post", "/api/login", json={
            "username": username,
            "password": password
        })

        if resp is None:
            flash("No se pudo conectar con el servidor. Inténtalo de nuevo.", "error")
            return render_template("login.html")

        data = resp.json()
        if resp.status_code == 200:
            # Guardar token JWT y datos del usuario en sesión Flask (server-side)
            session["token"]    = data["token"]
            session["username"] = data["username"]
            session["role"]     = data["role"]
            flash(f"Bienvenido, {data['username']}!", "success")
            return redirect(url_for("dashboard"))
        elif resp.status_code == 429:
            flash("Demasiados intentos. Espera 15 minutos.", "error")
        else:
            flash(data.get("error", "Credenciales incorrectas"), "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    """
    Vista principal — accesible para ambos roles.
    Admin: UI morada + estadísticas + acceso al panel.
    User:  UI azul  + solo lista de proyectos.
    """
    headers = get_auth_headers()

    # Obtener proyectos desde MySQL vía backend
    resp = call_backend("get", "/api/projects", headers=headers)

    if resp and resp.status_code == 401:
        session.clear()
        flash("Sesión expirada.", "error")
        return redirect(url_for("login"))

    projects = []
    if resp and resp.ok:
        projects = resp.json().get("projects", [])

    # Si es admin, obtener estadísticas adicionales de MySQL
    stats = None
    if session.get("role") == "admin":
        resp_stats = call_backend("get", "/api/admin/stats", headers=headers)
        if resp_stats and resp_stats.ok:
            stats = resp_stats.json()

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role"),
        projects=projects,
        stats=stats
    )


@app.route("/admin")
@login_required
def admin():
    """Panel de administración — solo para rol admin."""
    if session.get("role") != "admin":
        flash("Acceso denegado. Área exclusiva para administradores.", "error")
        return redirect(url_for("dashboard"))

    headers = get_auth_headers()

    resp_users = call_backend("get", "/api/admin/users",  headers=headers)
    resp_logs  = call_backend("get", "/api/admin/logs",   headers=headers)
    resp_stats = call_backend("get", "/api/admin/stats",  headers=headers)

    users = resp_users.json().get("users", []) if resp_users and resp_users.ok else []
    logs  = resp_logs.json().get("logs",   []) if resp_logs  and resp_logs.ok  else []
    stats = resp_stats.json()               if resp_stats and resp_stats.ok else {}

    return render_template(
        "admin.html",
        username=session.get("username"),
        role=session.get("role"),
        users=users,
        logs=logs,
        stats=stats
    )


@app.route("/admin/toggle-user/<int:user_id>", methods=["POST"])
@login_required
def toggle_user(user_id: int):
    """Activa/desactiva un usuario — solo admin."""
    if session.get("role") != "admin":
        flash("Acceso denegado.", "error")
        return redirect(url_for("dashboard"))

    headers = get_auth_headers()
    resp = call_backend("post", f"/api/admin/users/{user_id}/toggle", headers=headers)

    if resp and resp.ok:
        flash(resp.json().get("message", "Usuario actualizado."), "success")
    else:
        flash("Error al actualizar el usuario.", "error")

    return redirect(url_for("admin"))


@app.route("/admin/new-project", methods=["GET", "POST"])
@login_required
def new_project():
    """Formulario para crear proyectos — solo admin."""
    if session.get("role") != "admin":
        flash("Acceso denegado.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        headers = get_auth_headers()
        resp = call_backend("post", "/api/projects", headers=headers, json={
            "name":        request.form.get("name", "").strip(),
            "description": request.form.get("description", "").strip(),
            "status":      request.form.get("status", "activo"),
        })
        if resp and resp.status_code == 201:
            flash("Proyecto creado correctamente.", "success")
            return redirect(url_for("dashboard"))
        else:
            data = resp.json() if resp and resp.content else {}
            flash(data.get("error", "Error al crear el proyecto."), "error")

    return render_template("new_project.html",
                           username=session.get("username"),
                           role=session.get("role"))




# =============================================================================
# RUTAS PROXY API — Para Postman y clientes externos
# Redirigen las llamadas al backend interno y devuelven JSON directamente
# =============================================================================

from flask import jsonify

@app.route("/api/health")
def proxy_health():
    resp = call_backend("get", "/api/health")
    if resp is None:
        return jsonify({"error": "Backend no disponible"}), 503
    return resp.content, resp.status_code, {"Content-Type": "application/json"}


@app.route("/api/login", methods=["POST"])
def proxy_login():
    resp = call_backend("post", "/api/login",
                        json=request.get_json(),
                        headers={"Content-Type": "application/json"})
    if resp is None:
        return jsonify({"error": "Backend no disponible"}), 503
    return resp.content, resp.status_code, {"Content-Type": "application/json"}


@app.route("/api/profile")
def proxy_profile():
    auth = request.headers.get("Authorization")
    resp = call_backend("get", "/api/profile",
                        headers={"Authorization": auth} if auth else {})
    if resp is None:
        return jsonify({"error": "Backend no disponible"}), 503
    return resp.content, resp.status_code, {"Content-Type": "application/json"}


@app.route("/api/projects", methods=["GET", "POST"])
def proxy_projects():
    auth = request.headers.get("Authorization")
    headers = {"Authorization": auth} if auth else {}
    if request.method == "POST":
        resp = call_backend("post", "/api/projects",
                            json=request.get_json(), headers=headers)
    else:
        resp = call_backend("get", "/api/projects", headers=headers)
    if resp is None:
        return jsonify({"error": "Backend no disponible"}), 503
    return resp.content, resp.status_code, {"Content-Type": "application/json"}


@app.route("/api/admin/users")
def proxy_admin_users():
    auth = request.headers.get("Authorization")
    resp = call_backend("get", "/api/admin/users",
                        headers={"Authorization": auth} if auth else {})
    if resp is None:
        return jsonify({"error": "Backend no disponible"}), 503
    return resp.content, resp.status_code, {"Content-Type": "application/json"}


@app.route("/api/admin/users/<int:user_id>/toggle", methods=["POST"])
def proxy_toggle_user(user_id):
    auth = request.headers.get("Authorization")
    resp = call_backend("post", f"/api/admin/users/{user_id}/toggle",
                        headers={"Authorization": auth} if auth else {})
    if resp is None:
        return jsonify({"error": "Backend no disponible"}), 503
    return resp.content, resp.status_code, {"Content-Type": "application/json"}


@app.route("/api/admin/logs")
def proxy_admin_logs():
    auth = request.headers.get("Authorization")
    resp = call_backend("get", "/api/admin/logs",
                        headers={"Authorization": auth} if auth else {})
    if resp is None:
        return jsonify({"error": "Backend no disponible"}), 503
    return resp.content, resp.status_code, {"Content-Type": "application/json"}


@app.route("/api/admin/stats")
def proxy_admin_stats():
    auth = request.headers.get("Authorization")
    resp = call_backend("get", "/api/admin/stats",
                        headers={"Authorization": auth} if auth else {})
    if resp is None:
        return jsonify({"error": "Backend no disponible"}), 503
    return resp.content, resp.status_code, {"Content-Type": "application/json"}

# =============================================================================
# CABECERAS DE SEGURIDAD
# =============================================================================

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
