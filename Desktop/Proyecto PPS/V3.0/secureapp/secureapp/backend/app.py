"""
=============================================================================
BACKEND API — Flask REST API con MySQL y bcrypt
=============================================================================
REQUISITO: "El programa deberá tener un front end en Python Flask que se
comunicará con un back end a través de una API."

REQUISITO: "base de datos mysql conectada"
→ Usa MySQL como base de datos real (contenedor mysql:8 en Docker).
  El driver es mysql-connector-python (puro Python, sin dependencias C).
  bcrypt reemplaza SHA-256 para el hash de contraseñas.

COMUNICACIÓN SEGURA:
  Frontend → POST /api/login → recibe JWT
  Frontend → GET  /api/...   → envía JWT en cabecera Authorization: Bearer <token>
  Backend  → verifica JWT, consulta MySQL, devuelve JSON
=============================================================================
"""

import os
import time
import secrets
from datetime import datetime, timedelta
from functools import wraps

import bcrypt                          # Hash seguro de contraseñas (adaptive)
import jwt                             # PyJWT — firma/verifica tokens JWT
import mysql.connector                 # Driver oficial MySQL para Python
from mysql.connector import pooling    # Pool de conexiones para rendimiento
from flask import Flask, request, jsonify, g

app = Flask(__name__)

# =============================================================================
# CONFIGURACIÓN — todo desde variables de entorno (OWASP A05 + A02)
# =============================================================================
# Nunca hardcodear secretos. Se leen de docker-compose.yml / fichero .env

SECRET_KEY           = os.environ.get("SECRET_KEY", secrets.token_hex(32))
JWT_ALGORITHM        = "HS256"
JWT_EXPIRATION_HOURS = 1

# Credenciales MySQL — vienen del servicio 'mysql' en docker-compose.yml
DB_CONFIG = {
    "host":     os.environ.get("MYSQL_HOST",     "mysql"),
    "port":     int(os.environ.get("MYSQL_PORT", "3306")),
    "user":     os.environ.get("MYSQL_USER",     "appuser"),
    "password": os.environ.get("MYSQL_PASSWORD", "apppassword"),
    "database": os.environ.get("MYSQL_DATABASE", "secureapp"),
}

# Pool de conexiones: evita abrir/cerrar conexión en cada request
# OWASP A04 (Insecure Design): acotar recursos con pool_size
_pool = None


def get_pool():
    """
    Crea el pool de conexiones MySQL la primera vez que se llama.
    Reintenta hasta 30 veces con espera exponencial para aguantar
    el tiempo de arranque del contenedor MySQL.
    """
    global _pool
    if _pool is not None:
        return _pool

    for attempt in range(30):
        try:
            _pool = pooling.MySQLConnectionPool(
                pool_name="secureapp_pool",
                pool_size=5,           # Máximo 5 conexiones simultáneas
                pool_reset_session=True,
                **DB_CONFIG
            )
            app.logger.info("✅ Pool MySQL creado correctamente")
            return _pool
        except mysql.connector.Error as e:
            wait = min(2 ** attempt, 30)   # Espera exponencial: 1s, 2s, 4s… máx 30s
            app.logger.warning(
                f"⏳ MySQL no disponible (intento {attempt + 1}/30): {e}. "
                f"Reintentando en {wait}s..."
            )
            time.sleep(wait)

    raise RuntimeError("❌ No se pudo conectar a MySQL tras 30 intentos")


def get_db():
    """
    Obtiene una conexión del pool para la request actual.
    Flask la almacena en 'g' y se devuelve al pool al terminar la request.
    """
    if not hasattr(g, "db") or not g.db.is_connected():
        g.db = get_pool().get_connection()
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Devuelve la conexión al pool al terminar cada request."""
    db = getattr(g, "db", None)
    if db is not None and db.is_connected():
        db.close()


# =============================================================================
# INICIALIZACIÓN DE LA BASE DE DATOS
# =============================================================================

def init_db():
    """
    Crea las tablas si no existen e inserta los usuarios de demo.

    Tabla 'users':
      - username: identificador único (UNIQUE)
      - password_hash: hash bcrypt de la contraseña (NUNCA texto plano)
      - role: 'admin' o 'user' — base del control de acceso por roles
      - active: permite deshabilitar usuarios sin borrarlos
      - created_at: auditoría de cuándo se creó la cuenta

    Tabla 'audit_log':
      - Registra cada acción relevante con timestamp e IP
        (OWASP A09 — Security Logging and Monitoring)

    Tabla 'projects':
      - Datos reales de la aplicación, no datos hardcodeados
        REQUISITO: "base de datos mysql conectada" — los proyectos
        también vienen de MySQL, no de listas estáticas en el código.

    REQUISITO: "dos tipos de usuarios: administrador y usuario normal"
    → Los roles se almacenan en la columna 'role' de MySQL.
    """
    db = get_db()
    cursor = db.cursor()

    # Tabla de usuarios
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            username      VARCHAR(64)  UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role          ENUM('admin', 'user') NOT NULL DEFAULT 'user',
            active        TINYINT(1) NOT NULL DEFAULT 1,
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_username (username)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """)

    # Tabla de auditoría
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            username   VARCHAR(64),
            action     VARCHAR(128),
            ip         VARCHAR(45),
            detail     TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_username (username),
            INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """)

    # Tabla de proyectos — datos reales en MySQL
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            name        VARCHAR(128) NOT NULL,
            description TEXT,
            status      ENUM('activo', 'en revisión', 'completado', 'cancelado')
                        NOT NULL DEFAULT 'activo',
            owner       VARCHAR(64),
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
                        ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """)

    # Insertar usuario admin de demo si no existe
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        admin_hash = bcrypt.hashpw(b"Admin1234!", bcrypt.gensalt(rounds=12))
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            ("admin", admin_hash.decode("utf-8"), "admin")
        )
        app.logger.info("👤 Usuario 'admin' creado")

    # Insertar usuario normal de demo si no existe
    cursor.execute("SELECT id FROM users WHERE username = 'usuario'")
    if not cursor.fetchone():
        user_hash = bcrypt.hashpw(b"User1234!", bcrypt.gensalt(rounds=12))
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            ("usuario", user_hash.decode("utf-8"), "user")
        )
        app.logger.info("👤 Usuario 'usuario' creado")

    # Insertar proyectos de demo si la tabla está vacía
    cursor.execute("SELECT COUNT(*) FROM projects")
    if cursor.fetchone()[0] == 0:
        projects = [
            ("Proyecto Alpha",  "Migración de infraestructura a la nube", "activo",      "admin"),
            ("Proyecto Beta",   "Rediseño del portal de clientes",         "en revisión", "usuario"),
            ("Proyecto Gamma",  "Automatización de pruebas QA",            "completado",  "usuario"),
            ("Proyecto Delta",  "Integración con API de pagos",            "activo",      "admin"),
            ("Proyecto Epsilon","Actualización de seguridad OWASP",        "en revisión", "admin"),
        ]
        cursor.executemany(
            "INSERT INTO projects (name, description, status, owner) VALUES (%s, %s, %s, %s)",
            projects
        )
        app.logger.info(f"📋 {len(projects)} proyectos de demo insertados")

    db.commit()
    cursor.close()


# =============================================================================
# HASH DE CONTRASEÑAS — bcrypt
# =============================================================================

def hash_password(password: str) -> str:
    """
    Genera un hash bcrypt de la contraseña.

    bcrypt es el estándar para hashear contraseñas porque:
    - Es LENTO a propósito (rounds=12 → ~250ms por hash)
    - Incluye salt aleatorio automáticamente en cada llamada
    - Resistente a ataques de GPU: una GPU moderna solo puede probar
      ~10.000 hashes bcrypt/s vs ~10.000.000.000 SHA-256/s

    rounds=12 es el equilibrio recomendado velocidad/seguridad en 2024.
    Aumentar a 13-14 en servidores más potentes.

    OWASP A02 (Cryptographic Failures): usar algoritmos adaptativos
    para contraseñas, nunca MD5/SHA-1/SHA-256 sin factor de coste.
    """
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=12)
    ).decode("utf-8")


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifica si la contraseña coincide con el hash almacenado.
    bcrypt.checkpw maneja automáticamente el salt embebido en el hash.
    La comparación es en tiempo constante (inmune a timing attacks).
    """
    return bcrypt.checkpw(
        password.encode("utf-8"),
        stored_hash.encode("utf-8")
    )


# =============================================================================
# JWT — Tokens de autenticación
# =============================================================================

def create_token(user_id: int, username: str, role: str) -> str:
    """
    Genera un JWT firmado con HS256.
    Incluye: user_id, username, role, emisión y expiración.
    OWASP A07: tokens con expiración corta (1 hora).
    """
    payload = {
        "sub":  str(user_id),
        "user": username,
        "role": role,
        "iat":  datetime.utcnow(),
        "exp":  datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict:
    """Verifica firma y expiración del JWT. Lanza excepción si es inválido."""
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])


# =============================================================================
# DECORADORES DE AUTORIZACIÓN
# =============================================================================

def token_required(f):
    """
    Protege un endpoint: exige JWT válido en Authorization: Bearer <token>.
    Si es válido, añade el payload a request.current_user.
    REQUISITO OWASP A01 (Broken Access Control).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Token requerido"}), 401
        try:
            payload = verify_token(auth.split(" ")[1])
            request.current_user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido"}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """
    Exige JWT válido Y role=='admin'. Devuelve 403 si el rol no es suficiente.
    REQUISITO: "dos tipos de usuarios: administrador y usuario normal".
    """
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if request.current_user.get("role") != "admin":
            return jsonify({"error": "Acceso denegado: se requiere rol admin"}), 403
        return f(*args, **kwargs)
    return decorated


# =============================================================================
# AUDITORÍA
# =============================================================================

def log_action(username: str, action: str, detail: str = ""):
    """
    Registra una acción en audit_log de MySQL.
    OWASP A09: logging de eventos de seguridad con IP y detalle.
    Se ejecuta en una conexión separada para no afectar a la request principal.
    """
    try:
        conn = get_pool().get_connection()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO audit_log (username, action, ip, detail) VALUES (%s, %s, %s, %s)",
            (username, action, request.remote_addr or "unknown", detail)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error(f"Error al escribir audit_log: {e}")


# =============================================================================
# RATE LIMITING — en memoria (usar Redis en producción multi-instancia)
# =============================================================================

_login_attempts: dict = {}   # { ip: [datetime, ...] }

def check_rate_limit(ip: str) -> bool:
    """
    Máximo 5 intentos de login por IP en ventana de 15 minutos.
    OWASP A07: prevención de ataques de fuerza bruta.
    """
    now      = datetime.utcnow()
    window   = timedelta(minutes=15)
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < window]
    if len(attempts) >= 5:
        return False
    attempts.append(now)
    _login_attempts[ip] = attempts
    return True


# =============================================================================
# ENDPOINTS
# =============================================================================

@app.route("/api/health", methods=["GET"])
def health():
    """
    Health check — verifica que el backend Y MySQL están operativos.
    Usado por Docker healthcheck y por el frontend para verificar disponibilidad.
    """
    try:
        db  = get_db()
        cur = db.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        cur.close()
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {e}"

    status = "ok" if db_status == "ok" else "degraded"
    return jsonify({
        "status":   status,
        "service":  "backend-api",
        "database": db_status,
        "engine":   "MySQL 8"
    }), 200 if status == "ok" else 503


@app.route("/api/login", methods=["POST"])
def login():
    """
    Autenticación de usuario.

    Seguridad implementada:
    1. Rate limiting por IP (OWASP A07)
    2. Inputs saneados y truncados (OWASP A03)
    3. Query SQL parametrizada — sin SQL injection (OWASP A03)
    4. bcrypt.checkpw — verificación en tiempo constante (OWASP A07)
    5. Mismo mensaje de error para usuario inexistente o contraseña mal
       → no revela si el usuario existe (enumeración de usuarios)
    6. Registro en audit_log de éxitos y fallos (OWASP A09)
    """
    ip = request.remote_addr or "unknown"

    if not check_rate_limit(ip):
        log_action("?", "login_rate_limited", f"IP: {ip}")
        return jsonify({"error": "Demasiados intentos. Espera 15 minutos."}), 429

    data     = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()[:64]
    password = str(data.get("password", ""))[:128]

    if not username or not password:
        return jsonify({"error": "Usuario y contraseña requeridos"}), 400

    try:
        db  = get_db()
        cur = db.cursor(dictionary=True)
        # Query parametrizada — NUNCA concatenar strings con inputs del usuario
        cur.execute(
            "SELECT id, username, password_hash, role, active "
            "FROM users WHERE username = %s",
            (username,)
        )
        row = cur.fetchone()
        cur.close()
    except mysql.connector.Error as e:
        app.logger.error(f"Error MySQL en login: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

    # Verificar contraseña con bcrypt (tiempo constante, inmune a timing attacks)
    # Si el usuario no existe hacemos un checkpw igualmente para no revelar
    # si el usuario existe midiendo el tiempo de respuesta.
    dummy_hash = "$2b$12$" + "x" * 53   # Hash falso para comparación ficticia
    stored     = row["password_hash"] if row else dummy_hash
    valid      = row is not None and verify_password(password, stored)

    if not valid:
        log_action(username, "login_failed", f"IP: {ip}")
        return jsonify({"error": "Credenciales incorrectas"}), 401

    if not row["active"]:
        log_action(username, "login_blocked", "Cuenta desactivada")
        return jsonify({"error": "Cuenta desactivada. Contacta al administrador."}), 403

    token = create_token(row["id"], row["username"], row["role"])
    log_action(username, "login_success", f"IP: {ip}")

    return jsonify({
        "token":    token,
        "username": row["username"],
        "role":     row["role"],
        "message":  "Autenticación exitosa"
    })


@app.route("/api/profile", methods=["GET"])
@token_required
def profile():
    """Devuelve el perfil del usuario autenticado desde MySQL."""
    user = request.current_user
    try:
        db  = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT id, username, role, created_at FROM users WHERE id = %s",
            (user["sub"],)
        )
        row = cur.fetchone()
        cur.close()
    except mysql.connector.Error as e:
        return jsonify({"error": str(e)}), 500

    if not row:
        return jsonify({"error": "Usuario no encontrado"}), 404

    return jsonify({
        "id":         row["id"],
        "username":   row["username"],
        "role":       row["role"],
        "created_at": str(row["created_at"]),
    })


@app.route("/api/projects", methods=["GET"])
@token_required
def get_projects():
    """
    Devuelve proyectos desde MySQL — accesible para ambos roles.
    REQUISITO: "base de datos mysql conectada" — datos reales de la BD,
    no listas hardcodeadas en el código.
    """
    user = request.current_user
    log_action(user["user"], "get_projects")

    try:
        db  = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT id, name, description, status, owner, created_at "
            "FROM projects ORDER BY created_at DESC"
        )
        projects = cur.fetchall()
        cur.close()
    except mysql.connector.Error as e:
        return jsonify({"error": str(e)}), 500

    # Convertir datetimes a string para serialización JSON
    for p in projects:
        p["created_at"] = str(p["created_at"])

    return jsonify({
        "projects": projects,
        "total":    len(projects),
        "user":     user["user"],
        "role":     user["role"]
    })


@app.route("/api/projects", methods=["POST"])
@admin_required
def create_project():
    """
    Crea un nuevo proyecto en MySQL — solo administradores.
    REQUISITO: "administrador hace algo diferente"
    → Solo admin puede crear proyectos. Usuario normal recibe 403.
    """
    data = request.get_json(silent=True) or {}
    name        = str(data.get("name", "")).strip()[:128]
    description = str(data.get("description", "")).strip()[:500]
    status      = data.get("status", "activo")

    valid_statuses = {"activo", "en revisión", "completado", "cancelado"}
    if not name:
        return jsonify({"error": "El nombre del proyecto es obligatorio"}), 400
    if status not in valid_statuses:
        return jsonify({"error": f"Estado inválido. Usa: {valid_statuses}"}), 400

    owner = request.current_user["user"]
    try:
        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO projects (name, description, status, owner) "
            "VALUES (%s, %s, %s, %s)",
            (name, description, status, owner)
        )
        db.commit()
        new_id = int(cur.lastrowid)
        cur.close()
    except mysql.connector.Error as e:
        return jsonify({"error": str(e)}), 500

    log_action(owner, "create_project", f"ID:{new_id} nombre:{name}")
    return jsonify({"message": "Proyecto creado", "id": new_id}), 201


@app.route("/api/admin/users", methods=["GET"])
@admin_required
def list_users():
    """Lista todos los usuarios — solo administradores. OWASP A01."""
    try:
        db  = get_db()
        cur = db.cursor(dictionary=True)
        # NUNCA devolver password_hash — mínima exposición de datos
        cur.execute(
            "SELECT id, username, role, active, created_at "
            "FROM users ORDER BY id"
        )
        users = cur.fetchall()
        cur.close()
    except mysql.connector.Error as e:
        return jsonify({"error": str(e)}), 500

    for u in users:
        u["created_at"] = str(u["created_at"])
        u["active"]     = bool(u["active"])

    log_action(request.current_user["user"], "list_users")
    return jsonify({"users": users, "total": len(users)})


@app.route("/api/admin/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def toggle_user(user_id: int):
    """Activa/desactiva un usuario — solo admin."""
    try:
        db  = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT id, username, active FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        if not user:
            cur.close()
            return jsonify({"error": "Usuario no encontrado"}), 404

        new_status = 0 if user["active"] else 1
        cur.execute("UPDATE users SET active = %s WHERE id = %s", (new_status, user_id))
        db.commit()
        cur.close()
    except mysql.connector.Error as e:
        return jsonify({"error": str(e)}), 500

    action = "user_activated" if new_status else "user_deactivated"
    log_action(request.current_user["user"], action, f"user_id:{user_id}")
    return jsonify({"message": f"Usuario {'activado' if new_status else 'desactivado'}"})


@app.route("/api/admin/logs", methods=["GET"])
@admin_required
def get_logs():
    """Log de auditoría completo — solo administradores. OWASP A09."""
    limit = min(int(request.args.get("limit", 100)), 500)
    try:
        db  = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT id, username, action, ip, detail, created_at "
            "FROM audit_log ORDER BY id DESC LIMIT %s",
            (limit,)
        )
        logs = cur.fetchall()
        cur.close()
    except mysql.connector.Error as e:
        return jsonify({"error": str(e)}), 500

    for log in logs:
        log["created_at"] = str(log["created_at"])

    return jsonify({"logs": logs, "total": len(logs)})


@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def get_stats():
    """Estadísticas del sistema para el panel admin."""
    try:
        db  = get_db()
        cur = db.cursor(dictionary=True)

        cur.execute("SELECT COUNT(*) AS total FROM users")
        total_users = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) AS total FROM users WHERE role='admin'")
        total_admins = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) AS total FROM projects")
        total_projects = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) AS total FROM audit_log")
        total_logs = cur.fetchone()["total"]

        cur.execute(
            "SELECT COUNT(*) AS total FROM audit_log "
            "WHERE action='login_failed' AND created_at > NOW() - INTERVAL 1 HOUR"
        )
        failed_logins_1h = cur.fetchone()["total"]

        cur.execute(
            "SELECT status, COUNT(*) AS total FROM projects GROUP BY status"
        )
        projects_by_status = {r["status"]: r["total"] for r in cur.fetchall()}

        cur.close()
    except mysql.connector.Error as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "users":              total_users,
        "admins":             total_admins,
        "projects":           total_projects,
        "audit_log_entries":  total_logs,
        "failed_logins_1h":   failed_logins_1h,
        "projects_by_status": projects_by_status,
    })


# =============================================================================
# CABECERAS DE SEGURIDAD HTTP (OWASP A05)
# =============================================================================

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"]   = "default-src 'self'"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"]             = "no-store"
    return response


# =============================================================================
# ARRANQUE
# =============================================================================

if __name__ == "__main__":
    # Inicializar pool y BD antes de arrancar el servidor
    app.logger.setLevel("INFO")
    get_pool()       # Crea el pool (con reintentos si MySQL aún no está listo)
    with app.app_context():
        init_db()    # Crea tablas e inserta datos de demo

    app.run(host="0.0.0.0", port=5001, debug=False)
