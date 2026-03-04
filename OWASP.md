# OWASP Top 10 — 2025 🔐

**Análisis de Seguridad — SecureApp**

> Aplicación Web y API · Versión 2.0 · Marzo 2026

---

## Introducción

Este documento analiza la implementación del OWASP Top 10 2025 en SecureApp, cubriendo tanto la perspectiva de aplicación web como la de APIs. Para cada categoría se describe el riesgo, las medidas implementadas y el fichero exacto donde verificarlo.

**Estado general: todos los puntos del Top 10 están cubiertos.**

| # | Categoría | Estado |
|---|-----------|--------|
| A01 | Broken Access Control | ✅ Cubierto |
| A02 | Cryptographic Failures | ✅ Cubierto |
| A03 | Injection | ✅ Cubierto |
| A04 | Insecure Design | ✅ Cubierto |
| A05 | Security Misconfiguration | ✅ Cubierto |
| A06 | Vulnerable and Outdated Components | ✅ Cubierto |
| A07 | Identification and Authentication Failures | ✅ Cubierto |
| A08 | Software and Data Integrity Failures | ✅ Cubierto |
| A09 | Security Logging and Monitoring Failures | ✅ Cubierto |
| A10 | Server-Side Request Forgery (SSRF) | ✅ Cubierto |

---

## A01:2025 — Broken Access Control

### Descripción del riesgo
El control de acceso fuerza políticas para que los usuarios no puedan actuar fuera de sus permisos. Las vulnerabilidades llevan a acceso no autorizado a datos o funcionalidades.

### Medidas implementadas

**Fichero:** `backend/app.py` — funciones `token_required` y `admin_required`

- `@token_required`: verifica JWT válido en cada endpoint protegido. Sin token o token inválido → 401.
- `@admin_required`: verifica JWT válido Y `role == 'admin'`. Usuario normal en ruta admin → 403.
- **Doble verificación:** el frontend comprueba `session['role']` antes de llamar al backend. El backend verifica el rol del JWT independientemente.
- Columna `active` en tabla `users`: permite desactivar usuarios sin borrarlos.
- Endpoint `POST /api/projects` exclusivo de admin. Usuario normal obtiene 403 aunque tenga JWT válido.

```python
# backend/app.py
def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if request.current_user.get("role") != "admin":
            return jsonify({"error": "Acceso denegado"}), 403
        return f(*args, **kwargs)
    return decorated
```

### Tests que verifican esto
- `test_admin_users_blocked_for_user` → user token devuelve 403
- `test_admin_users_accessible_for_admin` → admin token devuelve 200
- `test_create_project_user_forbidden` → user en POST /api/projects → 403

---

## A02:2025 — Cryptographic Failures

### Descripción del riesgo
Fallos en criptografía o su ausencia exponen datos sensibles. Incluye contraseñas mal protegidas, algoritmos débiles y secretos hardcodeados.

### Medidas implementadas

**Fichero:** `backend/app.py` — funciones `hash_password`, `create_token`

- **bcrypt con rounds=12**: genera ~250ms por hash. GPU brute-force inviable. (SHA-256 sin coste: ~10B hash/s; bcrypt rounds=12: ~10K hash/s)
- Salt aleatorio automático en cada `bcrypt.hashpw`. Dos hashes del mismo texto son distintos.
- La columna `password_hash` de MySQL nunca contiene la contraseña en texto plano.
- Los endpoints admin nunca devuelven `password_hash` en las respuestas JSON.
- JWT con algoritmo HS256. Token expira en 1 hora.
- `SECRET_KEY` de 32 bytes aleatorios con `secrets.token_hex(32)` si no se define en entorno.
- Secretos en variables de entorno. `.env` está en `.gitignore`.

```python
# backend/app.py
def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=12)   # salt aleatorio, factor de coste 12
    ).decode("utf-8")

SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))  # nunca hardcodeado
```

### Tests que verifican esto
- `TestBcrypt.test_hash_is_not_plaintext`
- `TestBcrypt.test_two_hashes_of_same_password_differ`
- `TestBcrypt.test_verify_correct_password` / `test_verify_wrong_password`

---

## A03:2025 — Injection

### Descripción del riesgo
SQL Injection ocurre cuando datos no confiables se envían a un intérprete como parte de un comando o consulta.

### Medidas implementadas

**Fichero:** `backend/app.py` — todas las funciones con `get_db`

- **Nunca** se construye SQL concatenando strings. Se usa siempre `%s` como placeholder.
- `mysql-connector-python` gestiona el escape automáticamente.
- Inputs del usuario truncados antes de usarse (`username[:64]`, `password[:128]`).
- Jinja2 aplica auto-escaping en todos los templates HTML. `{{ variable }}` escapa caracteres peligrosos.
- `Content-Security-Policy: default-src 'self'` impide cargar scripts de orígenes externos.

```python
# backend/app.py — CORRECTO: query parametrizada
cursor.execute(
    "SELECT id, username, password_hash, role, active "
    "FROM users WHERE username = %s",
    (username,)   # parámetro separado, nunca en el string SQL
)

# INCORRECTO (nunca se hace):
# cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")  # VULNERABLE
```

---

## A04:2025 — Insecure Design

### Descripción del riesgo
Riesgos relacionados con fallos de diseño: arquitectura insegura, falta de modelos de amenazas, patrones inseguros.

### Medidas implementadas

**Fichero:** `docker-compose.yml`

- **Red Docker segregada:** Backend NO expuesto al exterior. MySQL NO expuesto al exterior.
- Solo el frontend (puerto 5000) es accesible desde el host.
- Pool de conexiones MySQL con `pool_size=5`. Previene agotamiento de conexiones.
- `timeout=8s` en llamadas HTTP del frontend al backend.
- Inputs truncados: `username` máx 64 chars, `password` máx 128 chars.
- El frontend no tiene acceso directo a MySQL. Toda operación pasa por la API del backend.

```yaml
# docker-compose.yml
backend:
  expose:
    - "5001"   # solo visible dentro de la red Docker appnet

frontend:
  ports:
    - "5000:5000"   # único puerto expuesto al exterior
```

---

## A05:2025 — Security Misconfiguration

### Descripción del riesgo
Configuraciones de seguridad incorrectas, permisos excesivos, funcionalidades innecesarias habilitadas.

### Medidas implementadas

**Fichero:** `backend/app.py` y `frontend/app.py` — decorador `@after_request`

7 cabeceras HTTP de seguridad en todas las respuestas:

| Cabecera | Valor | Protección |
|----------|-------|-----------|
| `X-Content-Type-Options` | `nosniff` | Previene MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Previene clickjacking |
| `X-XSS-Protection` | `1; mode=block` | Filtro XSS del navegador |
| `Strict-Transport-Security` | `max-age=31536000` | Fuerza HTTPS 1 año |
| `Content-Security-Policy` | `default-src 'self'` | Solo recursos del mismo origen |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controla Referer |
| `Cache-Control` | `no-store` | No cachear respuestas sensibles |

- `debug=False` en producción.
- Contenedores corren como usuario `appuser` (no root).
- Imagen base `python:3.12-slim` — mínima superficie de ataque.

```python
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"]   = "default-src \'self\'"
    response.headers["Cache-Control"]             = "no-store"
    return response
```

### Tests que verifican esto
- `TestSecurityHeaders` — 8 tests verificando cada cabecera

---

## A06:2025 — Vulnerable and Outdated Components

### Descripción del riesgo
Uso de componentes con vulnerabilidades conocidas, versiones antiguas sin parches.

### Medidas implementadas

**Ficheros:** `backend/requirements.txt`, `frontend/requirements.txt`

- `flask==3.0.3` — última versión estable
- `pyjwt==2.8.0` — con correcciones de seguridad recientes
- `bcrypt==4.1.3` — librería activamente mantenida por pyca
- `mysql-connector-python==8.4.0` — driver oficial Oracle
- `requests==2.32.3` — con fix para CVEs anteriores
- Imágenes Docker: `mysql:8.0` y `python:3.12-slim` oficiales
- **Bandit** ejecutado en cada push (job `security` en CI/CD)

---

## A07:2025 — Identification and Authentication Failures

### Descripción del riesgo
Vulnerabilidades en autenticación: contraseñas débiles, sesiones mal gestionadas, falta de protección contra fuerza bruta.

### Medidas implementadas

**Fichero:** `backend/app.py` — función `check_rate_limit`, `create_token`; `frontend/app.py` — configuración `SESSION_COOKIE`

- **Rate limiting:** máximo 5 intentos de login por IP en ventana de 15 minutos. El 6º recibe HTTP 429.
- **JWT con expiración:** los tokens expiran en 1 hora (campo `exp`).
- **Sesiones seguras:**
  - `SESSION_COOKIE_HTTPONLY=True` → JavaScript no puede leer la cookie (mitiga XSS)
  - `SESSION_COOKIE_SAMESITE='Lax'` → no se envía en requests cross-site (mitiga CSRF)
  - `SESSION_COOKIE_SECURE=True` cuando HTTPS en producción
- **Protección contra timing attacks:** si el usuario no existe, se realiza igualmente `bcrypt.checkpw` con hash ficticio. El tiempo de respuesta es idéntico tanto si el usuario existe como si no.
- Mismo mensaje de error para usuario inexistente Y contraseña errónea.

```python
# Timing attack protection
dummy_hash = "$2b$12$" + "x" * 53
stored = row["password_hash"] if row else dummy_hash
valid  = row is not None and verify_password(password, stored)
# tiempo ~250ms siempre, independientemente de si el usuario existe
```

### Tests que verifican esto
- `TestRateLimit` — 5 tests
- `test_login_rate_limited` → 6º intento recibe 429
- `test_login_nonexistent_user` → devuelve 401 (no 404)

---

## A08:2025 — Software and Data Integrity Failures

### Descripción del riesgo
Código y datos no protegidos contra modificaciones. Deserialización insegura, CI/CD sin validación, dependencias de fuentes no confiables.

### Medidas implementadas

- Imágenes Docker `mysql:8.0` y `python:3.12-slim` son imágenes oficiales con checksums verificados.
- No se usa JavaScript, CSS ni fuentes desde CDNs externos en los templates.
- `Content-Security-Policy: default-src 'self'` bloquea cualquier recurso externo.
- Cada merge a `main` debe pasar los jobs `test + security + docker build`.
- Bandit analiza el código antes del build.
- El payload del JWT está firmado con HS256. Cualquier modificación invalida la firma.

---

## A09:2025 — Security Logging and Monitoring Failures

### Descripción del riesgo
Sin logging adecuado, las brechas no se detectan. Incluye no registrar logins fallidos, no alertar sobre actividad sospechosa.

### Medidas implementadas

**Fichero:** `backend/app.py` — función `log_action`, tabla `audit_log`

- Registra: `username`, `action`, `ip`, `detail`, `created_at` en cada evento relevante.
- Acciones registradas: `login_success`, `login_failed`, `login_blocked`, `get_projects`, `list_users`, `create_project`, `user_activated`, `user_deactivated`.
- La IP de origen se registra en cada acción.
- Los logs persisten en MySQL (volumen Docker).
- El administrador ve los últimos 100 eventos en tiempo real desde la UI.
- El dashboard admin muestra **"fallos de login en la última hora"** con alerta visual si supera 3.

```python
def log_action(username: str, action: str, detail: str = ""):
    conn = get_pool().get_connection()
    cur  = conn.cursor()
    cur.execute(
        "INSERT INTO audit_log (username, action, ip, detail) VALUES (%s,%s,%s,%s)",
        (username, action, request.remote_addr, detail)
    )
    conn.commit()
```

---

## A10:2025 — Server-Side Request Forgery (SSRF)

### Descripción del riesgo
SSRF ocurre cuando la aplicación hace peticiones HTTP a una URL suministrada por el usuario, permitiendo acceder a servicios internos.

### Medidas implementadas

**Fichero:** `frontend/app.py` — constante `BACKEND_URL`

- `BACKEND_URL` fija en variable de entorno. El frontend **nunca** acepta una URL del usuario.
- Todas las llamadas al backend usan `call_backend()` con la URL fija.
- No existe ningún endpoint que acepte una URL como parámetro.
- La red Docker actúa como barrera adicional.

```python
# frontend/app.py
BACKEND_URL = os.environ.get("BACKEND_URL", "http://backend:5001")

def call_backend(method: str, path: str, **kwargs):
    # path viene del código, nunca del usuario
    url = f"{BACKEND_URL}{path}"
    return getattr(requests, method)(url, timeout=8, **kwargs)
```

---

## Referencias

- [OWASP Top 10 2021 Web](https://owasp.org/Top10/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/)
- [OWASP Cheat Sheet — Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Cheat Sheet — JWT](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP Cheat Sheet — SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
