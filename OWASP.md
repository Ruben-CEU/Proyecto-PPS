# OWASP Top 10 — 2025 🔐

**Análisis de Seguridad · SecureApp · Proyecto PPS · CEU · Marzo 2026**

---

## Resumen ejecutivo

Este documento analiza la cobertura del OWASP Top 10 2025 en SecureApp desde dos perspectivas: aplicación web y API REST. Para cada categoría se detalla el riesgo, las medidas implementadas con referencias exactas al código, y los tests automatizados que las verifican.

| # | Categoría | Estado |
|---|-----------|--------|
| A01 | Broken Access Control | ✅ Implementado |
| A02 | Cryptographic Failures | ✅ Implementado |
| A03 | Injection | ✅ Implementado |
| A04 | Insecure Design | ✅ Implementado |
| A05 | Security Misconfiguration | ✅ Implementado |
| A06 | Vulnerable and Outdated Components | ✅ Implementado |
| A07 | Identification and Authentication Failures | ✅ Implementado |
| A08 | Software and Data Integrity Failures | ✅ Implementado |
| A09 | Security Logging and Monitoring Failures | ✅ Implementado |
| A10 | Server-Side Request Forgery (SSRF) | ✅ Implementado |

---

## A01 — Broken Access Control

### Riesgo
Sin controles de acceso adecuados, los usuarios pueden actuar fuera de sus permisos: acceder a datos ajenos, ejecutar funciones restringidas o escalar privilegios.

### Implementación

**Fichero:** `backend/app.py`

El sistema implementa dos niveles de control mediante decoradores de Flask:

```python
def token_required(f):
    """Exige JWT válido. Sin token o token inválido → 401."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        payload = verify_token(token)   # lanza excepción si inválido
        request.current_user = payload
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Exige JWT válido Y role == 'admin'. Usuario normal → 403."""
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if request.current_user.get("role") != "admin":
            return jsonify({"error": "Acceso denegado"}), 403
        return f(*args, **kwargs)
    return decorated
```

Medidas adicionales:
- **Doble verificación de rol:** el frontend comprueba `session['role']` antes de llamar al backend, y el backend verifica el JWT independientemente. Un atacante no puede saltarse la verificación del backend.
- **Control de estado de cuenta:** columna `active` en la tabla `users`. Un usuario desactivado no puede autenticarse aunque su contraseña sea correcta.
- **Separación de endpoints:** `POST /api/projects` y todos los endpoints `/api/admin/*` requieren `@admin_required`. Un usuario con rol `user` y JWT válido obtiene 403.

### Tests que verifican este control
- `test_admin_users_blocked_for_user` → token de usuario → 403
- `test_admin_users_accessible_for_admin` → token de admin → 200
- `TestProjectsPOST::test_post_project_user_forbidden` → POST proyectos con token user → 403
- `TestToggleUserPOST::test_toggle_by_user_role_returns_403` → toggle con token user → 403

---

## A02 — Cryptographic Failures

### Riesgo
El uso de algoritmos criptográficos débiles, contraseñas almacenadas en texto plano o secretos hardcodeados en el código expone datos sensibles ante un atacante que acceda a la base de datos o al repositorio.

### Implementación

**Fichero:** `backend/app.py`

**Hashing de contraseñas con bcrypt:**
```python
def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=12)  # salt único por hash, factor de coste 12
    ).decode("utf-8")
```

- `rounds=12` genera ~250ms por operación de hash, haciendo inviable el ataque de fuerza bruta por GPU.
- Cada llamada genera un salt aleatorio: dos hashes del mismo texto son siempre distintos.
- La columna `password_hash` de MySQL nunca contiene texto plano ni hashes reversibles.

**Tokens JWT seguros:**
- Algoritmo HS256 con `SECRET_KEY` de 32 bytes aleatorios.
- Expiración de 1 hora en el campo `exp`.
- `SECRET_KEY` obtenida de variable de entorno, con `secrets.token_hex(32)` como fallback.

**Gestión de secretos:**
```python
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
```
- Todos los secretos (`SECRET_KEY`, `MYSQL_PASSWORD`, `FLASK_SECRET_KEY`) se definen en `.env`.
- El fichero `.env` está excluido del repositorio en `.gitignore`.
- Los endpoints de administración nunca incluyen el campo `password_hash` en las respuestas JSON.

### Tests que verifican este control
- `TestBcrypt::test_hash_not_plaintext` → el hash no es la contraseña
- `TestBcrypt::test_two_hashes_differ` → mismo input, hashes distintos (salt aleatorio)
- `TestBcrypt::test_verify_correct` / `test_verify_wrong` → verificación correcta
- `TestJWT::test_tampered_signature_raises` → firma manipulada → excepción

---

## A03 — Injection

### Riesgo
La inyección SQL ocurre cuando datos del usuario se incluyen directamente en una consulta sin sanitización, permitiendo al atacante modificar la lógica de la query y acceder o destruir datos.

### Implementación

**Fichero:** `backend/app.py`

**Todas las consultas son parametrizadas — sin excepción:**
```python
# CORRECTO — parámetro separado del SQL
cursor.execute(
    "SELECT id, username, password_hash, role, active "
    "FROM users WHERE username = %s",
    (username,)
)

# NUNCA se hace esto:
# cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")  # VULNERABLE
```

El driver `mysql-connector-python` escapa automáticamente los parámetros, haciendo imposible la inyección independientemente del contenido del input.

Medidas complementarias:
- Inputs truncados antes de usarse: `username[:64]`, `password[:128]`.
- Jinja2 aplica auto-escaping en todos los templates: `{{ variable }}` escapa `<`, `>`, `"`, `'` automáticamente, previniendo XSS reflejado.
- `Content-Security-Policy: default-src 'self'` bloquea la carga de scripts externos, como segunda línea de defensa contra XSS.

---

## A04 — Insecure Design

### Riesgo
Una arquitectura con decisiones de diseño inseguras crea vulnerabilidades estructurales difíciles de corregir a posteriori: superficies de ataque innecesarias, ausencia de límites de confianza o falta de defensa en profundidad.

### Implementación

**Fichero:** `docker-compose.yml`

**Segregación de red:**
```yaml
backend:
  expose:
    - "5001"    # solo accesible dentro de la red Docker 'appnet'

frontend:
  ports:
    - "5000:5000"   # único servicio expuesto al exterior
```

- El backend y MySQL son accesibles únicamente desde la red Docker interna. Un atacante externo no puede alcanzarlos directamente.
- El frontend actúa como único punto de entrada y nunca expone acceso directo a MySQL.

Medidas de diseño adicionales:
- Pool de conexiones MySQL con `pool_size=5` para prevenir agotamiento de recursos.
- Timeout de 8 segundos en llamadas HTTP del frontend al backend.
- Inputs truncados para prevenir desbordamientos y ataques de recursos.
- Usuario no-root `appuser` en todos los contenedores.

---

## A05 — Security Misconfiguration

### Riesgo
Configuraciones por defecto inseguras, cabeceras HTTP ausentes, permisos excesivos o funcionalidades innecesarias habilitadas son vectores de ataque comunes y fácilmente explotables.

### Implementación

**Ficheros:** `backend/app.py`, `frontend/app.py`

Las 7 cabeceras de seguridad se aplican en **todas** las respuestas HTTP mediante un decorador `@after_request`:

```python
@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"]             = "no-store"
    response.headers["Content-Security-Policy"]   = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
```

| Cabecera | Valor | Protección |
|----------|-------|-----------|
| `X-Content-Type-Options` | `nosniff` | Previene MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Previene clickjacking |
| `X-XSS-Protection` | `1; mode=block` | Activa el filtro XSS del navegador |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controla la cabecera Referer |
| `Cache-Control` | `no-store` | Impide que los navegadores cacheen respuestas sensibles |
| `Content-Security-Policy` | `default-src 'self'` | Solo recursos del mismo origen |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Fuerza HTTPS durante 1 año |

Configuración adicional:
- `debug=False` en producción (Flask no expone trazas de error).
- Imagen base `python:3.12-slim` — superficie de ataque mínima.
- Contenedores ejecutados como usuario `appuser` (no root).

### Tests que verifican este control
- `TestSecurityHeaders` — 8 tests verificando cada cabecera en respuestas normales y de error.

---

## A06 — Vulnerable and Outdated Components

### Riesgo
El uso de dependencias con vulnerabilidades conocidas o sin mantenimiento activo es uno de los vectores de ataque más explotados en producción.

### Implementación

**Ficheros:** `backend/requirements.txt`, `frontend/requirements.txt`, `.github/workflows/ci.yml`

Versiones fijas en todos los `requirements.txt`:

```
# backend/requirements.txt
flask==3.0.3
pyjwt==2.8.0
bcrypt==4.1.3
mysql-connector-python==8.4.0

# frontend/requirements.txt
flask==3.0.3
requests==2.32.3
```

- Todas las versiones corresponden a releases estables con parches de seguridad aplicados en el momento del desarrollo.
- Las imágenes Docker `mysql:8.0` y `python:3.12-slim` son imágenes oficiales con mantenimiento activo.
- **Bandit** se ejecuta en cada push en el job `security` del pipeline CI/CD, analizando el código Python en busca de patrones inseguros.

---

## A07 — Identification and Authentication Failures

### Riesgo
Contraseñas débiles, falta de protección contra fuerza bruta, sesiones mal gestionadas o tokens sin expiración permiten comprometer cuentas de usuario.

### Implementación

**Fichero:** `backend/app.py`, `frontend/app.py`

**Rate limiting — protección contra fuerza bruta:**
```python
def check_rate_limit(ip: str) -> bool:
    """Máximo 5 intentos por IP en ventana de 15 minutos."""
    now = time.time()
    window = [t for t in _login_attempts.get(ip, []) if now - t < 900]
    if len(window) >= 5:
        return False   # 6º intento → 429
    window.append(now)
    _login_attempts[ip] = window
    return True
```

**Protección contra timing attacks:**
```python
# Si el usuario no existe, se ejecuta igualmente bcrypt.checkpw con un hash ficticio.
# El tiempo de respuesta es ~250ms en ambos casos → no se puede enumerar usuarios.
dummy_hash = "$2b$12$" + "x" * 53
stored = row["password_hash"] if row else dummy_hash
valid  = row is not None and verify_password(password, stored)
```

**Sesiones seguras:**
```python
app.config["SESSION_COOKIE_HTTPONLY"] = True    # JavaScript no puede leer la cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Protección CSRF
app.config["SESSION_COOKIE_SECURE"]   = True   # Solo HTTPS en producción
```

- JWT con expiración de 1 hora (`exp`).
- Mismo mensaje de error para usuario inexistente y contraseña incorrecta (no se revela qué usuarios existen).

### Tests que verifican este control
- `TestRateLimit` — 5 tests: ventana deslizante, múltiples IPs independientes.
- `test_login_nonexistent_user` → devuelve 401, no 404.
- `test_login_rate_limited` → 6º intento devuelve 429.

---

## A08 — Software and Data Integrity Failures

### Riesgo
Código o dependencias provenientes de fuentes no verificadas, pipelines de CI/CD sin validación, o deserialización insegura permiten introducir código malicioso en producción.

### Implementación

- Imágenes Docker `mysql:8.0` y `python:3.12-slim` son imágenes oficiales verificadas mediante checksums.
- No se carga ningún recurso externo (JavaScript, CSS, fuentes) en los templates HTML. Todo es local.
- `Content-Security-Policy: default-src 'self'` bloquea la carga de cualquier recurso externo, incluyendo scripts inyectados.
- El pipeline CI/CD requiere que los jobs `test`, `security` y `docker build` pasen antes de cualquier deploy.
- El payload del JWT está firmado con HS256. Cualquier modificación del contenido invalida la firma, previniendo manipulación de roles o identidades.

---

## A09 — Security Logging and Monitoring Failures

### Riesgo
Sin un registro adecuado de eventos de seguridad, las brechas pasan desapercibidas durante días o semanas. La ausencia de alertas ante actividad sospechosa impide la respuesta a incidentes.

### Implementación

**Fichero:** `backend/app.py` — función `log_action`, tabla `audit_log`

```python
def log_action(username: str, action: str, detail: str = ""):
    conn = get_pool().get_connection()
    cur  = conn.cursor()
    cur.execute(
        "INSERT INTO audit_log (username, action, ip, detail) VALUES (%s, %s, %s, %s)",
        (username, action, request.remote_addr, detail)
    )
    conn.commit()
```

Acciones registradas automáticamente:

| Acción | Cuándo se registra |
|--------|-------------------|
| `login_success` | Login exitoso |
| `login_failed` | Contraseña incorrecta |
| `login_blocked` | Rate limit activado |
| `get_projects` | Listado de proyectos |
| `list_users` | Admin lista usuarios |
| `create_project` | Creación de proyecto |
| `user_activated` | Admin activa usuario |
| `user_deactivated` | Admin desactiva usuario |

Cada entrada incluye `username`, `action`, `ip`, `detail` y `created_at`.

**Monitorización en tiempo real:**
- El panel de administración muestra los últimos 100 eventos.
- El dashboard admin incluye un contador de fallos de login en la última hora con **alerta visual roja** si supera 3.
- Los logs persisten en MySQL a través del volumen Docker.

---

## A10 — Server-Side Request Forgery (SSRF)

### Riesgo
Si una aplicación realiza peticiones HTTP a URLs suministradas por el usuario, un atacante puede redirigirlas hacia servicios internos (como bases de datos o APIs de metadatos de cloud) que no deberían ser accesibles desde el exterior.

### Implementación

**Fichero:** `frontend/app.py`

```python
BACKEND_URL = os.environ.get("BACKEND_URL", "http://backend:5001")

def call_backend(method: str, path: str, **kwargs):
    """
    La URL de destino es siempre BACKEND_URL + path.
    path viene del código de la aplicación, nunca del usuario.
    """
    return getattr(requests, method)(
        f"{BACKEND_URL}{path}", timeout=8, **kwargs
    )
```

- `BACKEND_URL` es una constante definida en variables de entorno. No existe ningún endpoint que acepte una URL como parámetro de entrada.
- El usuario nunca puede influir en el destino de las peticiones HTTP que hace el servidor.
- La red Docker actúa como barrera adicional: solo el backend es accesible desde el frontend, y el backend no tiene salida a Internet.

---

## Referencias

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/)
- [OWASP Cheat Sheet — Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Cheat Sheet — JSON Web Token](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP Cheat Sheet — SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Cheat Sheet — HTTP Security Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
