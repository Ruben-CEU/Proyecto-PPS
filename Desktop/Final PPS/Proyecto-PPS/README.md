# SecureApp 🔒

**Aplicación web segura con Flask · MySQL · Docker · JWT · bcrypt**

> Versión 2.0 — Marzo 2026

---

## Descripción del Proyecto

SecureApp es una aplicación web full-stack que implementa buenas prácticas de seguridad con Python Flask, MySQL y Docker. Cubre autenticación JWT, autorización por roles, API REST segura, base de datos MySQL real y cumplimiento del OWASP Top 10 2025.

---

## 2. Requisitos del Proyecto e Implementación

### 2.1 Contenedores Docker

**Requisito:** Las aplicaciones se deben crear en contenedores.

**Ficheros:** `docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile`

Tres contenedores orquestados con Docker Compose:

- **mysql** → MySQL 8.0 oficial. Puerto 3306 solo red interna Docker. Datos en volumen `mysql_data`.
- **backend** → Flask REST API puerto 5001. Solo accesible desde la red interna.
- **frontend** → Flask UI puerto 5000. Único servicio expuesto al exterior.

Orden controlado: `depends_on + condition: service_healthy`. MySQL listo → backend → frontend.

```bash
cp .env.example .env
docker compose up --build -d
# http://localhost:5000
```

---

### 2.2 Entorno Virtual / Aislamiento

**Requisito:** Aprovechar entornos virtuales para aislar el desarrollo.

**Opción utilizada:** Contenedores Docker como entorno de desarrollo aislado.

Cada contenedor tiene sistema de ficheros propio, dependencias Python independientes, usuario no-root (`appuser`) y red privada Docker. El aislamiento supera al de `virtualenv` y garantiza reproducibilidad total en cualquier máquina con Docker.

```bash
# Ver entornos corriendo (equivalente al prompt del entorno virtual):
docker ps
# secureapp-frontend  Up (healthy)
# secureapp-backend   Up (healthy)
# secureapp-mysql     Up (healthy)
```

---

### 2.3 Autenticación y Autorización — Dos Roles

**Requisito:** Dos usuarios (admin y normal). Indicar usuario identificado. Admin ve algo diferente (color, título, etc.).

**Ficheros:** `backend/app.py` (`token_required`, `admin_required`), `dashboard.html`, `admin.html`

Implementación de roles:

- Columna `role ENUM('admin','user')` en tabla `users` de MySQL. Demo: `admin/Admin1234!` y `usuario/User1234!`
- JWT firmado con HS256 incluye el campo `role`. El frontend no puede modificarlo sin invalidar la firma.
- `@token_required`: exige JWT válido en cada endpoint protegido.
- `@admin_required`: exige JWT válido Y `role == 'admin'`. Endpoints `/api/admin/*` lo usan.

Diferenciación visual según rol:

| | Admin | Usuario |
|---|---|---|
| Fondo | Morado `#f5f3ff` | Azul `#f1f5f9` |
| Cabecera | `#4c1d95` | `#1e3a5f` |
| Badge | `ADMIN` | `USER` |
| Menú extra | Panel admin, crear proyectos, estadísticas | Solo proyectos |

---

### 2.4 Frontend Flask comunicado con Backend via API

**Requisito:** Front end Flask que se comunicará con un back end a través de una API con mecanismos seguros.

**Ficheros:** `backend/app.py` (endpoints), `frontend/app.py` (función `call_backend`)

```
Navegador <-> Frontend Flask :5000
                |
           HTTP + JWT Bearer (red interna Docker)
                |
         Backend Flask API :5001
                |
          mysql-connector-python
                |
           MySQL 8 :3306
```

Mecanismo seguro: JWT HS256. Flujo:

1. `POST /api/login` → backend verifica contraseña en MySQL con `bcrypt.checkpw` → genera JWT firmado
2. Frontend guarda JWT en sesión Flask server-side (cookie `HttpOnly + SameSite=Lax`)
3. Cada llamada incluye cabecera: `Authorization: Bearer <token>`
4. Backend verifica firma JWT con `@token_required` antes de procesar cada request

Endpoints de la API REST:

| Método | Endpoint | Protección |
|--------|----------|-----------|
| GET | `/api/health` | Pública |
| POST | `/api/login` | Pública |
| GET | `/api/profile` | `@token_required` |
| GET | `/api/projects` | `@token_required` |
| POST | `/api/projects` | `@admin_required` |
| GET | `/api/admin/users` | `@admin_required` |
| POST | `/api/admin/users/<id>/toggle` | `@admin_required` |
| GET | `/api/admin/logs` | `@admin_required` |
| GET | `/api/admin/stats` | `@admin_required` |

---

### 2.5 Base de Datos MySQL

**Requisito:** Base de datos MySQL conectada.

**Ficheros:** `backend/app.py` (`get_pool`, `get_db`, `init_db`), `docker-compose.yml`, `mysql/init.sql`

- Driver: `mysql-connector-python 8.4.0` (oficial de Oracle/MySQL)
- Pool de conexiones: `MySQLConnectionPool` con `pool_size=5`
- 30 reintentos con espera exponencial al arrancar (aguanta el boot del contenedor MySQL)
- Creación automática de tablas con `init_db()` en el primer arranque
- Persistencia: volumen Docker `mysql_data`

Tablas:

| Tabla | Columnas principales |
|-------|---------------------|
| `users` | id, username UNIQUE, password_hash (bcrypt), role ENUM, active, created_at |
| `audit_log` | id, username, action, ip, detail, created_at |
| `projects` | id, name, description, status ENUM, owner, created_at, updated_at |

```bash
# Verificar la BD:
docker exec secureapp-mysql mysql -u appuser -papppassword secureapp \
  -e "SHOW TABLES; SELECT username, role FROM users;"
```

---

### 2.6 OWASP Top 10

**Requisito:** Comprobar OWASP Top 10 (web y APIs). Ver fichero [OWASP.md](./OWASP.md) para análisis completo.

| # | Categoría | Estado | Medida principal |
|---|-----------|--------|-----------------|
| A01 | Broken Access Control | ✅ | `@token_required` + `@admin_required` |
| A02 | Cryptographic Failures | ✅ | bcrypt rounds=12 + JWT HS256 |
| A03 | Injection | ✅ | Queries parametrizadas con `%s` |
| A04 | Insecure Design | ✅ | Red Docker segregada + pool |
| A05 | Security Misconfiguration | ✅ | 7 cabeceras HTTP + no-root |
| A06 | Vulnerable Components | ✅ | Versiones fijas + Bandit CI |
| A07 | Authentication Failures | ✅ | Rate limit 5/15min + JWT exp 1h |
| A08 | Software Integrity | ✅ | Imágenes Docker oficiales |
| A09 | Security Logging | ✅ | Tabla `audit_log` MySQL |
| A10 | SSRF | ✅ | `BACKEND_URL` fija en entorno |

---

### 2.7 Pruebas (Unitarias e Integración)

**Requisito:** Crear tantos tipos de pruebas como sea posible, mínimo unitarias e integración.

**Ficheros:** `tests/test_backend.py`, `tests/test_backend_extended.py`, `tests/test_frontend.py`, `tests/test_mysql_integration.py`

**Tests unitarios** (`test_backend_extended.py`):
- `TestBcrypt` — 8 tests: hash, verificación, salt aleatorio, contraseña larga
- `TestJWT` — 8 tests: creación, verificación, expiración, firma manipulada
- `TestRateLimit` — 5 tests: ventana deslizante, múltiples IPs independientes
- `TestInputValidation` — 5 tests: truncado de inputs, body vacío, sin JSON

**Tests de integración con MySQL mockeado** (`test_backend_extended.py`):
- `TestLoginPOST` — 6 tests: MySQL consultado con username correcto, audit_log escrito, usuario inactivo
- `TestProjectsPOST` — 8 tests: INSERT con datos exactos, commit llamado, lastrowid al cliente
- `TestToggleUserPOST` — 5 tests: UPDATE en MySQL, 404 para inexistente, 403 para user

**Tests de persistencia simulada** (`test_backend_extended.py`):
- `TestMySQLPersistenceSimulated` — 5 tests: ciclo POST→GET con BD en memoria, IDs incrementales, audit trail

**Tests con MySQL real** (`test_mysql_integration.py`):
- Ejecutados en GitHub Actions con contenedor MySQL 8.0 real
- Verifican tablas, bcrypt real, persistencia real, toggle de usuarios, ciclo completo end-to-end

```bash
pip install -r tests/requirements-test.txt
pytest tests/test_backend.py tests/test_backend_extended.py tests/test_frontend.py -v
```

---

### 2.8 Control de Versiones Git y GitHub

**Requisito:** Gestionar versiones con git, abrir forks de nuevas características, merge a main, subir a GitHub.

**Fichero:** `.gitignore` (excluye `.env`, `__pycache__`, `*.db`)

```bash
# Rama de feature
git checkout -b feature/nueva-funcionalidad
git add . && git commit -m "feat: descripción"

# Merge sin fast-forward (mantiene historial)
git checkout main
git merge --no-ff feature/nueva-funcionalidad
git push origin main
```

---

### 2.9 GitHub Actions — CI/CD

**Requisito:** Utilizar herramienta de automatización (GitHub Actions, Jenkins o similar).

**Fichero:** `.github/workflows/ci.yml`

Pipeline en 4 jobs, activado en push a `main`/`develop` y en Pull Requests:

```
push a main
    │
    ├── test          pytest unitarios + integración (~2 min)
    ├── test-mysql    MySQL 8 real como servicio (~3 min)
    ├── security      Bandit análisis estático (~1 min)
    │
    └── [si los 3 pasan] ──► docker build + smoke test ──► deploy
```

---

## 3. Estructura del Proyecto

```
Proyecto-PPS/
├── backend/
│   ├── app.py              Flask API + MySQL + JWT + bcrypt
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── app.py              Flask UI
│   ├── Dockerfile
│   ├── requirements.txt
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── dashboard.html
│       ├── admin.html
│       └── new_project.html
├── mysql/
│   └── init.sql
├── tests/
│   ├── test_backend.py
│   ├── test_backend_extended.py
│   ├── test_frontend.py
│   ├── test_mysql_integration.py
│   └── requirements-test.txt
├── .github/workflows/
│   └── ci.yml
├── docker-compose.yml
├── .env.example
├── README.md
└── OWASP.md
```

---

## 4. Instalación y Puesta en Marcha

### Requisitos previos

- Docker Desktop (Win/Mac) o Docker Engine + Compose (Linux)
- Git
- Puerto 5000 libre

### Arranque

```bash
git clone https://github.com/Ruben-CEU/Proyecto-PPS.git
cd Proyecto-PPS
cp .env.example .env        # editar contraseñas seguras
docker compose up --build -d
# Esperar ~30s a que MySQL inicialice
docker compose ps           # verificar todos Up (healthy)
# Abrir http://localhost:5000
```

### Credenciales de demo

| Usuario | Contraseña | Rol |
|---------|-----------|-----|
| `admin` | `Admin1234!` | Administrador |
| `usuario` | `User1234!` | Usuario normal |

### Comandos útiles

```bash
docker compose logs -f                  # logs en tiempo real
docker compose logs -f backend          # solo logs del backend
docker compose down -v                  # borrar TODO incluidos datos MySQL
docker exec secureapp-mysql mysql ...   # acceso directo a MySQL
pytest tests/ -v                        # ejecutar tests
```

---

## 5. Tecnologías Utilizadas

| Categoría | Tecnología |
|-----------|-----------|
| Backend | Python 3.12, Flask 3.0, PyJWT 2.8, bcrypt 4.1, mysql-connector-python 8.4 |
| Frontend | Python 3.12, Flask 3.0, Requests 2.32, Jinja2 |
| Base de datos | MySQL 8.0, pool de conexiones, 3 tablas |
| Infraestructura | Docker 24+, Docker Compose V2, red bridge privada |
| CI/CD | GitHub Actions (test → security → docker → deploy) |
| Testing | pytest, unittest.mock, responses |
| Seguridad | JWT HS256, bcrypt rounds=12, OWASP Top 10 2025, 7 cabeceras HTTP |
