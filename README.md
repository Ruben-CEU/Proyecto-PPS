# SecureApp 🔒

**Aplicación web segura construida con Flask · MySQL · Docker · JWT · bcrypt**

> Proyecto de Puesta en Producción Segura (PPS) · CEU · Marzo 2026

[![CI/CD Pipeline](https://github.com/Ruben-CEU/Proyecto-PPS/actions/workflows/ci.yml/badge.svg)](https://github.com/Ruben-CEU/Proyecto-PPS/actions/workflows/ci.yml)
[![CI/CD Pipeline](https://github.com/Ruben-CEU/Proyecto-PPS/actions/workflows/ci.yml/badge.svg)](https://github.com/Ruben-CEU/Proyecto-PPS/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![JWT](https://img.shields.io/badge/JWT-HS256-000000?logo=jsonwebtokens&logoColor=white)](https://jwt.io/)
[![bcrypt](https://img.shields.io/badge/bcrypt-rounds%3D12-338C00?logo=security&logoColor=white)](https://pypi.org/project/bcrypt/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202025-000000?logo=owasp&logoColor=white)](./OWASP.md)
[![Postman](https://img.shields.io/badge/Postman-53%2F53%20tests-FF6C37?logo=postman&logoColor=white)](./postman/README.md)
[![pytest](https://img.shields.io/badge/pytest-passing-0A9EDC?logo=pytest&logoColor=white)](./tests/)
---

## Descripción

SecureApp es una aplicación web full-stack que demuestra la implementación práctica de buenas prácticas de seguridad en un entorno de producción real. Está construida sobre Python Flask, MySQL 8 y Docker, e implementa autenticación JWT, autorización por roles, API REST segura y cumplimiento del **OWASP Top 10 2025**.

---

## Índice

1. [Requisitos e implementación](#requisitos-e-implementación)
2. [Estructura del proyecto](#estructura-del-proyecto)
3. [Instalación y puesta en marcha](#instalación-y-puesta-en-marcha)
4. [Pruebas](#pruebas)
5. [Tecnologías](#tecnologías)

---

## Requisitos e implementación

### 1. Contenedores Docker

**Ficheros:** `docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile`

La aplicación se despliega en tres contenedores orquestados con Docker Compose:

| Contenedor | Imagen | Puerto | Exposición |
|-----------|--------|--------|-----------|
| `secureapp-mysql` | mysql:8.0 | 3306 | Solo red interna |
| `secureapp-backend` | python:3.12-slim | 5001 | Solo red interna |
| `secureapp-frontend` | python:3.12-slim | 5000 | Exterior ← único punto de entrada |

El orden de arranque está controlado mediante `depends_on + condition: service_healthy`, garantizando que MySQL esté listo antes de que el backend intente conectarse, y el backend antes del frontend.

```bash
cp .env.example .env
docker compose up --build -d
# Acceder en http://localhost:5000
```

---

### 2. Entorno aislado de desarrollo

**Opción utilizada:** contenedores Docker como entorno de desarrollo aislado.

Cada contenedor tiene su propio sistema de ficheros, dependencias Python independientes, usuario no-root (`appuser`) y red privada Docker. Este enfoque supera al de `virtualenv` tradicional ya que garantiza reproducibilidad total en cualquier máquina con Docker instalado.

```bash
docker ps
# secureapp-frontend  Up (healthy)
# secureapp-backend   Up (healthy)
# secureapp-mysql     Up (healthy)
```

---

### 3. Autenticación y autorización — dos roles

**Ficheros:** `backend/app.py`, `frontend/templates/dashboard.html`, `frontend/templates/admin.html`

El sistema implementa dos roles diferenciados con experiencias visuales distintas:

- **Rol admin** → interfaz morada (`#4c1d95`), acceso al panel de administración, gestión de usuarios y creación de proyectos.
- **Rol user** → interfaz azul (`#1e3a5f`), acceso de solo lectura a proyectos.

La autorización se implementa mediante dos decoradores en el backend:

- `@token_required` — exige JWT válido. Sin token → 401.
- `@admin_required` — exige JWT válido y `role == 'admin'`. Usuario normal → 403.

El rol viaja dentro del propio JWT firmado con HS256, por lo que el frontend no puede modificarlo sin invalidar la firma.

| | Admin | Usuario |
|--|-------|---------|
| Color cabecera | `#4c1d95` (morado) | `#1e3a5f` (azul) |
| Badge | `ADMIN` | `USER` |
| Panel administración | ✅ | ❌ |
| Crear proyectos | ✅ | ❌ |
| Ver proyectos | ✅ | ✅ |

---

### 4. Frontend Flask comunicado con Backend via API REST

**Ficheros:** `backend/app.py`, `frontend/app.py`

```
Navegador ←→ Frontend Flask :5000
                    │
          HTTP + JWT Bearer
          (red interna Docker)
                    │
          Backend Flask API :5001
                    │
       mysql-connector-python
                    │
            MySQL 8 :3306
```

**Flujo de autenticación:**

1. `POST /api/login` → el backend verifica la contraseña contra MySQL con `bcrypt.checkpw` y genera un JWT firmado.
2. El frontend guarda el JWT en una sesión Flask server-side (cookie `HttpOnly + SameSite=Lax`).
3. Cada llamada al backend incluye `Authorization: Bearer <token>`.
4. El backend verifica la firma del JWT antes de procesar cualquier request protegido.

**Endpoints de la API:**

| Método | Ruta | Acceso |
|--------|------|--------|
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

### 5. Base de datos MySQL

**Ficheros:** `backend/app.py`, `docker-compose.yml`, `mysql/init.sql`

- Driver oficial `mysql-connector-python 8.4.0`.
- Pool de conexiones `MySQLConnectionPool` con `pool_size=5`.
- 30 reintentos con espera exponencial en el arranque para aguantar el boot del contenedor MySQL.
- Inicialización automática de tablas con `init_db()` en el primer arranque.
- Datos persistidos en volumen Docker `mysql_data`.

| Tabla | Columnas clave |
|-------|---------------|
| `users` | id, username (UNIQUE), password_hash (bcrypt), role ENUM, active, created_at |
| `projects` | id, name, description, status ENUM, owner, created_at |
| `audit_log` | id, username, action, ip, detail, created_at |

```bash
# Verificar tablas y usuarios directamente en MySQL:
docker exec secureapp-mysql mysql -u appuser -papppassword secureapp \
  -e "SHOW TABLES; SELECT username, role, active FROM users;"
```

---

### 6. OWASP Top 10 — 2025

Ver el análisis completo en [OWASP.md](./OWASP.md).

| # | Categoría | Estado | Medida principal |
|---|-----------|--------|-----------------|
| A01 | Broken Access Control | ✅ | `@token_required` + `@admin_required` |
| A02 | Cryptographic Failures | ✅ | bcrypt rounds=12 + JWT HS256 + secrets en `.env` |
| A03 | Injection | ✅ | Queries parametrizadas con `%s`, nunca concatenación |
| A04 | Insecure Design | ✅ | Red Docker segregada, solo frontend expuesto |
| A05 | Security Misconfiguration | ✅ | 7 cabeceras HTTP de seguridad en todas las respuestas |
| A06 | Vulnerable Components | ✅ | Versiones fijas en `requirements.txt` + Bandit en CI |
| A07 | Auth Failures | ✅ | Rate limiting 5/15min + JWT exp 1h + timing attack protection |
| A08 | Software Integrity | ✅ | Imágenes Docker oficiales + CSP + CI/CD obligatorio |
| A09 | Security Logging | ✅ | Tabla `audit_log` en MySQL con IP, acción y timestamp |
| A10 | SSRF | ✅ | `BACKEND_URL` fija, nunca suministrada por el usuario |

---

### 7. Pruebas

**Ficheros:** `tests/`

El proyecto incluye cuatro niveles de pruebas:

**Unitarias** — sin base de datos ni red:
- `TestBcrypt` (8 tests): hash, verificación, salt aleatorio, contraseñas largas.
- `TestJWT` (8 tests): creación, verificación, expiración, firma manipulada.
- `TestRateLimit` (5 tests): ventana deslizante, múltiples IPs independientes.
- `TestInputValidation` (5 tests): truncado de inputs, body vacío, sin JSON.

**Integración con MySQL mockeado:**
- `TestLoginPOST` (6 tests): MySQL consultado con username correcto, audit_log escrito, usuario inactivo bloqueado.
- `TestProjectsPOST` (8 tests): INSERT verificado con datos exactos, `db.commit()` llamado, `lastrowid` devuelto.
- `TestToggleUserPOST` (5 tests): UPDATE en MySQL, 404 para inexistente, 403 para user normal.

**Persistencia simulada en memoria:**
- `TestMySQLPersistenceSimulated` (5 tests): ciclo completo POST → GET, IDs incrementales, audit trail.

**Contrato API y seguridad:**
- `TestSecurityHeaders` (8 tests): las 7 cabeceras HTTP verificadas en respuestas normales y de error.
- `TestHTTPMethods` (4 tests): métodos no permitidos devuelven 405.

**Pruebas Postman** — ver carpeta [`postman/`](./postman/README.md):
- 53 tests sobre todos los endpoints reales de la API.
- Verificación end-to-end con la aplicación corriendo en Docker.

```bash
# Ejecutar tests automatizados:
pip install -r tests/requirements-test.txt
pytest tests/test_backend.py tests/test_backend_extended.py tests/test_frontend.py -v
```

---

### 8. Control de versiones con Git y GitHub

**Fichero:** `.gitignore`

El flujo de trabajo sigue la estrategia de ramas por funcionalidad:

```bash
# Crear rama para nueva funcionalidad
git checkout -b feature/nombre-funcionalidad

git add .
git commit -m "feat: descripción del cambio"
git push origin feature/nombre-funcionalidad

# En GitHub: abrir Pull Request → revisar → merge a main
```

El `.gitignore` excluye `.env`, `__pycache__`, `*.db` y otros ficheros que no deben versionarse.

---

### 9. CI/CD con GitHub Actions

**Fichero:** `.github/workflows/ci.yml`

El pipeline se activa automáticamente en cada `git push` a `main` o `develop`, y en cada Pull Request:

```
push a main / PR
        │
        ├── Tests y Cobertura       pytest unitarios + integración
        ├── Tests con MySQL real    contenedor MySQL 8 como servicio
        ├── Análisis Bandit         análisis estático de seguridad
        │
        └── [si los 3 pasan]
                │
                ├── Build y Smoke Test Docker    build + arranque completo
                │
                └── [solo en main]
                        │
                        └── Deploy a Producción
```

---

## Estructura del proyecto

```
Proyecto-PPS/
├── backend/
│   ├── app.py                  API REST: JWT, bcrypt, MySQL, rate limiting
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── app.py                  UI Flask + rutas proxy API para Postman
│   ├── Dockerfile
│   ├── requirements.txt
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── dashboard.html      Vista diferenciada por rol
│       ├── admin.html          Panel de administración
│       └── new_project.html
├── mysql/
│   └── init.sql
├── tests/
│   ├── conftest.py             Configuración de rutas para pytest
│   ├── test_backend.py         Tests unitarios e integración
│   ├── test_backend_extended.py  Tests POST y persistencia MySQL
│   ├── test_frontend.py        Tests frontend con backend mockeado
│   └── requirements-test.txt
├── postman/
│   ├── README.md               Documentación de pruebas Postman
│   ├── SecureApp.postman_collection.json
│   └── SecureApp.postman_environment.json
├── .github/
│   └── workflows/
│       └── ci.yml              Pipeline CI/CD
├── docker-compose.yml
├── .env.example
├── README.md
└── OWASP.md
```

---

## Instalación y puesta en marcha

### Requisitos previos

- Docker Desktop (Windows/Mac) o Docker Engine + Compose Plugin (Linux)
- Git
- Puerto 5000 libre en el host

### Arranque rápido

```bash
git clone https://github.com/Ruben-CEU/Proyecto-PPS.git
cd Proyecto-PPS

# Configurar variables de entorno
cp .env.example .env
# Editar .env con contraseñas seguras antes de continuar

# Construir y arrancar
docker compose up --build -d

# Verificar que los 3 contenedores están sanos
docker compose ps

# Acceder a la aplicación
# http://localhost:5000
```

### Credenciales de demo

| Usuario | Contraseña | Rol |
|---------|-----------|-----|
| `admin` | `Admin1234!` | Administrador — interfaz morada |
| `usuario` | `User1234!` | Usuario normal — interfaz azul |

### Comandos útiles

```bash
docker compose logs -f                    # Logs en tiempo real (todos los servicios)
docker compose logs -f backend            # Solo logs del backend
docker compose restart backend            # Reiniciar backend (limpia rate limiting)
docker compose down -v                    # Parar y eliminar datos de MySQL
pytest tests/ -v                          # Ejecutar suite de tests
```

---

## Tecnologías

| Capa | Tecnología |
|------|-----------|
| Backend | Python 3.12, Flask 3.0.3, PyJWT 2.8.0, bcrypt 4.1.3, mysql-connector-python 8.4.0 |
| Frontend | Python 3.12, Flask 3.0.3, Requests 2.32.3, Jinja2 |
| Base de datos | MySQL 8.0 — 3 tablas, pool de conexiones, volumen persistente |
| Infraestructura | Docker 24+, Docker Compose V2, red bridge privada |
| CI/CD | GitHub Actions — 5 jobs: test, test-mysql, security, docker, deploy |
| Testing | pytest, unittest.mock, Postman/Newman |
| Seguridad | JWT HS256, bcrypt rounds=12, OWASP Top 10 2025, 7 cabeceras HTTP |
