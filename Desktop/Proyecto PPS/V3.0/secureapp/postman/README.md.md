# Pruebas Postman — SecureApp API

Documentación de la colección Postman para verificar todos los endpoints de la API REST de SecureApp.

---

## Requisitos previos

Antes de ejecutar las pruebas necesitas:

**1. Docker corriendo con los 3 contenedores activos:**
```bash
cd secureapp
docker compose up -d
docker compose ps   # verificar que los 3 están Up (healthy)
```

**2. Postman instalado:**
Descárgalo gratis en [postman.com/downloads](https://www.postman.com/downloads/)

**3. Importar los dos ficheros en Postman:**
- `SecureApp.postman_collection.json` — la colección con todos los tests
- `SecureApp.postman_environment.json` — las variables de entorno

Para importar: abre Postman → **Import** → arrastra los dos ficheros a la vez.

**4. Activar el entorno:**
En Postman, arriba a la derecha, selecciona **SecureApp Local** en el desplegable de entornos.

---

## Variables de entorno

| Variable | Valor inicial | Descripción |
|----------|--------------|-------------|
| `base_url` | `http://localhost:5000` | URL base del frontend (proxy hacia el backend) |
| `admin_token` | *(vacío)* | Se rellena automáticamente al ejecutar el login de admin |
| `user_token` | *(vacío)* | Se rellena automáticamente al ejecutar el login de usuario |
| `project_id` | *(vacío)* | Se rellena automáticamente al crear o listar proyectos |

> ⚠️ **Importante:** Los tokens se guardan automáticamente al ejecutar los tests de login. No necesitas copiarlos manualmente. Ejecuta siempre la colección completa en orden.

---

## Cómo ejecutar

### Opción A — Ejecutar toda la colección (recomendado)

1. En el panel izquierdo, clic derecho en **SecureApp API**
2. Seleccionar **Run collection**
3. Dejar el orden por defecto
4. Añadir un **Delay de 500ms** entre requests (evita el rate limiting)
5. Clic en **Run SecureApp API**

### Opción B — Ejecutar un request suelto

Si quieres probar un endpoint concreto, primero ejecuta manualmente **"POST /api/login — admin correcto"** de la carpeta 02 para que se guarde el token, y luego ya puedes ejecutar cualquier otro request.

---

## Descripción de las pruebas

### 01 - Health Check (1 prueba)

Verifica que el servicio está operativo.

| Request | Método | Qué verifica |
|---------|--------|-------------|
| GET /api/health | GET | Status 200, `status: ok`, base de datos MySQL conectada, Content-Type JSON |

---

### 02 - Autenticación (6 pruebas)

Verifica el sistema de login con JWT. El primer test guarda el token automáticamente.

| Request | Método | Resultado esperado | Qué verifica |
|---------|--------|--------------------|-------------|
| Login admin correcto | POST | 200 ✅ | Token JWT con 3 partes, role=admin, token guardado en variable |
| Login usuario normal | POST | 200 ✅ | Token JWT, role=user, token guardado en variable |
| Contraseña incorrecta | POST | 401 ❌ | No devuelve token, devuelve campo `error` |
| Usuario inexistente | POST | 401 ❌ | Mismo error que contraseña incorrecta (no revela si el usuario existe — OWASP A07) |
| Body vacío | POST | 400 ❌ | Validación de campos obligatorios |
| GET en /api/login | GET | 405 ❌ | Método no permitido |

> 🔒 **OWASP A07:** El test de usuario inexistente verifica que la API devuelve 401 (no 404), evitando revelar qué usuarios existen en el sistema.

---

### 03 - Perfil y Datos (3 pruebas)

Verifica el control de acceso a datos del perfil.

| Request | Método | Resultado esperado | Qué verifica |
|---------|--------|--------------------|-------------|
| Perfil con token admin | GET | 200 ✅ | Devuelve username=admin y role=admin |
| Perfil sin token | GET | 401 ❌ | Acceso denegado sin autenticación |
| Perfil con token inválido | GET | 401 ❌ | Token manipulado o expirado es rechazado |

> 🔒 **OWASP A01:** Verifica que los endpoints protegidos rechazan requests sin JWT válido.

---

### 04 - Proyectos (6 pruebas)

Verifica el CRUD de proyectos y la autorización por rol.

| Request | Método | Resultado esperado | Qué verifica |
|---------|--------|--------------------|-------------|
| GET proyectos con token | GET | 200 ✅ | Array de proyectos, campo `total`, no expone `password_hash` |
| POST crear proyecto (admin) | POST | 201 ✅ | Crea proyecto en MySQL, devuelve `id` autoincremental |
| POST crear proyecto (usuario) | POST | 403 ❌ | Usuario normal no puede crear proyectos |
| POST nombre vacío | POST | 400 ❌ | Validación: nombre obligatorio |
| POST estado inválido | POST | 400 ❌ | Validación: solo acepta activo/completado/en revisión |
| POST sin token | POST | 401 ❌ | Requiere autenticación |

> 🔒 **OWASP A01:** El test de usuario denegado verifica que la autorización por rol funciona.
> 🗄️ **MySQL:** El test de creación verifica que el `id` devuelto es un número positivo asignado por MySQL autoincrement.

---

### 05 - Administración (8 pruebas)

Verifica el panel de administración exclusivo para el rol admin.

| Request | Método | Resultado esperado | Qué verifica |
|---------|--------|--------------------|-------------|
| GET usuarios (admin) | GET | 200 ✅ | Lista con `total`, sin `password_hash` en ningún usuario |
| GET usuarios (user) | GET | 403 ❌ | Usuario normal no puede listar usuarios |
| GET audit log | GET | 200 ✅ | Array de logs con campos `action`, `username`, `created_at` |
| GET estadísticas | GET | 200 ✅ | Campos `total_users`, `total_projects`, `failed_logins_last_hour` |
| POST toggle usuario (desactivar) | POST | 200 ✅ | Mensaje contiene "activado" o "desactivado" |
| POST toggle usuario (reactivar) | POST | 200 ✅ | Segundo toggle restaura el estado |
| POST toggle usuario inexistente | POST | 404 ❌ | Usuario con ID 999 no existe |
| POST toggle por usuario normal | POST | 403 ❌ | Solo admin puede activar/desactivar usuarios |

> 🔒 **OWASP A02:** El test de lista de usuarios verifica que `password_hash` nunca se expone en la API.
> 🔒 **OWASP A09:** El test de audit log verifica que las acciones quedan registradas en MySQL.

---

### 06 - Cabeceras de Seguridad OWASP A05 (2 pruebas)

Verifica que todas las respuestas incluyen las cabeceras HTTP de seguridad requeridas.

| Request | Qué verifica |
|---------|-------------|
| Cabeceras en respuesta normal | Las 7 cabeceras en una respuesta 200 |
| Cabeceras en respuesta de error | Las cabeceras también presentes en respuestas 401 |

Cabeceras verificadas:

| Cabecera | Valor | Protección |
|----------|-------|-----------|
| `X-Frame-Options` | `DENY` | Previene clickjacking |
| `X-Content-Type-Options` | `nosniff` | Previene MIME sniffing |
| `Cache-Control` | `no-store` | No cachear datos sensibles |
| `Content-Security-Policy` | `default-src 'self'` | Bloquea recursos externos |
| `Strict-Transport-Security` | `max-age=...` | Fuerza HTTPS |
| `Referrer-Policy` | presente | Controla cabecera Referer |
| `X-XSS-Protection` | `1; mode=block` | Filtro XSS del navegador |

---

## Resumen total

| Carpeta | Tests | Casos ✅ | Casos ❌ |
|---------|-------|---------|---------|
| 01 Health Check | 3 | 3 | 0 |
| 02 Autenticación | 13 | 5 | 8 |
| 03 Perfil y Datos | 5 | 2 | 3 |
| 04 Proyectos | 10 | 4 | 6 |
| 05 Administración | 12 | 8 | 4 |
| 06 Cabeceras Seguridad | 9 | 7 | 2 |
| **TOTAL** | **52** | **29** | **23** |

> Los casos ❌ son pruebas de comportamiento negativo — verifican que la API rechaza correctamente peticiones inválidas, no autorizadas o malformadas. Son tan importantes como los casos ✅.

---

## Solución de problemas

**Error 429 Too Many Requests:**
El rate limiting bloqueó tu IP por demasiados intentos de login fallidos. Espera 15 minutos o reinicia el backend:
```bash
docker compose restart backend
```

**Error 401 en todos los requests:**
El token no se guardó. Ejecuta primero manualmente el request **"POST /api/login — admin correcto"** de la carpeta 02.

**Error de conexión / ECONNREFUSED:**
Los contenedores no están corriendo:
```bash
docker compose up -d
docker compose ps
```

**`{{base_url}}` aparece sin resolver:**
El entorno no está activado. Selecciona **SecureApp Local** en el desplegable de arriba a la derecha en Postman.
