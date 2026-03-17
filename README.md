# Pruebas Postman — SecureApp API

Documentación de la colección de tests Postman para la API REST de SecureApp.

---

## Resultado de ejecución

**53 / 53 tests pasados ✅** — 0 fallos · Tiempo medio de respuesta: 32ms

![Resultados de la ejecución](https://github.com/Ruben-CEU/Proyecto-PPS/blob/feature/postman-tests/resuldatos.png?raw=true)

---

## Requisitos previos

**1. Aplicación corriendo en Docker:**
```bash
docker compose up -d
docker compose ps   # los 3 contenedores deben estar Up (healthy)
```

**2. Postman instalado** — [postman.com/downloads](https://www.postman.com/downloads/)

**3. Importar los ficheros en Postman:**

Abrir Postman → **Import** → arrastrar los dos ficheros a la vez:
- `SecureApp.postman_collection.json` — colección con todos los tests
- `SecureApp.postman_environment.json` — variables de entorno

**4. Activar el entorno:**

En Postman, seleccionar **SecureApp Local** en el desplegable de entornos (arriba a la derecha).

---

## Variables de entorno

| Variable | Valor por defecto | Descripción |
|----------|------------------|-------------|
| `base_url` | `http://localhost:5000` | URL del frontend — proxy hacia el backend |
| `admin_token` | *(se rellena automáticamente)* | JWT del administrador |
| `user_token` | *(se rellena automáticamente)* | JWT del usuario normal |
| `project_id` | *(se rellena automáticamente)* | ID del último proyecto creado o listado |

Los tokens se guardan automáticamente al ejecutar el login — no es necesario copiarlos manualmente.

---

## Cómo ejecutar

1. Clic derecho sobre **SecureApp API** en el panel izquierdo → **Run collection**
2. Configurar **Delay: 500 ms** entre requests (evita activar el rate limiting)
3. Clic en **Run SecureApp API**

> Si aparecen errores 429 (Too Many Requests), ejecutar `docker compose restart backend` para reiniciar el contador de rate limiting.

---

## Descripción de las pruebas

### 01 — Health Check · 3 tests

Verifica que el backend y la base de datos están operativos antes de ejecutar el resto.

| Request | Qué verifica |
|---------|-------------|
| `GET /api/health` | Status 200, campo `status: ok`, `engine: MySQL 8`, Content-Type JSON |

---

### 02 — Autenticación · 10 tests

Verifica el sistema de login con JWT. El primer test guarda el token automáticamente para los requests siguientes.

| Request | Resultado esperado | Qué verifica |
|---------|--------------------|-------------|
| Login admin correcto | 200 ✅ | Token JWT (3 partes), `role: admin`, token guardado en entorno |
| Login usuario normal | 200 ✅ | Token JWT, `role: user`, token guardado en entorno |
| Contraseña incorrecta | 401 ❌ | Sin token en respuesta, campo `error` presente |
| Usuario inexistente | 401 ❌ | Mismo error que contraseña incorrecta — no revela si el usuario existe (OWASP A07) |
| Body vacío | 400 ❌ | Validación de campos obligatorios |
| GET en `/api/login` | 405 ❌ | Método no permitido |

---

### 03 — Perfil y Datos · 3 tests

Verifica el control de acceso a los datos del perfil autenticado.

| Request | Resultado esperado | Qué verifica |
|---------|--------------------|-------------|
| Perfil con token admin | 200 ✅ | `username: admin`, `role: admin` |
| Perfil sin token | 401 ❌ | Acceso denegado sin autenticación (OWASP A01) |
| Perfil con token inválido | 401 ❌ | Token manipulado o firmado con clave incorrecta es rechazado |

---

### 04 — Proyectos · 7 tests

Verifica el listado y creación de proyectos, incluyendo la autorización por rol.

| Request | Resultado esperado | Qué verifica |
|---------|--------------------|-------------|
| GET proyectos con token | 200 ✅ | Array de proyectos, campo `total`, sin `password_hash` en la respuesta |
| POST crear proyecto (admin) | 201 ✅ | Fila persistida en MySQL, `id` autoincremental devuelto |
| POST crear proyecto (usuario normal) | 403 ❌ | Usuarios con rol `user` no pueden crear proyectos (OWASP A01) |
| POST nombre vacío | 400 ❌ | El nombre es un campo obligatorio |
| POST estado inválido | 400 ❌ | Solo se aceptan `activo`, `completado`, `en revisión`, `cancelado` |
| POST sin token | 401 ❌ | Requiere autenticación |

---

### 05 — Administración · 8 tests

Verifica el panel de administración, accesible exclusivamente para el rol admin.

| Request | Resultado esperado | Qué verifica |
|---------|--------------------|-------------|
| GET usuarios (admin) | 200 ✅ | Lista con `total`, sin `password_hash` en ningún usuario (OWASP A02) |
| GET usuarios (usuario normal) | 403 ❌ | Solo admin puede listar usuarios |
| GET audit log | 200 ✅ | Array de logs con `action`, `username`, `ip`, `created_at` (OWASP A09) |
| GET estadísticas | 200 ✅ | Campos numéricos: `users`, `projects`, `admins`, `failed_logins_1h` |
| POST toggle desactivar usuario | 200 ✅ | Mensaje indica el nuevo estado |
| POST toggle reactivar usuario | 200 ✅ | Estado restaurado al original |
| POST toggle usuario inexistente | 404 ❌ | ID 999 no existe en la base de datos |
| POST toggle (usuario normal) | 403 ❌ | Solo admin puede cambiar el estado de cuentas |

---

### 06 — Cabeceras de Seguridad OWASP A05 · 7 tests

Verifica que las 7 cabeceras HTTP de seguridad están presentes en todas las respuestas.

| Cabecera | Valor | Protección |
|----------|-------|-----------|
| `X-Frame-Options` | `DENY` | Previene clickjacking |
| `X-Content-Type-Options` | `nosniff` | Previene MIME-type sniffing |
| `Cache-Control` | `no-store` | No cachear respuestas sensibles |
| `Content-Security-Policy` | `default-src 'self'` | Bloquea recursos externos |
| `Strict-Transport-Security` | `max-age=31536000` | Fuerza HTTPS durante 1 año |
| `Referrer-Policy` | presente | Controla la cabecera Referer |
| `X-XSS-Protection` | `1; mode=block` | Filtro XSS del navegador |

---

## Resumen

| Carpeta | Tests | ✅ Positivos | ❌ Negativos |
|---------|-------|------------|------------|
| 01 Health Check | 3 | 3 | 0 |
| 02 Autenticación | 10 | 5 | 5 |
| 03 Perfil y Datos | 3 | 1 | 2 |
| 04 Proyectos | 7 | 2 | 5 |
| 05 Administración | 8 | 4 | 4 |
| 06 Cabeceras Seguridad | 7 | 7 | 0 |
| **Total** | **53** | **22** | **16** |

Los tests negativos (❌) verifican que la API rechaza correctamente peticiones no autorizadas, malformadas o con métodos no permitidos. Son tan relevantes como los positivos para garantizar la seguridad de la aplicación.

---

## Solución de problemas

| Síntoma | Causa probable | Solución |
|---------|---------------|---------|
| Error 429 en los logins | Rate limiting activado por intentos previos | `docker compose restart backend` |
| Error 401 en todos los requests | Token no guardado (login no ejecutado primero) | Ejecutar manualmente `POST /api/login — admin correcto` |
| Sin respuesta / timeout | Los contenedores no están corriendo | `docker compose up -d` |
| `{{base_url}}` aparece sin resolver | El entorno no está activado en Postman | Seleccionar **SecureApp Local** en el desplegable de entornos |
