-- Inicialización de la base de datos SecureApp
-- Este script se ejecuta automáticamente la primera vez que arranca el contenedor MySQL

-- Asegurar charset y colación correcta (soporte completo de Unicode + emojis)
ALTER DATABASE secureapp
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

-- Las tablas las crea el backend (init_db()) al arrancar.
-- Este fichero solo garantiza la configuración del charset.
