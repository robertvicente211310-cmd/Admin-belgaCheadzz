# Panel de licencias Belga

Incluye un panel HTML en español y una API Python con SQLite. La API está adaptada al protocolo que se encontró dentro de `BelgaCheats_1.0_sign.apk`: envía `type=register` o `type=login` mediante POST de formulario a `/`.

**El archivo HTML solo es la interfaz; no puede verificar licencias por sí solo.** Para que las claves funcionen desde el APK hay que publicar también `server.py` en un servidor que ejecute Python y use HTTPS. No subas solamente `admin.html` a un hosting de archivos estáticos.

## Funciones incluidas

- Crear de 1 a 100 licencias por lote, con duración de 7, 30, 90, 180 o 365 días, o sin vencimiento.
- Ver licencias, notas, vencimiento, estado de uso y usuario asociado; revocarlas.
- Una licencia se consume al registrarse; la primera autenticación vincula la cuenta al HWID enviado por el APK.
- Contraseñas de usuario con PBKDF2 y base SQLite persistente.
- Acceso de administrador mediante `ADMIN_PASSWORD`, cookie HttpOnly y límite básico de intentos.
- Respuestas JSON compatibles con la comprobación de login y registro observada en la app.

## Probar localmente

Necesitas Python 3.10 o superior. Desde esta carpeta:

```bash
ADMIN_PASSWORD='elige-una-clave-larga-y-unica' python3 server.py
```

Abre `http://localhost:8080/` e inicia sesión con esa contraseña. Los datos se guardan en `data/licenses.sqlite3`; haz copia de seguridad de esa carpeta. Para parar el servidor, usa `Ctrl+C`.

## Publicar

Despliega **los dos archivos** (`server.py` y `admin.html`) en un host que mantenga procesos Python y almacenamiento persistente. Configura estas variables en el host:

- `ADMIN_PASSWORD`: contraseña larga, aleatoria y exclusiva del panel.
- `PUBLIC_HTTPS=1`: activa el atributo Secure de la cookie cuando el sitio ya está detrás de HTTPS.
- `PORT`: opcional; el host puede asignarlo.
- `LICENSE_DATA_DIR`: opcional; carpeta persistente para la base de datos.

El servidor incluido habla HTTP internamente. En producción, termina TLS/HTTPS en el proxy del proveedor y reenvía las solicitudes al puerto de la aplicación. Comprueba que la base SQLite persista entre reinicios y despliegues. No publiques el servicio en HTTP abierto ni pongas `ADMIN_PASSWORD` dentro de `admin.html`.

## Importante para el APK adjunto

El APK adjunto **no lee la URL desde un panel ni desde un ajuste remoto**: su código contiene la dirección `https://aimaiadmin-n8z9h9uz.manus.space/` directamente. Además, inspeccionando el cliente HTTP aparece una comprobación de certificado por pin (hash de la clave pública TLS). Por tanto:

1. Publicar este panel no cambia la dirección que consulta el APK.
2. Cambiar solo la URL incrustada tampoco basta: el certificado del nuevo dominio debe coincidir con los pins que espera la app, o hay que actualizar la configuración de pins en el proyecto fuente.
3. Para apuntar al nuevo dominio, necesitas el proyecto fuente Android, cambiar la URL y la fijación de certificado, compilar y firmar un APK nuevo. No puedo prometer compatibilidad editando únicamente este panel.
4. El APK también contiene una petición `/?action=offsets`; este paquete implementa las rutas de registro e inicio de sesión identificadas. La respuesta de offsets no se inventó porque su formato no queda establecido por el contrato de autenticación.

La API espera, como mínimo:

- Registro: `POST /` con `type=register`, `username`, `pass` (o `password`) y `key` (o `license`). Devuelve JSON con `success` y `message`.
- Login: `POST /` con `type=login`, `username`, `pass` y `hwid`. En éxito devuelve `{"success":true,"keyInfo":{"authenticated":true}}`.

## Alcance de seguridad

Este es un punto de partida funcional, no una auditoría de seguridad ni una solución anti-manipulación del APK. La autenticación de administrador y el almacenamiento deben permanecer en el servidor. Usa HTTPS, restringe el acceso administrativo cuando sea posible, mantén actualizado el host y conserva copias de seguridad. El servidor mantiene las sesiones de administración en memoria; cerrar/reiniciar el proceso cierra esas sesiones.
