# 📧 Configuración de Envío de Emails

Este documento explica cómo configurar el sistema de envío de emails para el código de activación de cuentas en el proyecto e-commerce backend.

## 🚀 Funcionalidades Implementadas

### ✅ Características Principales
- ✉️ **Envío de código de activación** al registrar una cuenta
- 🔄 **Reenvío de código** si el usuario no lo recibió
- ⏰ **Códigos con expiración** (configurable, por defecto 15 minutos)
- 🎨 **Plantillas HTML** profesionales y responsivas
- 🔒 **Envío asíncrono** para no bloquear el registro
- 📱 **Emails de bienvenida** después de la activación

### 📧 Tipos de Emails
1. **Email de Activación**: Contiene código de 6 dígitos para activar la cuenta
2. **Email de Bienvenida**: Se envía después de activar exitosamente la cuenta
3. **Email de Reset de Contraseña**: Para restablecer contraseñas (preparado para futuro)
4. **Email de Notificación**: Cuando se cambia la contraseña (preparado para futuro)

## ⚙️ Configuración

### 1. Variables de Entorno
Configura las siguientes variables de entorno en tu sistema:

```bash
# Gmail Configuration
export EMAIL_USERNAME="tu-email@gmail.com"
export EMAIL_PASSWORD="tu-app-password"
```

### 2. Configuración de Gmail

#### Paso 1: Habilitar Autenticación de 2 Factores
1. Ve a tu [Cuenta de Google](https://myaccount.google.com/)
2. Selecciona "Seguridad" en el panel izquierdo
3. En "Iniciar sesión en Google", selecciona "Verificación en 2 pasos"
4. Sigue las instrucciones para habilitarla

#### Paso 2: Generar Contraseña de Aplicación
1. En la misma sección de "Seguridad"
2. Selecciona "Contraseñas de aplicaciones"
3. Selecciona la aplicación y el dispositivo
4. Genera la contraseña de 16 caracteres
5. **Usa esta contraseña** como `EMAIL_PASSWORD`

### 3. Configuración Alternativa (Otros Proveedores)

#### Para Outlook/Hotmail:
```properties
spring.mail.host=smtp-mail.outlook.com
spring.mail.port=587
```

#### Para Yahoo:
```properties
spring.mail.host=smtp.mail.yahoo.com
spring.mail.port=587
```

#### Para Servidor SMTP Personalizado:
```properties
spring.mail.host=tu-servidor-smtp.com
spring.mail.port=587
spring.mail.username=${EMAIL_USERNAME}
spring.mail.password=${EMAIL_PASSWORD}
```

## 🛠️ Configuración en application.properties

Las siguientes propiedades están configuradas en `application.properties`:

```properties
# Email Configuration
spring.mail.host=smtp.gmail.com
spring.mail.port=587
spring.mail.username=${EMAIL_USERNAME:your-email@gmail.com}
spring.mail.password=${EMAIL_PASSWORD:your-app-password}
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true
spring.mail.properties.mail.smtp.starttls.required=true
spring.mail.properties.mail.smtp.ssl.trust=smtp.gmail.com

# Email Templates Configuration
app.email.from-name=E-Commerce Store
app.email.from-address=${EMAIL_USERNAME:your-email@gmail.com}
app.email.activation-code-expiry-minutes=15
app.email.reset-password-code-expiry-minutes=10
```

## 🔧 Personalización

### Cambiar Tiempo de Expiración
Modifica en `application.properties`:
```properties
app.email.activation-code-expiry-minutes=30  # 30 minutos
```

### Cambiar Nombre del Remitente
```properties
app.email.from-name=Tu Tienda Online
```

### Personalizar Plantillas
Las plantillas HTML están en: `src/main/resources/templates/emails/`
- `activation-email.html`: Email de activación
- `welcome-email.html`: Email de bienvenida
- `password-reset-email.html`: Email de reset de contraseña
- `password-changed-email.html`: Notificación de cambio de contraseña

## 📡 Endpoints API

### 1. Registro de Usuario
```http
POST /api/auth/register
Content-Type: application/json

{
  "idNumber": "12345678",
  "name": "Juan",
  "lastName": "Pérez",
  "email": "juan@email.com",
  "phoneNumber": "+573001234567",
  "password": "password123",
  "dateOfBirth": "1990-01-01"
}
```

### 2. Activar Cuenta
```http
POST /api/auth/activate-account
Content-Type: application/json

{
  "email": "juan@email.com",
  "activationCode": "123456"
}
```

### 3. Reenviar Código de Activación
```http
POST /api/auth/resend-activation-code
Content-Type: application/json

{
  "email": "juan@email.com"
}
```

## 🧪 Testing

### Configuración para Testing
El proyecto incluye configuración separada para testing que usa H2 in-memory database:
- `src/test/resources/application-test.properties`
- Los emails no se envían en el entorno de testing

### Probar el Envío de Emails
1. Configura las variables de entorno
2. Ejecuta la aplicación
3. Registra un usuario nuevo
4. Verifica que llegue el email con el código
5. Usa el código para activar la cuenta

## 🚨 Troubleshooting

### Error: "Authentication failed"
- ✅ Verifica que hayas habilitado la autenticación de 2 factores
- ✅ Usa la contraseña de aplicación, no tu contraseña normal
- ✅ Verifica que las variables de entorno estén configuradas

### Error: "Connection timeout"
- ✅ Verifica tu conexión a internet
- ✅ Algunos firewalls corporativos bloquean SMTP
- ✅ Prueba con un puerto diferente (465 para SSL)

### Los emails no llegan
- ✅ Verifica la carpeta de spam
- ✅ Confirma que el email esté bien escrito
- ✅ Revisa los logs de la aplicación

### Error: "Unknown property"
- ✅ Los warnings sobre propiedades desconocidas son normales
- ✅ Spring Boot carga las propiedades personalizadas correctamente

## 📝 Logs y Monitoreo

La aplicación registra información detallada sobre el envío de emails:

```
INFO  - Usuario registrado exitosamente: juan@email.com - ID: 1
INFO  - Email de activación enviado a: juan@email.com
INFO  - Cuenta activada exitosamente para usuario: juan@email.com
INFO  - Email de bienvenida enviado a: juan@email.com
```

## 🔒 Seguridad

### Buenas Prácticas Implementadas
- ✅ Códigos de 6 dígitos aleatorios
- ✅ Expiración automática de códigos
- ✅ Validación de formato de email
- ✅ Logs de seguridad
- ✅ Envío asíncrono para evitar bloqueos
- ✅ Manejo de errores sin exponer información sensible

### Recomendaciones Adicionales
- 🔐 Usa variables de entorno para credenciales
- 🔄 Rota las contraseñas de aplicación periódicamente
- 📊 Monitorea los logs de envío de emails
- 🚫 No hardcodees credenciales en el código

## 🎯 Próximos Pasos

### Funcionalidades Futuras
- [ ] Reset de contraseña por email
- [ ] Notificaciones de cambio de contraseña
- [ ] Templates personalizables desde base de datos
- [ ] Estadísticas de envío de emails
- [ ] Soporte para múltiples idiomas
- [ ] Rate limiting para envío de emails

¡El sistema de envío de emails está listo para usar! 🚀
