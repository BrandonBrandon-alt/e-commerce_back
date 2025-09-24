# 🚀 JWT Authentication - Documentación de Uso

## 📋 Resumen de la Implementación

Hemos implementado un sistema completo de autenticación JWT siguiendo las mejores prácticas de la industria. El sistema incluye:

### ✅ Componentes Implementados

1. **JwtUtil** - Utilidad para generar y validar tokens JWT
2. **CustomUserDetailsService** - Servicio personalizado para cargar usuarios
3. **JwtAuthenticationFilter** - Filtro que intercepta requests y valida tokens
4. **SecurityConfig** - Configuración principal de seguridad
5. **AuthController** - Endpoints para login, registro y validación
6. **AuthService** - Lógica de negocio para autenticación
7. **DTOs especializados** - Para respuestas y validaciones

## 🔧 Configuración

### application.properties
```properties
# JWT Configuration
app.jwt.secret=mySecretKey123456789012345678901234567890
app.jwt.expiration=86400000  # 24 horas en milisegundos
```

### Estructura de Roles
- **BUYER** - Comprador (rol por defecto)
- **SELLER** - Vendedor
- **ADMIN** - Administrador

## 📡 Endpoints de Autenticación

### 1. **Registro de Usuario**
```http
POST /api/auth/register
Content-Type: application/json

{
    "idNumber": "123456789",
    "name": "Juan",
    "lastName": "Pérez",
    "email": "juan@example.com",
    "phoneNumber": "+573001234567",
    "password": "MiPassword123!",
    "role": "BUYER"
}
```

**Respuesta exitosa:**
```json
{
    "message": "Usuario registrado exitosamente. Ya puedes iniciar sesión.",
    "timestamp": "2025-01-23T12:30:00"
}
```

### 2. **Login**
```http
POST /api/auth/login
Content-Type: application/json

{
    "email": "juan@example.com",
    "password": "MiPassword123!"
}
```

**Respuesta exitosa:**
```json
{
    "access_token": "eyJhbGciOiJIUzUxMiJ9...",
    "token_type": "Bearer",
    "expires_in": 86400000,
    "user_info": {
        "id": 1,
        "email": "juan@example.com",
        "name": "Juan",
        "last_name": "Pérez",
        "role": "BUYER",
        "phone_number": "+573001234567",
        "enabled": true
    },
    "timestamp": "2025-01-23T12:30:00",
    "message": "Autenticación exitosa"
}
```

### 3. **Validar Token**
```http
POST /api/auth/validate-token
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...
```

**Respuesta exitosa:**
```json
{
    "valid": true,
    "username": "juan@example.com",
    "expires_in": 86345000,
    "timestamp": "2025-01-23T12:30:00",
    "message": "Token válido"
}
```

### 4. **Obtener Información del Usuario**
```http
GET /api/auth/me
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...
```

### 5. **Logout**
```http
POST /api/auth/logout
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...
```

## 🔒 Seguridad Implementada

### ✅ Características de Seguridad

1. **Tokens JWT sin estado** - No se almacenan sesiones en servidor
2. **Encriptación BCrypt** - Para contraseñas (strength 12)
3. **CORS configurado** - Para integración con frontend
4. **Validación de tokens** - En cada request protegida
5. **Manejo de errores** - Sin exposición de información sensible
6. **Logging completo** - Para auditoría y debugging

### 🔐 Estructura del Token JWT

```json
{
  "alg": "HS512",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "sub": "juan@example.com",
  "userId": 1,
  "role": "BUYER",
  "name": "Juan",
  "iat": 1642942200,
  "exp": 1643028600
}
```

## 🧪 Pruebas con Postman

### 1. **Registro**
1. Crear nueva request POST a `http://localhost:8080/api/auth/register`
2. Headers: `Content-Type: application/json`
3. Body: JSON con datos del usuario

### 2. **Login**
1. Crear nueva request POST a `http://localhost:8080/api/auth/login`
2. Headers: `Content-Type: application/json`
3. Body: JSON con email y password

### 3. **Requests Protegidas**
1. Crear request GET/POST/PUT/DELETE a cualquier endpoint protegido
2. Headers: `Authorization: Bearer {token_obtenido_en_login}`

## 📝 Ejemplos de Uso en Frontend

### JavaScript (Fetch API)
```javascript
// Login
const login = async (email, password) => {
    const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (response.ok) {
        localStorage.setItem('token', data.access_token);
        return data;
    }
    throw new Error(data.message);
};

// Request con token
const apiCall = async (endpoint, options = {}) => {
    const token = localStorage.getItem('token');

    const response = await fetch(endpoint, {
        ...options,
        headers: {
            ...options.headers,
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
        },
    });

    return response;
};
```

## ⚠️ Consideraciones de Producción

### 🔧 Recomendaciones

1. **Secret JWT**: Usar una clave secreta más larga y almacenarla en variables de entorno
2. **Expiración**: Considerar tokens más cortos (15-60 minutos) con refresh tokens
3. **HTTPS**: Siempre usar HTTPS en producción
4. **Rate Limiting**: Implementar límites de requests
5. **CORS**: Configurar orígenes específicos en producción

### 🛡️ Mejoras Futuras

1. **Refresh Tokens**: Para mantener sesiones por más tiempo
2. **Blacklist de Tokens**: Para invalidar tokens comprometidos
3. **2FA**: Autenticación de dos factores
4. **Audit Logging**: Logs más detallados para seguridad
5. **Redis**: Para cache y blacklist de tokens

## 🚨 Manejo de Errores

### Códigos de Estado HTTP

- `200` - Operación exitosa
- `201` - Recurso creado
- `400` - Datos de entrada inválidos
- `401` - Credenciales incorrectas o token inválido
- `409` - Email o ID ya existe
- `500` - Error interno del servidor

### Mensajes de Error

Los errores son informativos pero no exponen información sensible:
```json
{
    "message": "Email o contraseña incorrectos",
    "timestamp": "2025-01-23T12:30:00"
}
```

## 🎯 Próximos Pasos

1. **Probar la implementación** con Postman o herramientas similares
2. **Crear endpoints protegidos** para tu lógica de negocio
3. **Implementar autorización por roles** en tus controladores
4. **Agregar validación de email** para activar cuentas
5. **Configurar logging** apropiado para producción

¡Tu sistema JWT está listo para usar! 🚀
