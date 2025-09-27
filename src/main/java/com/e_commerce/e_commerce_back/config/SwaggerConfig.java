package com.e_commerce.e_commerce_back.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Configuración de Swagger/OpenAPI para la documentación de la API
 * Proporciona una interfaz web interactiva para probar los endpoints
 */
@Configuration
public class SwaggerConfig {

    @Value("${server.port:8080}")
    private String serverPort;

    @Value("${spring.application.name:E-Commerce Backend}")
    private String applicationName;

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(apiInfo())
                .servers(List.of(
                        new Server()
                                .url("http://localhost:" + serverPort)
                                .description("Servidor de desarrollo local"),
                        new Server()
                                .url("https://api.tudominio.com")
                                .description("Servidor de producción")
                ))
                .addSecurityItem(new SecurityRequirement().addList("Bearer Authentication"))
                .components(new io.swagger.v3.oas.models.Components()
                        .addSecuritySchemes("Bearer Authentication", createAPIKeyScheme()));
    }

    /**
     * Información general de la API
     */
    private Info apiInfo() {
        return new Info()
                .title("E-Commerce Backend API")
                .description("""
                        ## API REST para sistema de E-Commerce de zapatos
                        
                        Esta API proporciona todas las funcionalidades necesarias para un sistema de comercio electrónico completo:
                        
                        ### 🔐 Autenticación y Usuarios
                        - Registro de usuarios con verificación por email
                        - Login con JWT tokens
                        - Gestión de perfiles de usuario
                        - Sistema de roles y permisos
                        
                        ### 👟 Productos y Catálogo
                        - Gestión completa de productos (zapatos)
                        - Categorías jerárquicas
                        - Tallas y control de inventario
                        - Imágenes y galerías de productos
                        
                        ### 🛒 Compras y Pedidos
                        - Carrito de compras
                        - Proceso de checkout
                        - Gestión de pedidos
                        - Historial de compras
                        
                        ### 💳 Pagos y Promociones
                        - Múltiples métodos de pago
                        - Sistema de cupones y descuentos
                        - Promociones especiales
                        
                        ### ⭐ Interacción Social
                        - Sistema de reseñas y calificaciones
                        - Listas de deseos
                        - Productos favoritos
                        
                        ### 📧 Notificaciones
                        - Notificaciones por email
                        - Notificaciones push
                        - Alertas de precio y stock
                        
                        ---
                        
                        ### 🔑 Autenticación
                        Para usar los endpoints protegidos, incluye el token JWT en el header:
                        ```
                        Authorization: Bearer <tu_token_jwt>
                        ```
                        
                        ### 📝 Notas de Desarrollo
                        - Todos los endpoints retornan JSON
                        - Los errores siguen el estándar HTTP
                        - Paginación disponible en endpoints de listado
                        - Validación completa de datos de entrada
                        """)
                .version("1.0.0")
                .contact(new Contact()
                        .name("Equipo de Desarrollo")
                        .email("dev@ecommerce.com")
                        .url("https://github.com/tu-usuario/e-commerce-backend"))
                .license(new License()
                        .name("MIT License")
                        .url("https://opensource.org/licenses/MIT"));
    }

    /**
     * Configuración del esquema de autenticación JWT
     */
    private SecurityScheme createAPIKeyScheme() {
        return new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .bearerFormat("JWT")
                .scheme("bearer")
                .description("Ingresa tu token JWT obtenido del endpoint de login")
                .name("Authorization");
    }
}
