package com.e_commerce.e_commerce_back.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Configuración de Redis para el proyecto e-commerce
 * Configura RedisTemplate para manejo de tokens temporales
 * 
 * Compatible con Docker Compose Redis:
 * - Host: localhost (cuando la app corre fuera del container)
 * - Puerto: 6379 (puerto estándar)
 * - Database: 0 (database por defecto)
 */
@Configuration
@Slf4j
public class RedisConfig {

    @Value("${spring.data.redis.host:localhost}")
    private String redisHost;

    @Value("${spring.data.redis.port:6379}")
    private int redisPort;

    @Value("${spring.data.redis.database:0}")
    private int redisDatabase;

    @Value("${spring.data.redis.password:}")
    private String redisPassword;

    /**
     * Configuración de la conexión Redis usando Lettuce
     * Lettuce es el cliente por defecto de Spring Boot y es thread-safe
     * Compatible con tu Redis Docker Compose
     */
    @Bean
    public LettuceConnectionFactory redisConnectionFactory() {
        log.info("Configurando conexión Redis: {}:{} database:{}", redisHost, redisPort, redisDatabase);
        
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();
        config.setHostName(redisHost);
        config.setPort(redisPort);
        config.setDatabase(redisDatabase);
        
        // Tu Redis Docker no tiene password configurado, pero dejamos la opción
        if (redisPassword != null && !redisPassword.trim().isEmpty()) {
            config.setPassword(redisPassword);
            log.info("Redis password configurado");
        }
        
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config);
        
        // Validar conexión al inicializar
        factory.setValidateConnection(true);
        
        return factory;
    }

    /**
     * RedisTemplate configurado para String keys y String values
     * Optimizado para el TokenRedisService que maneja códigos de activación/reset
     */
    @Bean
    public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory connectionFactory) {
        log.info("Configurando RedisTemplate<String, String> para TokenRedisService");
        
        RedisTemplate<String, String> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        
        // Usar StringRedisSerializer para keys y values
        // Esto hace que los datos sean legibles en Redis Commander
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        
        template.setKeySerializer(stringSerializer);
        template.setValueSerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);
        template.setHashValueSerializer(stringSerializer);
        
        // Habilitar transacciones si es necesario
        template.setEnableTransactionSupport(true);
        
        // Inicializar el template
        template.afterPropertiesSet();
        
        log.info("RedisTemplate configurado exitosamente");
        return template;
    }

    /**
     * Bean adicional para operaciones más complejas (opcional)
     * RedisTemplate con serialización JSON para objetos complejos
     */
    @Bean("jsonRedisTemplate")
    public RedisTemplate<String, Object> jsonRedisTemplate(RedisConnectionFactory connectionFactory) {
        log.info("Configurando RedisTemplate<String, Object> para objetos JSON");
        
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        
        // String para keys, JSON para values
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(new org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer());
        
        template.setEnableTransactionSupport(true);
        template.afterPropertiesSet();
        
        return template;
    }
}
