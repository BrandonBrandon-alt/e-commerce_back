package com.e_commerce.e_commerce_back.config;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettucePoolingClientConfiguration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;

@Configuration
@Slf4j
public class RedisConfig {

    @Value("${spring.data.redis.host}")
    private String redisHost;

    @Value("${spring.data.redis.port}")
    private int redisPort;

    @Value("${spring.data.redis.database}")
    private int redisDatabase;

    @Value("${spring.data.redis.timeout:5000ms}")
    private String redisTimeout;

    @Value("${spring.data.redis.lettuce.pool.max-active:10}")
    private int maxActive;

    @Value("${spring.data.redis.lettuce.pool.max-idle:5}")
    private int maxIdle;

    @Value("${spring.data.redis.lettuce.pool.min-idle:2}")
    private int minIdle;

    /**
     * configuracion del servicio de Redis
     * @return
     */
    @Bean
    public LettuceConnectionFactory redisConnectionFactory() {
        log.info("Configurando conexión Redis: {}:{} database:{}", redisHost, redisPort, redisDatabase);
        
        // Configuración del servidor Redis
        RedisStandaloneConfiguration serverConfig = new RedisStandaloneConfiguration();
        serverConfig.setHostName(redisHost);
        serverConfig.setPort(redisPort);
        serverConfig.setDatabase(redisDatabase);
        
        // Configuración del cliente Lettuce con pool
        LettuceClientConfiguration clientConfig = LettucePoolingClientConfiguration.builder()
                .commandTimeout(Duration.ofMillis(5000))
                .build();
        
        LettuceConnectionFactory factory = new LettuceConnectionFactory(serverConfig, clientConfig);
        factory.setValidateConnection(true);
        factory.setShareNativeConnection(true);
        
        log.info("LettuceConnectionFactory configurado exitosamente");
        return factory;
    }

    /**
     * RedisTemplate principal para JwtSessionService (maneja objetos)
     */
    @Bean
    @Primary
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        log.info("Configurando RedisTemplate<String, Object> principal para JwtSessionService");
        
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        
        // Configurar ObjectMapper con soporte para Java 8 Time API
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        objectMapper.registerModule(new JavaTimeModule()); // Soporte para Instant, LocalDateTime, etc.
        objectMapper.activateDefaultTyping(
            LaissezFaireSubTypeValidator.instance,
            ObjectMapper.DefaultTyping.NON_FINAL,
            JsonTypeInfo.As.PROPERTY
        );
        
        // Configurar Jackson serializer para objetos
        Jackson2JsonRedisSerializer<Object> jackson2JsonRedisSerializer = 
            new Jackson2JsonRedisSerializer<>(objectMapper, Object.class);
        
        // Configurar serializadores
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(jackson2JsonRedisSerializer);
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(jackson2JsonRedisSerializer);
        
        template.setEnableTransactionSupport(true);
        template.afterPropertiesSet();
        
        log.info("RedisTemplate<String, Object> configurado exitosamente");
        return template;
    }

    /**
     * Bean secundario para operaciones con strings simples
     * Renombrado para evitar conflicto con el bean de Spring Boot
     * IMPORTANTE: No habilitar transacciones para operaciones atómicas como INCR
     */
    @Bean("customStringRedisTemplate")
    public RedisTemplate<String, String> customStringRedisTemplate(RedisConnectionFactory connectionFactory) {
        log.info("Configurando RedisTemplate<String, String> personalizado para strings simples");
        
        RedisTemplate<String, String> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        template.setKeySerializer(stringSerializer);
        template.setValueSerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);
        template.setHashValueSerializer(stringSerializer);
        
        // NO habilitar transacciones para operaciones atómicas
        template.setEnableTransactionSupport(false);
        template.afterPropertiesSet();
        
        log.info("RedisTemplate<String, String> personalizado configurado exitosamente");
        return template;
    }
}