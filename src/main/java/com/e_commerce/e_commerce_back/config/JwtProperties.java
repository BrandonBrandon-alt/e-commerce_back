package com.e_commerce.e_commerce_back.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

/**
 * Configuración de propiedades JWT personalizadas
 * Estas propiedades se mapean desde application.properties con el prefijo "app.jwt"
 */
@Component
@Getter
@Setter
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {
    
    /**
     * Clave secreta para firmar los tokens JWT
     */
    private String secret;
    
    /**
     * Tiempo de expiración del token de acceso en milisegundos
     * Por defecto: 1 hora (3600000 ms)
     */
    private long expiration = 3600000L;
    
    /**
     * Tiempo de expiración del refresh token en milisegundos
     * Por defecto: 24 horas (86400000 ms)
     */
    private long refreshExpiration = 86400000L;
    
    // Constructors
    public JwtProperties() {}
    
    public JwtProperties(String secret, long expiration, long refreshExpiration) {
        this.secret = secret;
        this.expiration = expiration;
        this.refreshExpiration = refreshExpiration;
    }
    
    // Getters and Setters
    public String getSecret() {
        return secret;
    }
    
    public void setSecret(String secret) {
        this.secret = secret;
    }
    
    public long getExpiration() {
        return expiration;
    }
    
    public void setExpiration(long expiration) {
        this.expiration = expiration;
    }
    
    public long getRefreshExpiration() {
        return refreshExpiration;
    }
    
    public void setRefreshExpiration(long refreshExpiration) {
        this.refreshExpiration = refreshExpiration;
    }
    
    /**
     * Obtiene el tiempo de expiración en segundos
     * @return tiempo de expiración en segundos
     */
    public long getExpirationInSeconds() {
        return expiration / 1000;
    }
    
    /**
     * Obtiene el tiempo de expiración del refresh token en segundos
     * @return tiempo de expiración del refresh token en segundos
     */
    public long getRefreshExpirationInSeconds() {
        return refreshExpiration / 1000;
    }
    
    @Override
    public String toString() {
        return "JwtProperties{" +
                "secret='[PROTECTED]'" +
                ", expiration=" + expiration +
                ", refreshExpiration=" + refreshExpiration +
                '}';
    }
}
