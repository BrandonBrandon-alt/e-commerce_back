package com.e_commerce.e_commerce_back.services.implementation;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;

/**
 * Servicio para verificar tokens de Google OAuth2
 */
@Service
@Slf4j
public class GoogleOAuthService {

    @Value("${google.client.id}")
    private String googleClientId;

    /**
     * Verifica el token de ID de Google y extrae la información del usuario
     *
     * @param idToken Token de ID de Google
     * @return Payload del token verificado
     * @throws Exception si el token es inválido
     */
    public GoogleIdToken.Payload verifyGoogleToken(String idToken) throws Exception {
        log.info("Verificando token de Google");

        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
                new NetHttpTransport(),
                new GsonFactory())
                .setAudience(Collections.singletonList(googleClientId))
                .build();

        GoogleIdToken googleIdToken = verifier.verify(idToken);

        if (googleIdToken == null) {
            log.error("Token de Google inválido");
            throw new IllegalArgumentException("Invalid Google ID token");
        }

        GoogleIdToken.Payload payload = googleIdToken.getPayload();
        
        log.info("Token de Google verificado exitosamente para email: {}", payload.getEmail());
        
        return payload;
    }

    /**
     * Extrae el email del payload de Google
     */
    public String getEmail(GoogleIdToken.Payload payload) {
        return payload.getEmail();
    }

    /**
     * Extrae el nombre del payload de Google
     */
    public String getName(GoogleIdToken.Payload payload) {
        return (String) payload.get("name");
    }

    /**
     * Extrae el nombre de pila del payload de Google
     */
    public String getGivenName(GoogleIdToken.Payload payload) {
        return (String) payload.get("given_name");
    }

    /**
     * Extrae el apellido del payload de Google
     */
    public String getFamilyName(GoogleIdToken.Payload payload) {
        return (String) payload.get("family_name");
    }

    /**
     * Extrae la URL de la foto de perfil del payload de Google
     */
    public String getPictureUrl(GoogleIdToken.Payload payload) {
        return (String) payload.get("picture");
    }

    /**
     * Verifica si el email está verificado por Google
     */
    public Boolean isEmailVerified(GoogleIdToken.Payload payload) {
        return payload.getEmailVerified();
    }
}
