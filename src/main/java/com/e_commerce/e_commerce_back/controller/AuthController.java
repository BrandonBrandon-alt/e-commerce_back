package com.e_commerce.e_commerce_back.controller;

import com.e_commerce.e_commerce_back.dto.*;
import com.e_commerce.e_commerce_back.services.interfaces.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controlador para operaciones de autenticación
 * Maneja login, registro y operaciones relacionadas con JWT
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Autenticación", description = "Operaciones de autenticación y autorización")
public class AuthController {

    private final AuthService authService;

    /**
     * Endpoint para login de usuarios
     */
    @PostMapping("/login")
    @Operation(summary = "Iniciar sesión", description = "Autentica un usuario y devuelve un token JWT")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login exitoso"),
            @ApiResponse(responseCode = "401", description = "Credenciales inválidas"),
            @ApiResponse(responseCode = "400", description = "Datos de entrada inválidos")
    })
    public ResponseEntity<AuthResponseDTO> login(@Valid @RequestBody LoginDTO loginDTO) {
        log.info("Intento de login para email: {}", loginDTO.email());
        
        try {
            AuthResponseDTO response = authService.login(loginDTO);
            log.info("Login exitoso para email: {}", loginDTO.email());
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Error en login para email: {}, error: {}", loginDTO.email(), e.getMessage());
            throw e;
        }
    }

    /**
     * Endpoint para registro de usuarios
     */
    @PostMapping("/register")
    @Operation(summary = "Registrar usuario", description = "Registra un nuevo usuario en el sistema")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Usuario registrado exitosamente"),
            @ApiResponse(responseCode = "409", description = "Email o número de identificación ya existe"),
            @ApiResponse(responseCode = "400", description = "Datos de entrada inválidos")
    })
    public ResponseEntity<AuthResponseDTO> register(@Valid @RequestBody RegisterUserDTO createUserDTO) {
        log.info("Intento de registro para email: {}", createUserDTO.email());
        
        try {
            AuthResponseDTO response = authService.register(createUserDTO);
            log.info("Registro exitoso para email: {}", createUserDTO.email());
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
            
        } catch (Exception e) {
            log.error("Error en registro para email: {}, error: {}", createUserDTO.email(), e.getMessage());
            throw e;
        }
    }

    /**
     * Endpoint para validar token JWT
     */
    @PostMapping("/validate-token")
    @Operation(summary = "Validar token", description = "Valida si un token JWT es válido y activo")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token válido"),
            @ApiResponse(responseCode = "401", description = "Token inválido o expirado")
    })
    public ResponseEntity<TokenValidationDTO> validateToken(@RequestHeader("Authorization") String authHeader) {
        log.debug("Validando token JWT");
        
        try {
            TokenValidationDTO response = authService.validateToken(authHeader);
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Error validando token: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Endpoint para obtener información del usuario autenticado
     */
    @GetMapping("/me")
    @Operation(summary = "Información del usuario", description = "Obtiene información del usuario autenticado")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Información obtenida exitosamente"),
            @ApiResponse(responseCode = "401", description = "No autenticado")
    })
    public ResponseEntity<UserInfoDTO> getCurrentUser() {
        log.debug("Obteniendo información del usuario autenticado");
        
        try {
            UserInfoDTO userInfo = authService.getCurrentUserInfo();
            return ResponseEntity.ok(userInfo);
            
        } catch (Exception e) {
            log.error("Error obteniendo información del usuario: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Endpoint para logout (invalidar token)
     */
    @PostMapping("/logout")
    @Operation(summary = "Cerrar sesión", description = "Invalida el token JWT actual")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Logout exitoso"),
            @ApiResponse(responseCode = "401", description = "No autenticado")
    })
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authHeader) {
        log.info("Cerrando sesión");
        
        try {
            authService.logout(authHeader);
            return ResponseEntity.ok("Sesión cerrada exitosamente");
            
        } catch (Exception e) {
            log.error("Error en logout: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Endpoint para activar cuenta con código de verificación
     */
    @PostMapping("/activate-account")
    @Operation(summary = "Activar cuenta", description = "Activa una cuenta de usuario usando el código de activación enviado por email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Cuenta activada exitosamente"),
            @ApiResponse(responseCode = "400", description = "Código inválido o expirado"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
    })
    public ResponseEntity<AuthResponseDTO> activateAccount(@Valid @RequestBody ActivateAccountDTO activateAccountDTO) {
        log.info("Intento de activación de cuenta para email: {}", activateAccountDTO.email());
        
        try {
            AuthResponseDTO response = authService.activateAccount(activateAccountDTO);
            log.info("Activación procesada para email: {}", activateAccountDTO.email());
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Error en activación para email: {}, error: {}", 
                     activateAccountDTO.email(), e.getMessage());
            throw e;
        }
    }

    /**
     * Endpoint para reenviar código de activación
     */
    @PostMapping("/resend-activation-code")
    @Operation(summary = "Reenviar código de activación", description = "Reenvía el código de activación a un usuario")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Código reenviado exitosamente"),
            @ApiResponse(responseCode = "400", description = "Cuenta ya activada"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
    })
    public ResponseEntity<AuthResponseDTO> resendActivationCode(@Valid @RequestBody ResendActivationCodeDTO resendDTO) {
        log.info("Intento de reenvío de código para email: {}", resendDTO.email());
        
        try {
            AuthResponseDTO response = authService.resendActivationCode(resendDTO.email());
            log.info("Reenvío procesado para email: {}", resendDTO.email());
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Error en reenvío para email: {}, error: {}", 
                     resendDTO.email(), e.getMessage());
            throw e;
        }
    }
}
