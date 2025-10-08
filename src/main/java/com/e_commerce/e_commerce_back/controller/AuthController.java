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

    // ============================================================================
    // REGISTRO Y ACTIVACIÓN
    // ============================================================================

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
        log.info("Intento de activación de cuenta con código");

        try {
            AuthResponseDTO response = authService.activateAccount(activateAccountDTO);
            log.info("Activación de cuenta procesada exitosamente");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error en activación de cuenta: {}", e.getMessage());
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

    // ============================================================================
    // LOGIN Y LOGOUT
    // ============================================================================

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

    // ============================================================================
    // DESBLOQUEO DE CUENTA
    // ============================================================================

    /**
     * Endpoint para solicitar desbloqueo inmediato de cuenta
     */
    @PostMapping("/request-unlock")
    @Operation(summary = "Solicitar desbloqueo de cuenta", description = "Envía un código de desbloqueo al email del usuario bloqueado")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Código de desbloqueo enviado"),
            @ApiResponse(responseCode = "400", description = "Cuenta no bloqueada o demasiadas solicitudes")
    })
    public ResponseEntity<AuthResponseDTO> requestUnlock(
            @Valid @RequestBody RequestImmediateUnlockDTO requestImmediateUnlockDTO) {
        log.info("Solicitud de desbloqueo para email: {}", requestImmediateUnlockDTO.email());

        try {
            AuthResponseDTO response = authService.requestImmediateUnlock(requestImmediateUnlockDTO);
            log.info("Solicitud de desbloqueo procesada para email: {}", requestImmediateUnlockDTO.email());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error en solicitud de desbloqueo para email: {}, error: {}",
                    requestImmediateUnlockDTO.email(), e.getMessage());
            throw e;
        }
    }

    /**
     * Endpoint para verificar código de desbloqueo
     */
    @PostMapping("/verify-unlock-code")
    @Operation(summary = "Verificar código de desbloqueo", description = "Verifica el código de desbloqueo y desbloquea la cuenta")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Cuenta desbloqueada exitosamente"),
            @ApiResponse(responseCode = "400", description = "Código inválido o expirado"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
    })
    public ResponseEntity<AuthResponseDTO> verifyUnlockCode(
            @Valid @RequestBody VerifyUnlockCodeDTO verifyUnlockCodeDTO) {
        log.info("Intento de verificación de código de desbloqueo");

        try {
            AuthResponseDTO response = authService.verifyUnlockCode(verifyUnlockCodeDTO);
            log.info("Verificación de código de desbloqueo procesada exitosamente");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error verificando código de desbloqueo: {}", e.getMessage());
            throw e;
        }
    }

    // ============================================================================
    // RECUPERACIÓN DE CONTRASEÑA
    // ============================================================================

    /**
     * Endpoint para solicitar reseteo de contraseña
     */
    @PostMapping("/forgot-password")
    @Operation(summary = "Olvidé mi contraseña", description = "Envía un código de reseteo de contraseña al email del usuario")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Código de reseteo enviado"),
            @ApiResponse(responseCode = "400", description = "Datos inválidos")
    })
    public ResponseEntity<AuthResponseDTO> forgotPassword(@Valid @RequestBody ForgotPasswordDTO forgotPasswordDTO) {
        log.info("Solicitud de reseteo de contraseña para email: {}", forgotPasswordDTO.email());

        try {
            AuthResponseDTO response = authService.forgotPassword(forgotPasswordDTO);
            log.info("Solicitud de reseteo procesada para email: {}", forgotPasswordDTO.email());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error en solicitud de reseteo para email: {}, error: {}",
                    forgotPasswordDTO.email(), e.getMessage());
            throw e;
        }
    }

    /**
     * Endpoint para resetear contraseña con código
     */
    @PostMapping("/reset-password")
    @Operation(summary = "Resetear contraseña", description = "Resetea la contraseña usando el código de verificación")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Contraseña reseteada exitosamente"),
            @ApiResponse(responseCode = "400", description = "Código inválido o contraseñas no coinciden"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
    })
    public ResponseEntity<AuthResponseDTO> resetPassword(@Valid @RequestBody ResetPasswordDTO resetPasswordDTO) {
        log.info("Intento de reseteo de contraseña con código");

        try {
            AuthResponseDTO response = authService.resetPassword(resetPasswordDTO);
            log.info("Reseteo de contraseña procesado exitosamente");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error en reseteo de contraseña: {}", e.getMessage());
            throw e;
        }
    }

    // ============================================================================
    // GESTIÓN DE CONTRASEÑA Y EMAIL
    // ============================================================================

    /**
     * Endpoint para cambiar contraseña (usuario autenticado)
     */
    @PutMapping("/change-password")
    @Operation(summary = "Cambiar contraseña", description = "Cambia la contraseña del usuario autenticado")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Contraseña cambiada exitosamente"),
            @ApiResponse(responseCode = "400", description = "Contraseña actual incorrecta o contraseñas no coinciden"),
            @ApiResponse(responseCode = "401", description = "No autenticado")
    })
    public ResponseEntity<AuthResponseDTO> changePassword(@Valid @RequestBody ChangePasswordDTO changePasswordDTO) {
        log.info("Solicitud de cambio de contraseña");

        try {
            AuthResponseDTO response = authService.changePassword(changePasswordDTO);
            log.info("Contraseña cambiada exitosamente");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error cambiando contraseña: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Endpoint para cambiar email (usuario autenticado)
     */
    @PutMapping("/change-email")
    @Operation(summary = "Cambiar email", description = "Cambia el email del usuario autenticado")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Email cambiado exitosamente"),
            @ApiResponse(responseCode = "400", description = "Emails no coinciden o contraseña incorrecta"),
            @ApiResponse(responseCode = "401", description = "No autenticado"),
            @ApiResponse(responseCode = "409", description = "Email ya existe")
    })
    public ResponseEntity<AuthResponseDTO> changeEmail(@Valid @RequestBody ChangeEmailDTO changeEmailDTO) {
        log.info("Solicitud de cambio de email");

        try {
            AuthResponseDTO response = authService.changeEmail(changeEmailDTO);
            log.info("Email cambiado exitosamente");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error cambiando email: {}", e.getMessage());
            throw e;
        }
    }

    @PostMapping("/verify-email-change")
    @Operation(summary = "Verificar cambio de email", description = "Verifica el cambio de email del usuario autenticado")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Email verificado exitosamente"),
            @ApiResponse(responseCode = "400", description = "Código de verificación incorrecto o expirado"),
            @ApiResponse(responseCode = "401", description = "No autenticado"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
    })
    public ResponseEntity<AuthResponseDTO> verifyEmailChange(@Valid @RequestBody VerifyEmailChangeDTO verifyEmailChangeDTO) {
        log.info("Solicitud de verificación de cambio de email");

        try {
            AuthResponseDTO response = authService.verifyEmailChange(verifyEmailChangeDTO);
            log.info("Email verificado exitosamente");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error verificando cambio de email: {}", e.getMessage());
            throw e;
        }
    }

    // ============================================================================
    // GESTIÓN DE PERFIL
    // ============================================================================

    /**
     * Endpoint para actualizar información del perfil
     */
    @PutMapping("/update-profile")
    @Operation(summary = "Actualizar perfil", description = "Actualiza la información del perfil del usuario autenticado")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Perfil actualizado exitosamente"),
            @ApiResponse(responseCode = "400", description = "Datos inválidos"),
            @ApiResponse(responseCode = "401", description = "No autenticado")
    })
    public ResponseEntity<AuthResponseDTO> updateProfile(
            @Valid @RequestBody UpdateUserProfileDTO updateUserProfileDTO) {
        log.info("Solicitud de actualización de perfil");

        try {
            AuthResponseDTO response = authService.updateUserInfo(updateUserProfileDTO);
            log.info("Perfil actualizado exitosamente");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error actualizando perfil: {}", e.getMessage());
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

    // ============================================================================
    // VALIDACIÓN Y REFRESH DE TOKENS
    // ============================================================================

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
     * Endpoint para refrescar token JWT
     */
    @PostMapping("/refresh-token")
    @Operation(summary = "Refrescar token", description = "Genera un nuevo access token usando el refresh token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token refrescado exitosamente"),
            @ApiResponse(responseCode = "401", description = "Refresh token inválido o expirado")
    })
    public ResponseEntity<AuthResponseDTO> refreshToken(@Valid @RequestBody RefreshTokenDTO refreshTokenDTO) {
        log.info("Solicitud de refresh token");

        try {
            AuthResponseDTO response = authService.refreshToken(refreshTokenDTO);
            log.info("Token refrescado exitosamente");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error refrescando token: {}", e.getMessage());
            throw e;
        }
    }

}
