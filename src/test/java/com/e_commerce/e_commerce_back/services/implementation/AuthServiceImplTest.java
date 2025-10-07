package com.e_commerce.e_commerce_back.services.implementation;

import com.e_commerce.e_commerce_back.dto.AuthResponseDTO;
import com.e_commerce.e_commerce_back.dto.ForgotPasswordDTO;
import com.e_commerce.e_commerce_back.dto.ActivateAccountDTO;
import com.e_commerce.e_commerce_back.dto.RegisterUserDTO;
import com.e_commerce.e_commerce_back.dto.TokenValidationDTO;
import com.e_commerce.e_commerce_back.dto.LoginDTO;
import com.e_commerce.e_commerce_back.dto.RequestImmediateUnlockDTO;
import com.e_commerce.e_commerce_back.dto.VerifyUnlockCodeDTO;
import com.e_commerce.e_commerce_back.entity.User;
import com.e_commerce.e_commerce_back.repository.UserRepository;
import com.e_commerce.e_commerce_back.security.JwtUtil;
import com.e_commerce.e_commerce_back.services.interfaces.EmailService;
import com.e_commerce.enums.EnumRole;
import com.e_commerce.enums.EnumStatus;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDate;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    AuthenticationManager authenticationManager;
    @Mock
    UserRepository userRepository;
    @Mock
    PasswordEncoder passwordEncoder;
    @Mock
    JwtUtil jwtUtil;
    @Mock
    EmailService emailService;
    @Mock
    TokenRedisService tokenRedisService;
    @Mock
    JwtSessionService jwtSessionService;
    @Mock
    AccountLockoutRedisService accountLockoutRedisService;

    @InjectMocks
    AuthServiceImpl authService;

    @BeforeEach
    void setup() {
        ReflectionTestUtils.setField(authService, "jwtExpiration", 3600000L);
        ReflectionTestUtils.setField(authService, "maxFailedAttempts", 5);
        ReflectionTestUtils.setField(authService, "lockoutDurationMinutes", 15);
        // Evitar UnnecessaryStubbing en tests que no usan este stub
        lenient().when(passwordEncoder.encode(any())).thenAnswer(inv -> "hash_" + inv.getArgument(0));
    }

    private User createTestUser() {
        return User.builder()
                .id(1L)
                .idNumber("1001277000")
                .name("Test")
                .lastName("User")
                .email("user@test.com")
                .phoneNumber("3000000000")
                .password("hash_Password123")
                .role(EnumRole.USER)
                .status(EnumStatus.INACTIVE)
                .emailVerified(false)
                .build();
    }

    @Test
    void register_success_sendsActivationEmail() {
        RegisterUserDTO dto = new RegisterUserDTO(
                "1001277000",
                "Test",
                "User",
                "user@test.com",
                "3000000000",
                "Password123",
                LocalDate.of(2000, 1, 1),
                true);

        when(userRepository.existsByEmail("user@test.com")).thenReturn(false);
        when(userRepository.findByIdNumber("1001277000")).thenReturn(Optional.empty());

        User saved = User.builder()
                .id(1L)
                .idNumber("1001277000")
                .name("Test")
                .lastName("User")
                .email("user@test.com")
                .phoneNumber("3000000000")
                .password("hash_Password123")
                .role(EnumRole.USER)
                .status(EnumStatus.INACTIVE)
                .emailVerified(false)
                .build();

        when(userRepository.save(any(User.class))).thenReturn(saved);
        when(tokenRedisService.generateAndStoreActivationCode(1L)).thenReturn("123456");

        AuthResponseDTO res = authService.register(dto);

        assertNotNull(res);
        assertNotNull(res.getMessage());
        verify(emailService, atLeastOnce()).sendActivationEmail(any(User.class), eq("123456"));
        verify(userRepository).save(any(User.class));
    }

    @Test
    void activateAccount_success_updatesUserAndSendsWelcome() {
        when(tokenRedisService.verifyAndConsumeActivationCode("123456")).thenReturn(5L);

        User user = User.builder()
                .id(5L)
                .email("user@test.com")
                .status(EnumStatus.INACTIVE)
                .emailVerified(false)
                .build();

        when(userRepository.findById(5L)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        AuthResponseDTO res = authService.activateAccount(new ActivateAccountDTO("123456"));

        assertNotNull(res);
        assertEquals("¡Cuenta activada exitosamente! Ya puedes iniciar sesión.", res.getMessage());
        verify(userRepository).save(any(User.class));
        verify(emailService, atLeastOnce()).sendWelcomeEmail(any(User.class));
    }

    @Test
    void validateToken_success_whenSessionValidAndUserEnabled() {
        String token = "token-xyz";
        String header = "Bearer " + token;

        JwtSessionService.SessionMetadata meta = JwtSessionService.SessionMetadata.builder()
                .userId(1L)
                .email("user@test.com")
                .sessionId("sid-1")
                .token(token)
                .tokenType("ACCESS")
                .userAgent("JUnit")
                .ipAddress("127.0.0.1")
                .createdAt(java.time.Instant.now())
                .expiresAt(java.time.Instant.now().plusSeconds(300))
                .build();
        JwtSessionService.SessionValidation validation = JwtSessionService.SessionValidation.valid(meta);
        when(jwtSessionService.validateAccessToken(token)).thenReturn(validation);

        when(jwtUtil.extractUsername(token)).thenReturn("user@test.com");
        when(jwtUtil.getTokenRemainingTime(token)).thenReturn(20000L);

        User user = User.builder()
                .id(1L)
                .email("user@test.com")
                .status(EnumStatus.ACTIVE)
                .emailVerified(true)
                .build();
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));

        TokenValidationDTO res = authService.validateToken(header);
        assertNotNull(res);
        assertTrue(res.isValid());
        assertEquals("user@test.com", res.getUsername());
    }

    @Test
    void validateToken_invalid_whenHeaderMissing() {
        TokenValidationDTO res = authService.validateToken(null);
        assertFalse(res.isValid());
    }

    @Test
    void getCurrentUserInfo_success_whenAuthenticated() {
        SecurityContext sc = mock(SecurityContext.class);
        SecurityContextHolder.setContext(sc);
        Authentication auth = mock(Authentication.class);
        when(sc.getAuthentication()).thenReturn(auth);
        when(auth.isAuthenticated()).thenReturn(true);
        when(auth.getName()).thenReturn("user@test.com");

        User user = User.builder()
                .id(1L)
                .email("user@test.com")
                .name("Nombre")
                .lastName("Apellido")
                .status(EnumStatus.ACTIVE)
                .emailVerified(true)
                .build();
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));

        var dto = authService.getCurrentUserInfo();
        assertNotNull(dto);
        assertEquals("user@test.com", dto.getEmail());
        assertEquals("Nombre", dto.getName());
    }

    @Test
    void getCurrentUserInfo_throws_whenNotAuthenticated() {
        SecurityContext sc = mock(SecurityContext.class);
        SecurityContextHolder.setContext(sc);
        when(sc.getAuthentication()).thenReturn(null);

        assertThrows(RuntimeException.class, () -> authService.getCurrentUserInfo());
    }

    @Test
    void logout_success_withValidToken_closesSession() {
        // Given
        String authHeader = "Bearer valid-token";
        String sessionId = "session-123";

        when(jwtSessionService.findSessionIdByAccessToken("valid-token")).thenReturn(sessionId);
        doNothing().when(jwtSessionService).closeSession(sessionId);

        try (MockedStatic<SecurityContextHolder> mockedStatic = mockStatic(SecurityContextHolder.class)) {
            // When
            authService.logout(authHeader);

            // Then
            verify(jwtSessionService).findSessionIdByAccessToken("valid-token");
            verify(jwtSessionService).closeSession(sessionId);
            mockedStatic.verify(SecurityContextHolder::clearContext);
        }
    }

    @Test
    void logout_success_withValidTokenButNoSession_blacklistsToken() {
        // Given
        String authHeader = "Bearer valid-token";

        when(jwtSessionService.findSessionIdByAccessToken("valid-token")).thenReturn(null);
        doNothing().when(jwtSessionService).blacklistAccessToken("valid-token");

        try (MockedStatic<SecurityContextHolder> mockedStatic = mockStatic(SecurityContextHolder.class)) {
            // When
            authService.logout(authHeader);

            // Then
            verify(jwtSessionService).findSessionIdByAccessToken("valid-token");
            verify(jwtSessionService).blacklistAccessToken("valid-token");
            mockedStatic.verify(SecurityContextHolder::clearContext);
        }
    }

    @Test
    void logout_success_withInvalidToken_blacklistsToken() {
        // Given
        String authHeader = "Bearer invalid-token";

        when(jwtSessionService.findSessionIdByAccessToken("invalid-token"))
                .thenThrow(new RuntimeException("Token inválido"));
        doNothing().when(jwtSessionService).blacklistAccessToken("invalid-token");

        try (MockedStatic<SecurityContextHolder> mockedStatic = mockStatic(SecurityContextHolder.class)) {
            // When
            authService.logout(authHeader);

            // Then
            verify(jwtSessionService).findSessionIdByAccessToken("invalid-token");
            verify(jwtSessionService).blacklistAccessToken("invalid-token");
            mockedStatic.verify(SecurityContextHolder::clearContext);
        }
    }

    @Test
    void logout_success_withoutBearerPrefix_doesNothing() {
        // Given
        String authHeader = "InvalidHeader";

        try (MockedStatic<SecurityContextHolder> mockedStatic = mockStatic(SecurityContextHolder.class)) {
            // When
            authService.logout(authHeader);

            // Then
            verify(jwtSessionService, never()).findSessionIdByAccessToken(any());
            verify(jwtSessionService, never()).closeSession(any());
            verify(jwtSessionService, never()).blacklistAccessToken(any());
            mockedStatic.verifyNoInteractions();
        }
    }

    @Test
    void logout_success_withNullHeader_doesNothing() {
        // Given
        String authHeader = null;

        try (MockedStatic<SecurityContextHolder> mockedStatic = mockStatic(SecurityContextHolder.class)) {
            // When
            authService.logout(authHeader);

            // Then
            verify(jwtSessionService, never()).findSessionIdByAccessToken(any());
            verify(jwtSessionService, never()).closeSession(any());
            verify(jwtSessionService, never()).blacklistAccessToken(any());
            mockedStatic.verifyNoInteractions();
        }
    }

    @Test
    void logout_success_withEmptyHeader_doesNothing() {
        // Given
        String authHeader = "";

        try (MockedStatic<SecurityContextHolder> mockedStatic = mockStatic(SecurityContextHolder.class)) {
            // When
            authService.logout(authHeader);

            // Then
            verify(jwtSessionService, never()).findSessionIdByAccessToken(any());
            verify(jwtSessionService, never()).closeSession(any());
            verify(jwtSessionService, never()).blacklistAccessToken(any());
            mockedStatic.verifyNoInteractions();
        }
    }

    @Test
    void logout_success_withBearerButNoToken_blacklistsEmptyToken() {
        // Given
        String authHeader = "Bearer ";

        when(jwtSessionService.findSessionIdByAccessToken("")).thenReturn(null);
        doNothing().when(jwtSessionService).blacklistAccessToken("");

        try (MockedStatic<SecurityContextHolder> mockedStatic = mockStatic(SecurityContextHolder.class)) {
            // When
            authService.logout(authHeader);

            // Then
            verify(jwtSessionService).findSessionIdByAccessToken("");
            verify(jwtSessionService).blacklistAccessToken("");
            mockedStatic.verify(SecurityContextHolder::clearContext);
        }
    }

    @Test
    void resendActivationCode_success_returnsSuccessResponse() {
        // Given
        String email = "user@test.com";
        User user = createTestUser();
        // Usuario no activado (status INACTIVE y emailVerified false por defecto)
        String activationCode = "123456";

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(tokenRedisService.canRequestToken(user.getId(), "activation")).thenReturn(true);
        when(tokenRedisService.generateAndStoreActivationCode(user.getId())).thenReturn(activationCode);
        doNothing().when(emailService).sendActivationEmail(user, activationCode);

        // When
        AuthResponseDTO result = authService.resendActivationCode(email);

        // Then
        assertNotNull(result);
        assertNotNull(result.getMessage());
        assertEquals("Nuevo código de activación enviado. Revisa tu email.", result.getMessage());
        verify(userRepository).findByEmail(email);
        verify(tokenRedisService).canRequestToken(user.getId(), "activation");
        verify(tokenRedisService).generateAndStoreActivationCode(user.getId());
        verify(emailService).sendActivationEmail(user, activationCode);
    }

    @Test
    void resendActivationCode_userNotFound_returnsErrorResponse() {
        // Given
        String email = "nonexistent@test.com";

        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        // When
        AuthResponseDTO result = authService.resendActivationCode(email);

        // Then
        assertNotNull(result);
        assertNotNull(result.getMessage());
        assertEquals("Usuario no encontrado", result.getMessage());
        verify(userRepository).findByEmail(email);
        verify(tokenRedisService, never()).canRequestToken(any(), any());
        verify(tokenRedisService, never()).generateAndStoreActivationCode(any());
        verify(emailService, never()).sendActivationEmail(any(), any());
    }

    @Test
    void resendActivationCode_userAlreadyActivated_returnsErrorResponse() {
        // Given
        String email = "user@test.com";
        User user = createTestUser();
        user.setStatus(EnumStatus.ACTIVE);
        user.setEmailVerified(true); // Usuario ya activado

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        // When
        AuthResponseDTO result = authService.resendActivationCode(email);

        // Then
        assertNotNull(result);
        assertNotNull(result.getMessage());
        assertEquals("La cuenta ya está activada", result.getMessage());
        verify(userRepository).findByEmail(email);
        verify(tokenRedisService, never()).canRequestToken(any(), any());
        verify(tokenRedisService, never()).generateAndStoreActivationCode(any());
        verify(emailService, never()).sendActivationEmail(any(), any());
    }

    @Test
    void resendActivationCode_rateLimitExceeded_returnsErrorResponse() {
        // Given
        String email = "user@test.com";
        User user = createTestUser();
        // Usuario no activado (status INACTIVE y emailVerified false por defecto)

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(tokenRedisService.canRequestToken(user.getId(), "activation")).thenReturn(false);

        // When
        AuthResponseDTO result = authService.resendActivationCode(email);

        // Then
        assertNotNull(result);
        assertNotNull(result.getMessage());
        assertEquals("Demasiadas solicitudes. Intenta en 1 hora", result.getMessage());
        verify(userRepository).findByEmail(email);
        verify(tokenRedisService).canRequestToken(user.getId(), "activation");
        verify(tokenRedisService, never()).generateAndStoreActivationCode(any());
        verify(emailService, never()).sendActivationEmail(any(), any());
    }

    @Test
    void resendActivationCode_emailServiceFails_returnsErrorResponse() {
        // Given
        String email = "user@test.com";
        User user = createTestUser();
        // Usuario no activado (status INACTIVE y emailVerified false por defecto)
        String activationCode = "123456";

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(tokenRedisService.canRequestToken(user.getId(), "activation")).thenReturn(true);
        when(tokenRedisService.generateAndStoreActivationCode(user.getId())).thenReturn(activationCode);
        doThrow(new RuntimeException("Email service error")).when(emailService).sendActivationEmail(user,
                activationCode);

        // When
        AuthResponseDTO result = authService.resendActivationCode(email);

        // Then
        assertNotNull(result);
        assertNotNull(result.getMessage());
        assertEquals("Error enviando el email de activación", result.getMessage());
        verify(userRepository).findByEmail(email);
        verify(tokenRedisService).canRequestToken(user.getId(), "activation");
        verify(tokenRedisService).generateAndStoreActivationCode(user.getId());
        verify(emailService).sendActivationEmail(user, activationCode);
    }

    @Test
    void resendActivationCode_normalizesEmail() {
        // Given
        String email = "  USER@TEST.COM  "; // Con espacios y mayúsculas
        String normalizedEmail = "user@test.com";
        User user = createTestUser();
        // Usuario no activado (status INACTIVE y emailVerified false por defecto)
        String activationCode = "123456";

        when(userRepository.findByEmail(normalizedEmail)).thenReturn(Optional.of(user));
        when(tokenRedisService.canRequestToken(user.getId(), "activation")).thenReturn(true);
        when(tokenRedisService.generateAndStoreActivationCode(user.getId())).thenReturn(activationCode);
        doNothing().when(emailService).sendActivationEmail(user, activationCode);

        // When
        AuthResponseDTO result = authService.resendActivationCode(email);

        // Then
        assertNotNull(result);
        assertNotNull(result.getMessage());
        verify(userRepository).findByEmail(normalizedEmail); // Verifica que se normalizó el email
        verify(tokenRedisService).canRequestToken(user.getId(), "activation");
        verify(tokenRedisService).generateAndStoreActivationCode(user.getId());
        verify(emailService).sendActivationEmail(user, activationCode);
    }

    @Test
    void forgotPassword_success_returnsSuccessResponse() {
        // Given
        ForgotPasswordDTO dto = new ForgotPasswordDTO("user@test.com");
        User user = createTestUser();
        // Usuario no activado (status INACTIVE y emailVerified false por defecto)
        String resetCode = "123456";

        when(userRepository.findByEmail(dto.email())).thenReturn(Optional.of(user));
        when(tokenRedisService.canRequestToken(user.getId(), "reset")).thenReturn(true);
        when(tokenRedisService.generateAndStoreResetCode(user.getId())).thenReturn(resetCode);
        doNothing().when(emailService).sendPasswordResetEmail(user, resetCode);

        // When
        AuthResponseDTO result = authService.forgotPassword(dto);

        // Then
        assertNotNull(result);
        assertNotNull(result.getMessage());
        assertEquals("Se ha enviado un código de reseteo a tu correo electrónico.", result.getMessage());
        verify(userRepository).findByEmail(dto.email());
        verify(tokenRedisService).canRequestToken(user.getId(), "reset");
        verify(tokenRedisService).generateAndStoreResetCode(user.getId());
        verify(emailService).sendPasswordResetEmail(user, resetCode);
    }

    // ============================================================================
    // TESTS DE BLOQUEO DE CUENTA
    // ============================================================================

    @Test
    void accountLockout_blocksAccountAfterMaxFailedAttempts() {
        // Given
        User user = createTestUser();
        user.setStatus(EnumStatus.ACTIVE);
        user.setEmailVerified(true);

        LoginDTO loginDTO = new LoginDTO("user@test.com", "wrongPassword");

        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));
        when(accountLockoutRedisService.isAccountLocked(user.getId())).thenReturn(false);
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Invalid credentials"));
        when(accountLockoutRedisService.recordFailedAttempt(user.getId())).thenReturn(5);
        when(accountLockoutRedisService.getRemainingAttempts(user.getId())).thenReturn(0);
        when(accountLockoutRedisService.isAccountLocked(user.getId())).thenReturn(true);

        // When & Then
        BadCredentialsException exception = assertThrows(BadCredentialsException.class, () -> {
            authService.login(loginDTO);
        });

        assertTrue(exception.getMessage().contains("bloqueada"));
        verify(accountLockoutRedisService).recordFailedAttempt(user.getId());
        verify(accountLockoutRedisService, atLeastOnce()).isAccountLocked(user.getId());
    }

    @Test
    void accountLockout_preventsLoginWhenAccountIsLocked() {
        // Given
        User user = createTestUser();
        user.setStatus(EnumStatus.ACTIVE);
        user.setEmailVerified(true);

        LoginDTO loginDTO = new LoginDTO("user@test.com", "correctPassword");
        java.time.Duration remainingTime = java.time.Duration.ofMinutes(10);

        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));
        when(accountLockoutRedisService.isAccountLocked(user.getId())).thenReturn(true);
        when(accountLockoutRedisService.getRemainingLockoutTime(user.getId())).thenReturn(remainingTime);

        // When & Then
        BadCredentialsException exception = assertThrows(BadCredentialsException.class, () -> {
            authService.login(loginDTO);
        });

        assertTrue(exception.getMessage().contains("bloqueada"));
        assertTrue(exception.getMessage().contains("10 minutos"));
        verify(accountLockoutRedisService).isAccountLocked(user.getId());
        verify(accountLockoutRedisService).getRemainingLockoutTime(user.getId());
        verify(authenticationManager, never()).authenticate(any());
    }

    @Test
    void accountLockout_resetsFailedAttemptsAfterSuccessfulLogin() {
        // Given
        User user = createTestUser();
        user.setStatus(EnumStatus.ACTIVE);
        user.setEmailVerified(true);

        LoginDTO loginDTO = new LoginDTO("user@test.com", "correctPassword");
        Authentication authentication = mock(Authentication.class);

        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));
        when(accountLockoutRedisService.isAccountLocked(user.getId())).thenReturn(false);
        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(jwtSessionService.createSession(any(), any(), any(), any()))
                .thenReturn(JwtSessionService.SessionTokens.builder()
                        .accessToken("access-token")
                        .refreshToken("refresh-token")
                        .expiresIn(3600L)
                        .build());

        // When
        AuthResponseDTO result = authService.login(loginDTO);

        // Then
        assertNotNull(result);
        verify(accountLockoutRedisService).resetFailedAttempts(user.getId());
        verify(userRepository).save(user);
    }

    @Test
    void accountLockout_showsRemainingAttemptsOnFailedLogin() {
        // Given
        User user = createTestUser();
        user.setStatus(EnumStatus.ACTIVE);
        user.setEmailVerified(true);

        LoginDTO loginDTO = new LoginDTO("user@test.com", "wrongPassword");

        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));
        when(accountLockoutRedisService.isAccountLocked(user.getId())).thenReturn(false);
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Invalid credentials"));
        when(accountLockoutRedisService.recordFailedAttempt(user.getId())).thenReturn(3);
        when(accountLockoutRedisService.getRemainingAttempts(user.getId())).thenReturn(2);

        // When & Then
        BadCredentialsException exception = assertThrows(BadCredentialsException.class, () -> {
            authService.login(loginDTO);
        });

        assertTrue(exception.getMessage().contains("Intentos restantes: 2"));
        verify(accountLockoutRedisService).recordFailedAttempt(user.getId());
        verify(accountLockoutRedisService).getRemainingAttempts(user.getId());
    }

    @Test
    void accountLockout_requestImmediateUnlock_sendsCodeWhenAccountIsLocked() {
        // Given
        RequestImmediateUnlockDTO dto = new RequestImmediateUnlockDTO("user@test.com");
        User user = createTestUser();
        String unlockCode = "123456";

        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));
        when(accountLockoutRedisService.isAccountLocked(user.getId())).thenReturn(true);
        when(tokenRedisService.canRequestToken(user.getId(), "unlock")).thenReturn(true);
        when(tokenRedisService.generateAndStoreUnlockCode(user.getId())).thenReturn(unlockCode);
        doNothing().when(emailService).sendUnlockCode(user, unlockCode);

        // When
        AuthResponseDTO result = authService.requestImmediateUnlock(dto);

        // Then
        assertNotNull(result);
        assertEquals("Código de desbloqueo enviado a tu email", result.getMessage());
        verify(accountLockoutRedisService).isAccountLocked(user.getId());
        verify(tokenRedisService).generateAndStoreUnlockCode(user.getId());
        verify(emailService).sendUnlockCode(user, unlockCode);
    }

    @Test
    void accountLockout_requestImmediateUnlock_returnsSuccessWhenAccountNotLocked() {
        // Given
        RequestImmediateUnlockDTO dto = new RequestImmediateUnlockDTO("user@test.com");
        User user = createTestUser();

        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));
        when(accountLockoutRedisService.isAccountLocked(user.getId())).thenReturn(false);

        // When
        AuthResponseDTO result = authService.requestImmediateUnlock(dto);

        // Then
        assertNotNull(result);
        assertEquals("Si el correo es válido y está bloqueado, recibirás un código", result.getMessage());
        verify(accountLockoutRedisService).isAccountLocked(user.getId());
        verify(tokenRedisService, never()).generateAndStoreUnlockCode(any());
        verify(emailService, never()).sendUnlockCode(any(), any());
    }

    @Test
    void accountLockout_verifyUnlockCode_unlocksAccountSuccessfully() {
        // Given
        VerifyUnlockCodeDTO dto = new VerifyUnlockCodeDTO("123456");
        User user = createTestUser();

        when(tokenRedisService.verifyAndConsumeUnlockCode("123456")).thenReturn(user.getId());
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(accountLockoutRedisService.isAccountLocked(user.getId())).thenReturn(true);
        doNothing().when(accountLockoutRedisService).unlockAccount(user.getId());
        doNothing().when(emailService).sendAccountUnlockedEmail(user);

        // When
        AuthResponseDTO result = authService.verifyUnlockCode(dto);

        // Then
        assertNotNull(result);
        assertEquals("Cuenta desbloqueada exitosamente. Ya puedes iniciar sesión.", result.getMessage());
        verify(tokenRedisService).verifyAndConsumeUnlockCode("123456");
        verify(accountLockoutRedisService).isAccountLocked(user.getId());
        verify(accountLockoutRedisService).unlockAccount(user.getId());
        verify(emailService).sendAccountUnlockedEmail(user);
    }

    @Test
    void accountLockout_verifyUnlockCode_returnsErrorWhenCodeIsInvalid() {
        // Given
        VerifyUnlockCodeDTO dto = new VerifyUnlockCodeDTO("invalid-code");

        when(tokenRedisService.verifyAndConsumeUnlockCode("invalid-code")).thenReturn(null);

        // When
        AuthResponseDTO result = authService.verifyUnlockCode(dto);

        // Then
        assertNotNull(result);
        assertEquals("Código de desbloqueo incorrecto o expirado", result.getMessage());
        verify(tokenRedisService).verifyAndConsumeUnlockCode("invalid-code");
        verify(accountLockoutRedisService, never()).unlockAccount(any());
    }

    @Test
    void accountLockout_verifyUnlockCode_returnsSuccessWhenAccountAlreadyUnlocked() {
        // Given
        VerifyUnlockCodeDTO dto = new VerifyUnlockCodeDTO("123456");
        User user = createTestUser();

        when(tokenRedisService.verifyAndConsumeUnlockCode("123456")).thenReturn(user.getId());
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(accountLockoutRedisService.isAccountLocked(user.getId())).thenReturn(false);

        // When
        AuthResponseDTO result = authService.verifyUnlockCode(dto);

        // Then
        assertNotNull(result);
        assertEquals("La cuenta ya está desbloqueada", result.getMessage());
        verify(accountLockoutRedisService).isAccountLocked(user.getId());
        verify(accountLockoutRedisService, never()).unlockAccount(any());
    }

}
