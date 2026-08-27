package com.example.auth.center.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.auth.center.domain.model.AccountStatus;
import com.example.auth.center.domain.model.UserAccount;
import com.example.auth.center.domain.model.UserId;
import com.example.auth.center.domain.port.PasswordHasher;
import com.example.auth.center.domain.port.UserAccountRepository;
import com.example.auth.center.domain.token.IssuedToken;
import com.example.auth.center.domain.token.TokenPair;
import com.example.auth.contract.AuthErrorCode;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AuthenticationServiceTest {

    private static final String USERNAME = "alice";
    private static final String RAW_PASSWORD = "Passw0rd!";
    private static final String PASSWORD_HASH = "$2a$10$hashed";

    private UserAccountRepository userAccountRepository;
    private PasswordHasher passwordHasher;
    private TokenPairFactory tokenPairFactory;
    private AuthenticationService authenticationService;

    @BeforeEach
    void setUp() {
        userAccountRepository = mock(UserAccountRepository.class);
        passwordHasher = mock(PasswordHasher.class);
        tokenPairFactory = mock(TokenPairFactory.class);
        authenticationService = new AuthenticationService(userAccountRepository, passwordHasher, tokenPairFactory);
    }

    @Test
    @DisplayName("帳密正確且帳號啟用時簽發憑證組")
    void issuesTokenPairWhenCredentialsAreValid() {
        UserAccount account = account(AccountStatus.ACTIVE);
        TokenPair expected = tokenPair();
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account));
        when(passwordHasher.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(true);
        when(tokenPairFactory.createFor(account)).thenReturn(expected);

        TokenPair actual = authenticationService.login(new LoginCommand(USERNAME, RAW_PASSWORD));

        assertThat(actual).isSameAs(expected);
    }

    @Test
    @DisplayName("帳號不存在與密碼錯誤回傳相同錯誤碼，避免帳號列舉")
    void returnsIdenticalErrorForUnknownUserAndWrongPassword() {
        when(userAccountRepository.findByUsername("ghost")).thenReturn(Optional.empty());
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account(AccountStatus.ACTIVE)));
        when(passwordHasher.matches(any(), any())).thenReturn(false);

        AuthErrorCode unknownUser = errorCodeOf("ghost", RAW_PASSWORD);
        AuthErrorCode wrongPassword = errorCodeOf(USERNAME, "wrong-password");

        assertThat(unknownUser).isEqualTo(AuthErrorCode.CREDENTIALS_INVALID).isEqualTo(wrongPassword);
    }

    @Test
    @DisplayName("帳號被停用時不簽發憑證")
    void rejectsDisabledAccount() {
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account(AccountStatus.DISABLED)));
        when(passwordHasher.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(true);

        assertThatThrownBy(() -> authenticationService.login(new LoginCommand(USERNAME, RAW_PASSWORD)))
                .isInstanceOf(AuthenticationFailedException.class)
                .extracting(e -> ((AuthenticationFailedException) e).errorCode())
                .isEqualTo(AuthErrorCode.ACCOUNT_DISABLED);

        verify(tokenPairFactory, never()).createFor(any());
    }

    @Test
    @DisplayName("密碼比對失敗時不會呼叫憑證工廠")
    void doesNotIssueTokensWhenPasswordMismatch() {
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account(AccountStatus.ACTIVE)));
        when(passwordHasher.matches(RAW_PASSWORD, PASSWORD_HASH)).thenReturn(false);

        assertThatThrownBy(() -> authenticationService.login(new LoginCommand(USERNAME, RAW_PASSWORD)))
                .isInstanceOf(AuthenticationFailedException.class);

        verify(tokenPairFactory, never()).createFor(any());
    }

    private AuthErrorCode errorCodeOf(String username, String password) {
        try {
            authenticationService.login(new LoginCommand(username, password));
            throw new AssertionError("預期應該拋出 AuthenticationFailedException");
        } catch (AuthenticationFailedException e) {
            return e.errorCode();
        }
    }

    private static UserAccount account(AccountStatus status) {
        return new UserAccount(UserId.of(2048), USERNAME, PASSWORD_HASH, "tenant-a", status,
                Set.of("ROLE_USER"), Set.of("order:read"));
    }

    private static TokenPair tokenPair() {
        Instant expiresAt = Instant.parse("2026-08-28T10:10:00Z");
        return new TokenPair(
                new IssuedToken("access-token", "jti-1", expiresAt),
                new IssuedToken("refresh-token", "refresh-1", expiresAt));
    }
}
