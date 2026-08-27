package com.example.auth.center.interfaces.rest;

import com.example.auth.center.application.AuthenticationService;
import com.example.auth.center.application.LoginCommand;
import com.example.auth.center.application.LogoutService;
import com.example.auth.center.application.TokenRefreshService;
import com.example.auth.center.interfaces.rest.dto.LoginRequest;
import com.example.auth.center.interfaces.rest.dto.LogoutRequest;
import com.example.auth.center.interfaces.rest.dto.RefreshRequest;
import com.example.auth.center.interfaces.rest.dto.TokenResponse;
import jakarta.validation.Valid;
import java.time.Clock;
import java.time.Instant;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 認證端點。
 *
 * <p>Controller 只做三件事：轉換 DTO、呼叫用例、組裝回應。
 * 任何 {@code if} 判斷出現在這裡都是業務邏輯洩漏到介面層的訊號。
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationService authenticationService;
    private final TokenRefreshService tokenRefreshService;
    private final LogoutService logoutService;
    private final Clock clock;

    public AuthController(AuthenticationService authenticationService,
                          TokenRefreshService tokenRefreshService,
                          LogoutService logoutService,
                          Clock clock) {
        this.authenticationService = authenticationService;
        this.tokenRefreshService = tokenRefreshService;
        this.logoutService = logoutService;
        this.clock = clock;
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        var tokenPair = authenticationService.login(new LoginCommand(request.username(), request.password()));
        return TokenResponse.from(tokenPair, Instant.now(clock));
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request) {
        var tokenPair = tokenRefreshService.refresh(request.refreshToken());
        return TokenResponse.from(tokenPair, Instant.now(clock));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestBody(required = false) LogoutRequest request) {
        String refreshToken = request == null ? null : request.refreshToken();
        logoutService.logout(BearerTokens.extract(authorization), refreshToken);
        return ResponseEntity.noContent().build();
    }
}
