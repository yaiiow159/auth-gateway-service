package com.example.auth.center.domain.port;

import com.example.auth.contract.AuthenticatedUser;
import java.time.Instant;
import java.util.Optional;

/**
 * Access Token 的驗證出口，供內部自省（introspection）端點使用。
 *
 * <p>網關預設走「本地驗簽」不會用到這裡；這個端點是給無法或不願意內建 JOSE 函式庫的
 * 邊緣元件（例如 Nginx Lua、舊系統）使用的備援路徑。
 */
public interface AccessTokenVerifier {

    Optional<VerifiedToken> verify(String token);

    record VerifiedToken(AuthenticatedUser user, String tokenId, Instant expiresAt) {
    }
}
