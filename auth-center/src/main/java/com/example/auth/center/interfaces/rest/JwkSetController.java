package com.example.auth.center.interfaces.rest;

import com.example.auth.center.domain.port.RsaKeyProvider;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 公鑰發布端點，路徑遵循 RFC 8414 慣例。
 *
 * <p>這是整套架構的效能關鍵：網關只要抓過一次 JWKS，之後每個請求都能在本地完成驗簽，
 * 不必為了驗證而呼叫授權中心。回應帶上 {@code Cache-Control} 讓網關與 CDN 能安心快取，
 * 但刻意不設太長 —— 金鑰輪替後需要能在可接受的時間內傳播出去。
 */
@RestController
public class JwkSetController {

    private static final long CACHE_SECONDS = 300;

    private final RsaKeyProvider keyProvider;

    public JwkSetController(RsaKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    @GetMapping(path = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> jwkSet() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(java.time.Duration.ofSeconds(CACHE_SECONDS)).cachePublic())
                .body(keyProvider.publicJwkSet().toJSONObject());
    }
}
