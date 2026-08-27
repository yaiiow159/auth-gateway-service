package com.example.auth.gateway.authentication;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;
import reactor.core.publisher.Mono;

/**
 * 為 {@link TokenVerifier} 加上短時快取的裝飾器。
 *
 * <p>只有遠端自省模式需要它：本地驗簽已經是純 CPU 運算，加快取只會多一層記憶體開銷
 * 與一段可能過期的授權結論，得不償失。
 *
 * <p><b>快取鍵是 Token 的 SHA-256，不是 Token 本身。</b>快取會把鍵長時間留在記憶體中，
 * 而 Token 是一份可直接冒用的憑證；一旦發生記憶體傾印或被其他程式讀取，
 * 存的是雜湊值就只是一堆無法反推的字串。
 *
 * <p><b>TTL 直接等於登出的最大延遲</b>，因此只能是秒級。快取的目的是削掉同一枚 Token
 * 在短時間內重複自省的尖峰，不是長期持有授權結論。
 */
public class CachingTokenVerifier implements TokenVerifier {

    private static final String DIGEST_ALGORITHM = "SHA-256";

    private final TokenVerifier delegate;
    private final Cache<String, AuthenticationResult> cache;

    public CachingTokenVerifier(TokenVerifier delegate, Duration ttl, long maximumSize) {
        this.delegate = delegate;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(ttl)
                .maximumSize(maximumSize)
                .build();
    }

    @Override
    public Mono<AuthenticationResult> verify(String rawToken) {
        String key = fingerprint(rawToken);
        AuthenticationResult cached = cache.getIfPresent(key);
        if (cached != null) {
            return Mono.just(cached);
        }
        // 失敗結果同樣快取：對無效 Token 的重複探測不該每次都打到授權中心
        return delegate.verify(rawToken).doOnNext(result -> cache.put(key, result));
    }

    private static String fingerprint(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance(DIGEST_ALGORITHM)
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 是 JDK 必備演算法，走到這裡代表 JVM 環境異常
            throw new IllegalStateException("無法計算 Token 指紋", e);
        }
    }
}
