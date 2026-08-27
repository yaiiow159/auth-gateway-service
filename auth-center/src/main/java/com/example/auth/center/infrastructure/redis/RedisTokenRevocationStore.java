package com.example.auth.center.infrastructure.redis;

import com.example.auth.center.domain.port.TokenRevocationStore;
import com.example.auth.center.infrastructure.config.AuthTokenProperties;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * 以 Redis 實作的撤銷名單。
 *
 * <p>紀錄的 TTL 等於 Token 的剩餘壽命：Token 自然過期之後就不可能再通過驗簽，
 * 撤銷紀錄自然也沒有保留的必要。這讓黑名單的大小只與「同時間內被撤銷的 Token 數」成正比，
 * 而不會隨系統運行時間無限成長。
 *
 * <p>網關讀取的是同一組鍵，因此 {@code key-prefix} 必須兩邊一致。
 */
public class RedisTokenRevocationStore implements TokenRevocationStore {

    private static final String REVOKED_MARKER = "1";

    private final StringRedisTemplate redisTemplate;
    private final String keyPrefix;
    private final Clock clock;

    public RedisTokenRevocationStore(StringRedisTemplate redisTemplate,
                                     AuthTokenProperties properties,
                                     Clock clock) {
        this.redisTemplate = redisTemplate;
        this.keyPrefix = properties.revocationKeyPrefix();
        this.clock = clock;
    }

    @Override
    public void revoke(String tokenId, Instant tokenExpiresAt) {
        Duration remaining = Duration.between(Instant.now(clock), tokenExpiresAt);
        if (remaining.isNegative() || remaining.isZero()) {
            return; // 已經過期的 Token 不需要撤銷
        }
        redisTemplate.opsForValue().set(keyOf(tokenId), REVOKED_MARKER, remaining);
    }

    @Override
    public boolean isRevoked(String tokenId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(keyOf(tokenId)));
    }

    private String keyOf(String tokenId) {
        return keyPrefix + tokenId;
    }
}
