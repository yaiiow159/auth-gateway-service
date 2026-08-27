package com.example.auth.center.infrastructure.redis;

import com.example.auth.center.domain.model.UserId;
import com.example.auth.center.domain.port.RefreshTokenStore;
import com.example.auth.center.domain.token.RefreshToken;
import com.example.auth.center.infrastructure.config.AuthTokenProperties;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * 以 Redis 實作的 Refresh Token 儲存。
 *
 * <p>Token 值本身就是 256 bits 的密碼學亂數，直接當作 Redis 的鍵使用，
 * 因此「查詢」與「驗證」是同一個動作，不需要額外的比對邏輯。
 *
 * <p>{@link #consume(String)} 以 {@code GETDEL} 完成，這是單一原子指令：
 * 兩個併發的換發請求只會有一個拿到值，另一個必然得到空值，藉此擋下 Refresh Token 重放。
 */
public class RedisRefreshTokenStore implements RefreshTokenStore {

    private static final int TOKEN_BYTES = 32;
    private static final char VALUE_SEPARATOR = '|';
    private static final String USER_INDEX_INFIX = "user:";

    private final StringRedisTemplate redisTemplate;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final String keyPrefix;
    private final Duration ttl;
    private final Clock clock;

    public RedisRefreshTokenStore(StringRedisTemplate redisTemplate,
                                  AuthTokenProperties properties,
                                  Clock clock) {
        this.redisTemplate = redisTemplate;
        this.keyPrefix = properties.refreshTokenKeyPrefix();
        this.ttl = properties.refreshTokenTtl();
        this.clock = clock;
    }

    @Override
    public RefreshToken issue(UserId userId) {
        String tokenId = generateTokenId();
        Instant expiresAt = Instant.now(clock).plus(ttl);

        redisTemplate.opsForValue().set(tokenKey(tokenId), encodeValue(userId, expiresAt), ttl);
        indexForRevocation(userId, tokenId);

        return new RefreshToken(tokenId, userId, expiresAt);
    }

    @Override
    public Optional<RefreshToken> consume(String tokenId) {
        if (tokenId == null || tokenId.isBlank()) {
            return Optional.empty();
        }
        String value = redisTemplate.opsForValue().getAndDelete(tokenKey(tokenId));
        if (value == null) {
            return Optional.empty();
        }
        RefreshToken token = decodeValue(tokenId, value);
        redisTemplate.opsForSet().remove(userIndexKey(token.userId()), tokenId);
        return Optional.of(token);
    }

    @Override
    public void revokeAll(UserId userId) {
        String indexKey = userIndexKey(userId);
        Set<String> tokenIds = redisTemplate.opsForSet().members(indexKey);
        if (tokenIds != null && !tokenIds.isEmpty()) {
            redisTemplate.delete(tokenIds.stream().map(this::tokenKey).toList());
        }
        redisTemplate.delete(indexKey);
    }

    /**
     * 建立「使用者 -> Token 清單」的反向索引，讓 {@link #revokeAll(UserId)} 不必掃描整個 keyspace。
     * 正式環境嚴禁使用 {@code KEYS} 指令做這件事，那會阻塞整個 Redis。
     */
    private void indexForRevocation(UserId userId, String tokenId) {
        String indexKey = userIndexKey(userId);
        redisTemplate.opsForSet().add(indexKey, tokenId);
        redisTemplate.expire(indexKey, ttl);
    }

    private String generateTokenId() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return encoder.encodeToString(bytes);
    }

    private String encodeValue(UserId userId, Instant expiresAt) {
        return userId.value() + VALUE_SEPARATOR + expiresAt.getEpochSecond();
    }

    private RefreshToken decodeValue(String tokenId, String value) {
        int separatorIndex = value.lastIndexOf(VALUE_SEPARATOR);
        String userId = value.substring(0, separatorIndex);
        Instant expiresAt = Instant.ofEpochSecond(Long.parseLong(value.substring(separatorIndex + 1)));
        return new RefreshToken(tokenId, UserId.of(userId), expiresAt);
    }

    private String tokenKey(String tokenId) {
        return keyPrefix + tokenId;
    }

    private String userIndexKey(UserId userId) {
        return keyPrefix + USER_INDEX_INFIX + userId.value();
    }
}
