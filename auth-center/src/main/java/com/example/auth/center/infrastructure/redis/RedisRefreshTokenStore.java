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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * 以 Redis 實作的 Refresh Token 儲存。
 *
 * <p>Token 值本身就是 256 bits 的密碼學亂數，直接當作 Redis 的鍵使用，
 * 因此「查詢」與「驗證」是同一個動作，不需要額外的比對邏輯。
 *
 * <p>{@link #consume(String)} 以 {@code GETDEL} 完成，這是單一原子指令：
 * 兩個併發的換發請求只會有一個拿到值，另一個必然得到空值，藉此擋下 Refresh Token 重放。
 *
 * <p>共維護四組鍵：
 * <ul>
 *   <li>{@code <prefix><tokenId>} —— Token 本體，值為 {@code userId|到期秒數}</li>
 *   <li>{@code <prefix>session:<accessJti>} —— 工作階段對應，供登出時反查</li>
 *   <li>{@code <prefix>used:<tokenId>} —— 已消耗紀錄，供重放偵測</li>
 *   <li>{@code <prefix>user:<userId>} —— 反向索引，供整批撤銷</li>
 * </ul>
 * 四者的 TTL 皆為 Refresh Token 的壽命，因此不會隨系統運行時間無限累積。
 */
public class RedisRefreshTokenStore implements RefreshTokenStore {

    private static final Logger log = LoggerFactory.getLogger(RedisRefreshTokenStore.class);

    private static final int TOKEN_BYTES = 32;
    private static final char VALUE_SEPARATOR = '|';
    private static final String USER_INDEX_INFIX = "user:";
    private static final String SESSION_INFIX = "session:";
    private static final String CONSUMED_INFIX = "used:";

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
    public RefreshToken issue(UserId userId, String sessionId) {
        String tokenId = generateTokenId();
        Instant expiresAt = Instant.now(clock).plus(ttl);

        redisTemplate.opsForValue().set(tokenKey(tokenId), encodeValue(userId, expiresAt), ttl);
        redisTemplate.opsForValue().set(sessionKey(sessionId), tokenId, ttl);
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
        // 留下「誰用過這枚 Token」的紀錄，讓稍後的重放能被歸因到具體使用者
        redisTemplate.opsForValue().set(consumedKey(tokenId), token.userId().value(), ttl);
        return Optional.of(token);
    }

    @Override
    public Optional<RefreshToken> consumeBySession(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return Optional.empty();
        }
        // 工作階段對應在輪替後會殘留指向已消耗的 Token，此時 consume 自然回傳空值
        String tokenId = redisTemplate.opsForValue().getAndDelete(sessionKey(sessionId));
        return tokenId == null ? Optional.empty() : consume(tokenId);
    }

    @Override
    public Optional<UserId> ownerOfConsumedToken(String tokenId) {
        if (tokenId == null || tokenId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(redisTemplate.opsForValue().get(consumedKey(tokenId))).map(UserId::of);
    }

    @Override
    public void revokeAll(UserId userId) {
        String indexKey = userIndexKey(userId);
        Set<String> tokenIds = redisTemplate.opsForSet().members(indexKey);
        if (tokenIds != null && !tokenIds.isEmpty()) {
            redisTemplate.delete(tokenIds.stream().map(this::tokenKey).toList());
            log.info("撤銷使用者全部 Refresh Token: userId={}, count={}", userId, tokenIds.size());
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
        if (separatorIndex <= 0) {
            throw new IllegalStateException("Refresh Token 的儲存格式無法解析: " + tokenId);
        }
        Instant expiresAt = Instant.ofEpochSecond(Long.parseLong(value.substring(separatorIndex + 1)));
        return new RefreshToken(tokenId, UserId.of(value.substring(0, separatorIndex)), expiresAt);
    }

    private String tokenKey(String tokenId) {
        return keyPrefix + tokenId;
    }

    private String sessionKey(String sessionId) {
        return keyPrefix + SESSION_INFIX + sessionId;
    }

    private String consumedKey(String tokenId) {
        return keyPrefix + CONSUMED_INFIX + tokenId;
    }

    private String userIndexKey(UserId userId) {
        return keyPrefix + USER_INDEX_INFIX + userId.value();
    }
}
