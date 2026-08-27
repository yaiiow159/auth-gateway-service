package com.example.auth.gateway.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.core.publisher.Mono;

/**
 * 以 Redis 查詢撤銷名單。
 *
 * <p><b>Redis 故障時的取捨（failOpen）：</b>
 * <ul>
 *   <li>{@code true}（預設）：查不到就當作未撤銷。已登出的短命 Token 可能在剩餘壽命內
 *       仍然可用，但整個站台不會因為 Redis 抖動而全面癱瘓。</li>
 *   <li>{@code false}：Redis 不可用時一律拒絕。安全性最高，代價是快取層變成單點故障。</li>
 * </ul>
 * 預設選擇前者，因為 Access Token 的壽命本來就只有幾分鐘，風險窗口有限；
 * 對安全要求極高的部署（金流、後台）應改為 {@code false}，並為 Redis 做高可用。
 * 無論選哪一種，失敗都必須留下錯誤日誌以便告警。
 */
public class RedisTokenRevocationChecker implements TokenRevocationChecker {

    private static final Logger log = LoggerFactory.getLogger(RedisTokenRevocationChecker.class);

    private final ReactiveStringRedisTemplate redisTemplate;
    private final String keyPrefix;
    private final boolean failOpen;

    public RedisTokenRevocationChecker(ReactiveStringRedisTemplate redisTemplate,
                                       String keyPrefix,
                                       boolean failOpen) {
        this.redisTemplate = redisTemplate;
        this.keyPrefix = keyPrefix;
        this.failOpen = failOpen;
    }

    @Override
    public Mono<Boolean> isRevoked(String tokenId) {
        if (tokenId == null || tokenId.isBlank()) {
            // 沒有 jti 的 Token 無法被撤銷，這本身就是不該接受的憑證
            return Mono.just(!failOpen);
        }
        return redisTemplate.hasKey(keyPrefix + tokenId)
                .onErrorResume(error -> {
                    log.error("撤銷名單查詢失敗，採用 failOpen={} 的預設行為", failOpen, error);
                    return Mono.just(!failOpen);
                });
    }
}
