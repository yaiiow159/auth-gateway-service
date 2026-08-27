package com.example.auth.center.infrastructure.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 使用者資料本地快取設定。
 *
 * @param ttl         快取存活時間，直接決定權限異動的最大延遲，不建議超過數分鐘
 * @param maximumSize 最大筆數，避免熱點資料以外的查詢把記憶體吃光
 * @param enabled     是否啟用；壓測或排查資料不一致時可關閉
 */
@ConfigurationProperties(prefix = "auth.cache.user")
public record UserCacheProperties(Duration ttl, Long maximumSize, Boolean enabled) {

    public UserCacheProperties {
        ttl = ttl == null ? Duration.ofSeconds(60) : ttl;
        maximumSize = maximumSize == null ? 10_000L : maximumSize;
        enabled = enabled == null || enabled;
    }
}
