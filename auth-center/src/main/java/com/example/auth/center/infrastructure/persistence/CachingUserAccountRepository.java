package com.example.auth.center.infrastructure.persistence;

import com.example.auth.center.domain.model.UserAccount;
import com.example.auth.center.domain.model.UserId;
import com.example.auth.center.domain.port.UserAccountRepository;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Duration;
import java.util.Optional;

/**
 * 為 {@link UserAccountRepository} 加上本地快取的裝飾器（Decorator）。
 *
 * <p>用裝飾器而非在 Adapter 內部塞快取邏輯，好處是「取資料」與「快取」兩個關注點各自獨立：
 * 要換快取策略只需替換這一層，要換資料來源只需替換被裝飾的物件，兩者不會互相牽動。
 *
 * <p><b>一致性取捨：</b>快取會讓權限異動延遲生效，最長為 {@code ttl}。因此 TTL 必須短
 * （預設 60 秒），而且「停權」這種必須立即生效的操作要走 Token 撤銷名單，不能只靠改資料庫。
 */
public class CachingUserAccountRepository implements UserAccountRepository {

    private final UserAccountRepository delegate;
    private final Cache<String, Optional<UserAccount>> byUsername;
    private final Cache<String, Optional<UserAccount>> byId;

    public CachingUserAccountRepository(UserAccountRepository delegate, Duration ttl, long maximumSize) {
        this.delegate = delegate;
        this.byUsername = buildCache(ttl, maximumSize);
        this.byId = buildCache(ttl, maximumSize);
    }

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return byUsername.get(username, delegate::findByUsername);
    }

    @Override
    public Optional<UserAccount> findById(UserId userId) {
        return byId.get(userId.value(), key -> delegate.findById(UserId.of(key)));
    }

    private static Cache<String, Optional<UserAccount>> buildCache(Duration ttl, long maximumSize) {
        return Caffeine.newBuilder()
                .expireAfterWrite(ttl)
                .maximumSize(maximumSize)
                .build();
    }
}
