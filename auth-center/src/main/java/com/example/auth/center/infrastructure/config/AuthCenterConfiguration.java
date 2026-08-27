package com.example.auth.center.infrastructure.config;

import com.example.auth.center.domain.port.AccessTokenIssuer;
import com.example.auth.center.domain.port.AccessTokenVerifier;
import com.example.auth.center.domain.port.PasswordHasher;
import com.example.auth.center.domain.port.RefreshTokenStore;
import com.example.auth.center.domain.port.RsaKeyProvider;
import com.example.auth.center.domain.port.TokenRevocationStore;
import com.example.auth.center.domain.port.UserAccountRepository;
import com.example.auth.center.infrastructure.crypto.BCryptPasswordHasher;
import com.example.auth.center.infrastructure.crypto.InMemoryRsaKeyProvider;
import com.example.auth.center.infrastructure.crypto.NimbusAccessTokenIssuer;
import com.example.auth.center.infrastructure.crypto.NimbusAccessTokenVerifier;
import com.example.auth.center.infrastructure.crypto.PemRsaKeyProvider;
import com.example.auth.center.infrastructure.persistence.CachingUserAccountRepository;
import com.example.auth.center.infrastructure.persistence.JpaUserAccountRepository;
import com.example.auth.center.infrastructure.redis.RedisRefreshTokenStore;
import com.example.auth.center.infrastructure.redis.RedisTokenRevocationStore;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ResourceLoader;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.util.StreamUtils;

/**
 * Adapter 的組裝點。
 *
 * <p>所有 Port 到 Adapter 的綁定集中在這一個檔案：想知道「密碼怎麼雜湊、Token 存在哪裡」，
 * 看這裡就夠了，不必在整個專案裡搜 {@code @Component}。
 */
@Configuration(proxyBeanMethods = false)
public class AuthCenterConfiguration {

    private static final int BCRYPT_STRENGTH = 10;
    private static final String CLASSPATH_PREFIX = "classpath:";
    private static final String FILE_PREFIX = "file:";

    /** 全系統統一的時間來源，讓所有與時間相關的邏輯都能在測試中被固定住。 */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public PasswordHasher passwordHasher() {
        return new BCryptPasswordHasher(BCRYPT_STRENGTH);
    }

    @Bean
    public RsaKeyProvider rsaKeyProvider(SigningKeyProperties properties, ResourceLoader resourceLoader) {
        if (!properties.hasStaticKeyPair()) {
            return new InMemoryRsaKeyProvider(properties.keyId());
        }
        return new PemRsaKeyProvider(
                properties.keyId(),
                resolvePem(resourceLoader, properties.privateKeyPem()),
                resolvePem(resourceLoader, properties.publicKeyPem()));
    }

    @Bean
    public AccessTokenIssuer accessTokenIssuer(RsaKeyProvider keyProvider,
                                               AuthTokenProperties properties,
                                               Clock clock) {
        return new NimbusAccessTokenIssuer(keyProvider, properties, clock);
    }

    @Bean
    public AccessTokenVerifier accessTokenVerifier(RsaKeyProvider keyProvider, AuthTokenProperties properties) {
        return new NimbusAccessTokenVerifier(keyProvider, properties);
    }

    @Bean
    public RefreshTokenStore refreshTokenStore(StringRedisTemplate redisTemplate,
                                               AuthTokenProperties properties,
                                               Clock clock) {
        return new RedisRefreshTokenStore(redisTemplate, properties, clock);
    }

    @Bean
    public TokenRevocationStore tokenRevocationStore(StringRedisTemplate redisTemplate,
                                                     AuthTokenProperties properties,
                                                     Clock clock) {
        return new RedisTokenRevocationStore(redisTemplate, properties, clock);
    }

    /**
     * 對外暴露的使用者查詢：預設包上一層本地快取。
     *
     * <p>標記 {@code @Primary} 讓應用層注入到裝飾後的版本，而 JPA Adapter 仍以具體型別存在，
     * 需要繞過快取時直接注入 {@link JpaUserAccountRepository} 即可。
     */
    @Bean
    @Primary
    public UserAccountRepository userAccountRepository(JpaUserAccountRepository jpaRepository,
                                                       UserCacheProperties cacheProperties) {
        if (!cacheProperties.enabled()) {
            return jpaRepository;
        }
        return new CachingUserAccountRepository(
                jpaRepository, cacheProperties.ttl(), cacheProperties.maximumSize());
    }

    /** 允許設定值直接寫 PEM 內容，或以 {@code classpath:} / {@code file:} 指向外部檔案。 */
    private static String resolvePem(ResourceLoader resourceLoader, String value) {
        if (!value.startsWith(CLASSPATH_PREFIX) && !value.startsWith(FILE_PREFIX)) {
            return value;
        }
        try (var input = resourceLoader.getResource(value).getInputStream()) {
            return StreamUtils.copyToString(input, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("無法讀取簽章金鑰: " + value, e);
        }
    }
}
