package com.example.auth.client.config;

import com.example.auth.client.aop.PermissionCheckAspect;
import com.example.auth.client.web.AuthClientExceptionHandler;
import com.example.auth.client.web.CurrentUserArgumentResolver;
import com.example.auth.client.web.GatewayIdentityFilter;
import com.example.auth.client.web.GatewayIdentityReader;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.util.List;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 下游服務只要把本套件加進依賴，身分解析就自動生效，不需要任何設定。
 *
 * <p>這正是抽成 starter 的價值：讓「正確且安全的做法」成為預設值。
 * 如果每個服務都得自己複製一段讀 Header 的程式碼，遲早會有人少驗一次簽章。
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(AuthClientProperties.class)
public class AuthClientAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public Clock authClientClock() {
        return Clock.systemUTC();
    }

    @Bean
    public GatewayIdentityReader gatewayIdentityReader(AuthClientProperties properties, Clock clock) {
        if (properties.verifySignature() && isBlank(properties.signingSecret())) {
            // 啟動就失敗，好過帶著一個「以為有驗、其實沒驗」的設定跑上正式環境
            throw new IllegalStateException(
                    "已啟用身分簽章驗證但未設定 auth.client.signing-secret；"
                            + "此密鑰必須與網關的 gateway.auth.identity.signing-secret 相同");
        }
        return new GatewayIdentityReader(
                properties.verifySignature(), properties.signingSecret(), properties.signatureTtl(), clock);
    }

    @Bean
    public GatewayIdentityFilter gatewayIdentityFilter(GatewayIdentityReader reader,
                                                       ObjectMapper objectMapper,
                                                       Clock clock) {
        return new GatewayIdentityFilter(reader, objectMapper, clock);
    }

    @Bean
    public WebMvcConfigurer currentUserArgumentResolverConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
                resolvers.add(new CurrentUserArgumentResolver());
            }
        };
    }

    @Bean
    public PermissionCheckAspect permissionCheckAspect() {
        return new PermissionCheckAspect();
    }

    @Bean
    public AuthClientExceptionHandler authClientExceptionHandler(Clock clock) {
        return new AuthClientExceptionHandler(clock);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
