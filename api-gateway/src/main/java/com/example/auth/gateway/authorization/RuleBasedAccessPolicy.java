package com.example.auth.gateway.authorization;

import com.example.auth.contract.AuthenticatedUser;
import com.example.auth.gateway.config.GatewayAuthProperties;
import java.util.List;
import java.util.Set;
import org.springframework.http.server.PathContainer;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * 依設定檔規則進行路徑層級授權。
 *
 * <p>規則在建構時就編譯成 {@link PathPattern}，而不是每個請求重新解析字串 ——
 * 網關是全站流量的必經之地，任何可以搬到啟動期做的工作都不該留在請求路徑上。
 *
 * <p>命中規則但條件不滿足時回傳 {@link AccessDecision#DENY}，而不是棄權：
 * 既然規則已經明確描述了這條路徑的要求，就不該讓後面的兜底邏輯有機會放行。
 */
public class RuleBasedAccessPolicy implements AccessPolicy {

    private final List<CompiledRule> rules;

    public RuleBasedAccessPolicy(List<GatewayAuthProperties.Rule> rules) {
        PathPatternParser parser = new PathPatternParser();
        this.rules = rules.stream().map(rule -> CompiledRule.compile(rule, parser)).toList();
    }

    @Override
    public AccessDecision evaluate(AccessContext context) {
        PathContainer path = PathContainer.parsePath(context.path());
        return rules.stream()
                .filter(rule -> rule.matches(path, context.method()))
                .findFirst()
                .map(rule -> rule.decide(context.user()))
                .orElse(AccessDecision.ABSTAIN);
    }

    /** 編譯後的規則，把設定檔中的字串轉成可高效比對的形式。 */
    private record CompiledRule(
            PathPattern pattern,
            Set<String> methods,
            Set<String> anyOfPermissions,
            Set<String> allOfPermissions,
            Set<String> anyOfRoles) {

        static CompiledRule compile(GatewayAuthProperties.Rule rule, PathPatternParser parser) {
            return new CompiledRule(
                    parser.parse(rule.path()),
                    rule.methods(),
                    rule.anyOfPermissions(),
                    rule.allOfPermissions(),
                    rule.anyOfRoles());
        }

        boolean matches(PathContainer path, String method) {
            return (methods.isEmpty() || methods.contains(method)) && pattern.matches(path);
        }

        AccessDecision decide(AuthenticatedUser user) {
            boolean satisfied = satisfiesAnyPermission(user)
                    && user.hasAllPermissions(allOfPermissions)
                    && satisfiesAnyRole(user);
            return satisfied ? AccessDecision.PERMIT : AccessDecision.DENY;
        }

        private boolean satisfiesAnyPermission(AuthenticatedUser user) {
            return anyOfPermissions.isEmpty() || user.hasAnyPermission(anyOfPermissions);
        }

        private boolean satisfiesAnyRole(AuthenticatedUser user) {
            return anyOfRoles.isEmpty() || anyOfRoles.stream().anyMatch(user::hasRole);
        }
    }
}
