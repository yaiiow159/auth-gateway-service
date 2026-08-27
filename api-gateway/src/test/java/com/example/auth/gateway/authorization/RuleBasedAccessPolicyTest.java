package com.example.auth.gateway.authorization;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.contract.AuthenticatedUser;
import com.example.auth.gateway.config.GatewayAuthProperties;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class RuleBasedAccessPolicyTest {

    private final RuleBasedAccessPolicy policy = new RuleBasedAccessPolicy(List.of(
            rule("/api/orders/**", Set.of("GET"), Set.of("order:read"), Set.of(), Set.of()),
            rule("/api/orders/**", Set.of("DELETE"), Set.of("order:delete"), Set.of(), Set.of()),
            rule("/api/admin/**", Set.of(), Set.of(), Set.of("user:manage"), Set.of("ROLE_ADMIN"))));

    @Test
    @DisplayName("命中規則且權限足夠時放行")
    void permitsWhenRuleMatchesAndPermissionSatisfied() {
        AccessDecision decision = policy.evaluate(
                context("/api/orders/1", "GET", Set.of(), Set.of("order:read")));

        assertThat(decision).isEqualTo(AccessDecision.PERMIT);
    }

    @Test
    @DisplayName("命中規則但權限不足時明確拒絕，不交給兜底判定")
    void deniesWhenRuleMatchesButPermissionMissing() {
        AccessDecision decision = policy.evaluate(
                context("/api/orders/1", "DELETE", Set.of(), Set.of("order:read")));

        assertThat(decision).isEqualTo(AccessDecision.DENY);
    }

    @Test
    @DisplayName("方法不符的規則不算命中")
    void ignoresRuleWithDifferentMethod() {
        AccessDecision decision = policy.evaluate(
                context("/api/orders/1", "PATCH", Set.of(), Set.of("order:read")));

        assertThat(decision).isEqualTo(AccessDecision.ABSTAIN);
    }

    @Test
    @DisplayName("沒有任何規則涵蓋的路徑一律棄權，由責任鏈的兜底值決定")
    void abstainsWhenNoRuleMatches() {
        AccessDecision decision = policy.evaluate(
                context("/api/reports/monthly", "GET", Set.of(), Set.of("order:read")));

        assertThat(decision).isEqualTo(AccessDecision.ABSTAIN);
    }

    @Test
    @DisplayName("角色與權限條件同時設定時必須全部滿足")
    void requiresBothRoleAndPermissionWhenRuleDeclaresBoth() {
        AccessContext missingRole = context("/api/admin/users", "GET", Set.of("ROLE_USER"), Set.of("user:manage"));
        AccessContext satisfied = context("/api/admin/users", "GET", Set.of("ROLE_ADMIN"), Set.of("user:manage"));

        assertThat(policy.evaluate(missingRole)).isEqualTo(AccessDecision.DENY);
        assertThat(policy.evaluate(satisfied)).isEqualTo(AccessDecision.PERMIT);
    }

    private static GatewayAuthProperties.Rule rule(String path, Set<String> methods, Set<String> anyOfPermissions,
                                                   Set<String> allOfPermissions, Set<String> anyOfRoles) {
        return new GatewayAuthProperties.Rule(path, methods, anyOfPermissions, allOfPermissions, anyOfRoles);
    }

    private static AccessContext context(String path, String method, Set<String> roles, Set<String> permissions) {
        return new AccessContext(path, method, new AuthenticatedUser("1024", "timmy", roles, permissions, null));
    }
}
