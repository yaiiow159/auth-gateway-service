package com.example.auth.contract;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class IdentitySignaturesTest {

    private static final String SECRET = "unit-test-secret-key-do-not-use-in-production";
    private static final Instant NOW = Instant.parse("2026-08-28T10:00:00Z");
    private static final Duration TOLERANCE = Duration.ofSeconds(30);

    @Test
    @DisplayName("正確的簽章可以通過驗證")
    void verifiesSignatureProducedBySign() {
        AuthenticatedUser user = user(Set.of("ADMIN"), Set.of("order:read"));

        String signature = IdentitySignatures.sign(SECRET, user, NOW);

        assertThat(IdentitySignatures.verify(SECRET, user, signature, NOW, TOLERANCE)).isTrue();
    }

    @Test
    @DisplayName("角色集合的迭代順序不影響簽章結果")
    void signatureIsStableRegardlessOfSetIterationOrder() {
        AuthenticatedUser ascending = user(new LinkedHashSet<>(java.util.List.of("A_ROLE", "Z_ROLE")), Set.of());
        AuthenticatedUser descending = user(new LinkedHashSet<>(java.util.List.of("Z_ROLE", "A_ROLE")), Set.of());

        assertThat(IdentitySignatures.sign(SECRET, ascending, NOW))
                .isEqualTo(IdentitySignatures.sign(SECRET, descending, NOW));
    }

    @Test
    @DisplayName("竄改權限內容後簽章驗證失敗")
    void rejectsTamperedPermissions() {
        AuthenticatedUser original = user(Set.of("USER"), Set.of("order:read"));
        String signature = IdentitySignatures.sign(SECRET, original, NOW);

        AuthenticatedUser escalated = user(Set.of("USER"), Set.of("order:read", "order:delete"));

        assertThat(IdentitySignatures.verify(SECRET, escalated, signature, NOW, TOLERANCE)).isFalse();
    }

    @Test
    @DisplayName("超過容許時間窗的簽章視為失效，避免重放攻擊")
    void rejectsSignatureOutsideToleranceWindow() {
        AuthenticatedUser user = user(Set.of("USER"), Set.of());
        String signature = IdentitySignatures.sign(SECRET, user, NOW);

        assertThat(IdentitySignatures.verify(SECRET, user, signature, NOW.plusSeconds(31), TOLERANCE)).isFalse();
    }

    @Test
    @DisplayName("使用不同密鑰簽發的簽章不被接受")
    void rejectsSignatureFromDifferentSecret() {
        AuthenticatedUser user = user(Set.of("USER"), Set.of());
        String forged = IdentitySignatures.sign("another-secret", user, NOW);

        assertThat(IdentitySignatures.verify(SECRET, user, forged, NOW, TOLERANCE)).isFalse();
    }

    @Test
    @DisplayName("格式錯誤的簽章不會拋出例外，只回傳驗證失敗")
    void rejectsMalformedSignatureWithoutThrowing() {
        AuthenticatedUser user = user(Set.of("USER"), Set.of());

        assertThat(IdentitySignatures.verify(SECRET, user, "not-a-signature", NOW, TOLERANCE)).isFalse();
        assertThat(IdentitySignatures.verify(SECRET, user, "1724832000.***", NOW, TOLERANCE)).isFalse();
        assertThat(IdentitySignatures.verify(SECRET, user, "", NOW, TOLERANCE)).isFalse();
    }

    @Test
    @DisplayName("含分隔符的角色代碼不會與兩個角色產生相同簽章")
    void distinguishesDelimiterInsideCodeFromTwoSeparateCodes() {
        AuthenticatedUser singleRoleContainingComma = user(Set.of("ROLE_VIEWER,ROLE_ADMIN"), Set.of());
        AuthenticatedUser twoDistinctRoles = user(Set.of("ROLE_VIEWER", "ROLE_ADMIN"), Set.of());

        String signature = IdentitySignatures.sign(SECRET, singleRoleContainingComma, NOW);

        assertThat(IdentitySignatures.sign(SECRET, twoDistinctRoles, NOW)).isNotEqualTo(signature);
        assertThat(IdentitySignatures.verify(SECRET, twoDistinctRoles, signature, NOW, TOLERANCE)).isFalse();
    }

    private static AuthenticatedUser user(Set<String> roles, Set<String> permissions) {
        return new AuthenticatedUser("1024", "timmy", roles, permissions, "tenant-a");
    }
}
