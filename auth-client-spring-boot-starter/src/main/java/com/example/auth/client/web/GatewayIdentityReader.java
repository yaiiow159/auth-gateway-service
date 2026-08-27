package com.example.auth.client.web;

import com.example.auth.contract.AuthHeaders;
import com.example.auth.contract.AuthenticatedUser;
import com.example.auth.contract.IdentitySignatures;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * 把網關注入的 Header 還原成 {@link AuthenticatedUser}。
 *
 * <p>刻意只依賴一個「取 Header」的函式而不是 {@code HttpServletRequest}，
 * 因此可以用一行 lambda 完成單元測試，不需要任何 Servlet mock。
 *
 * <p>驗簽開啟時的規則是「有身分就必須有正確簽章」：只要出現 {@code X-User-Id}
 * 卻無法通過驗章，一律視為偽造請求並拒絕，而不是降級成匿名 ——
 * 降級處理會讓攻擊者得以用偽造 Header 去試探哪些端點允許匿名存取。
 */
public class GatewayIdentityReader {

    private final boolean verifySignature;
    private final String signingSecret;
    private final Duration signatureTtl;
    private final Clock clock;

    public GatewayIdentityReader(boolean verifySignature, String signingSecret,
                                 Duration signatureTtl, Clock clock) {
        this.verifySignature = verifySignature;
        this.signingSecret = signingSecret;
        this.signatureTtl = signatureTtl;
        this.clock = clock;
    }

    public Optional<AuthenticatedUser> read(Function<String, String> headerLookup) {
        String userId = headerLookup.apply(AuthHeaders.USER_ID);
        if (userId == null || userId.isBlank()) {
            return Optional.empty();
        }

        AuthenticatedUser user = new AuthenticatedUser(
                userId,
                decode(headerLookup.apply(AuthHeaders.USERNAME)),
                split(headerLookup.apply(AuthHeaders.ROLES)),
                split(headerLookup.apply(AuthHeaders.PERMISSIONS)),
                decode(headerLookup.apply(AuthHeaders.TENANT_ID)));

        if (verifySignature) {
            verify(user, headerLookup.apply(AuthHeaders.SIGNATURE));
        }
        return Optional.of(user);
    }

    private void verify(AuthenticatedUser user, String signature) {
        if (signature == null || signature.isBlank()) {
            throw new InvalidIdentitySignatureException("身分 Header 缺少簽章");
        }
        if (!IdentitySignatures.verify(signingSecret, user, signature, Instant.now(clock), signatureTtl)) {
            throw new InvalidIdentitySignatureException("身分 Header 簽章驗證失敗");
        }
    }

    /** 網關以 URL encoding 寫入非 ASCII 內容，這裡對稱地還原。 */
    private static String decode(String value) {
        return value == null ? null : URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static Set<String> split(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(value.split(AuthHeaders.VALUE_DELIMITER))
                .map(String::trim)
                .filter(item -> !item.isEmpty())
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
    }
}
