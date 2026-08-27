package com.example.auth.client.web;

import com.example.auth.contract.AuthHeaders;
import com.example.auth.contract.AuthenticatedUser;
import com.example.auth.contract.HeaderCodec;
import com.example.auth.contract.IdentitySignatures;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
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

    /** 與網關的 {@link HeaderCodec} 對稱還原，兩端共用同一份實作以確保編解碼不會分岔。 */
    private static String decode(String value) {
        return HeaderCodec.decodeValue(value);
    }

    private static Set<String> split(String value) {
        return HeaderCodec.decodeList(value);
    }
}
