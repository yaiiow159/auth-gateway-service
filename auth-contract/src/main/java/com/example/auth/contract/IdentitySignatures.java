package com.example.auth.contract;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.TreeSet;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * 網關注入身分 Header 時所使用的 HMAC 簽章演算法。
 *
 * <p><b>為什麼需要它：</b>只靠「網路上只有網關能連到微服務」來保護 {@code X-User-Id}
 * 是一種脆弱的假設 —— 一次 Service Mesh 設定失誤、一個被打穿的 Sidecar，
 * 攻擊者就能直接對微服務送出偽造身分。簽章讓下游服務具備獨立驗證能力（零信任）。
 *
 * <p>簽章格式：{@code <發行時間戳>.<Base64Url(HMAC-SHA256)>}
 *
 * <p>這個類別被網關與下游 starter 同時引用，確保簽章與驗章邏輯永遠不會分岔。
 */
public final class IdentitySignatures {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final char SEGMENT_SEPARATOR = '.';
    private static final String FIELD_SEPARATOR = "\n";
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    private IdentitySignatures() {
        throw new AssertionError("工具類別不應被實例化");
    }

    /**
     * 產生簽章 Header 值。
     *
     * @param secret   網關與下游服務共享的密鑰
     * @param user     已認證的身分
     * @param issuedAt 簽發時間，用於限制簽章的有效期間（防重放）
     */
    public static String sign(String secret, AuthenticatedUser user, Instant issuedAt) {
        Objects.requireNonNull(secret, "secret 不可為 null");
        Objects.requireNonNull(user, "user 不可為 null");
        long epochSecond = issuedAt.getEpochSecond();
        String mac = ENCODER.encodeToString(hmac(secret, canonicalize(user, epochSecond)));
        return epochSecond + String.valueOf(SEGMENT_SEPARATOR) + mac;
    }

    /**
     * 驗證簽章是否有效且仍在有效期內。
     *
     * @param tolerance 允許的時鐘偏移與傳輸延遲上限
     * @return 簽章正確且未過期時回傳 {@code true}
     */
    public static boolean verify(String secret, AuthenticatedUser user, String signatureHeader,
                                 Instant now, Duration tolerance) {
        if (secret == null || user == null || signatureHeader == null) {
            return false;
        }
        int separatorIndex = signatureHeader.indexOf(SEGMENT_SEPARATOR);
        if (separatorIndex <= 0 || separatorIndex == signatureHeader.length() - 1) {
            return false;
        }
        long issuedAtEpochSecond;
        try {
            issuedAtEpochSecond = Long.parseLong(signatureHeader.substring(0, separatorIndex));
        } catch (NumberFormatException e) {
            return false;
        }
        if (isOutsideToleranceWindow(issuedAtEpochSecond, now, tolerance)) {
            return false;
        }
        byte[] expected = hmac(secret, canonicalize(user, issuedAtEpochSecond));
        byte[] actual = decodeQuietly(signatureHeader.substring(separatorIndex + 1));
        // 定時比較，避免透過回應時間差推敲出正確簽章
        return actual != null && MessageDigest.isEqual(expected, actual);
    }

    private static boolean isOutsideToleranceWindow(long issuedAtEpochSecond, Instant now, Duration tolerance) {
        long skewSeconds = Math.abs(now.getEpochSecond() - issuedAtEpochSecond);
        return skewSeconds > tolerance.toSeconds();
    }

    /**
     * 將身分序列化成穩定的字串表述。
     *
     * <p>角色與權限先排序再串接，否則同一份身分會因為 {@link java.util.Set} 的
     * 迭代順序不同而產生不同簽章。
     */
    private static String canonicalize(AuthenticatedUser user, long issuedAtEpochSecond) {
        return String.join(FIELD_SEPARATOR,
                user.userId(),
                nullToEmpty(user.username()),
                joinSorted(user.roles()),
                joinSorted(user.permissions()),
                nullToEmpty(user.tenantId()),
                Long.toString(issuedAtEpochSecond));
    }

    private static String joinSorted(java.util.Set<String> values) {
        return String.join(AuthHeaders.VALUE_DELIMITER, new TreeSet<>(values));
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static byte[] hmac(String secret, String payload) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            return mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        } catch (java.security.GeneralSecurityException e) {
            // HmacSHA256 是 JDK 必備演算法，走到這裡代表 JVM 環境異常，屬於不可回復錯誤
            throw new IllegalStateException("無法建立 HMAC-SHA256", e);
        }
    }

    private static byte[] decodeQuietly(String base64Url) {
        try {
            return Base64.getUrlDecoder().decode(base64Url);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
