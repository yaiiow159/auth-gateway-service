package com.example.auth.contract;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 身分 Header 值的編解碼。
 *
 * <p>存在的理由是兩個具體的失效情境：
 * <ol>
 *   <li><b>分隔符歧義。</b>角色與權限以逗號串接，若代碼本身含有逗號，
 *       {@code {"ROLE_A,ROLE_B"}}（一個角色）與 {@code {"ROLE_A","ROLE_B"}}（兩個角色）
 *       會產生完全相同的字串。下游因此多得到一個角色，而 HMAC 簽章驗證仍然通過 ——
 *       因為兩端正規化後的結果一模一樣，簽章根本察覺不到差異。</li>
 *   <li><b>控制字元。</b>HTTP Header 值不得包含 CR/LF，含有它的代碼會被 Netty 直接拒絕，
 *       使請求以 500 結束；在較寬鬆的容器上則可能演變成 Header 注入。</li>
 * </ol>
 *
 * <p>逐一編碼每個元素之後，逗號只會以 {@code %2C} 的形式出現在元素內部，
 * 分隔用的逗號因此重新變得明確。{@link IdentitySignatures} 的正規化使用同一組編碼，
 * 讓「不同的身分必然產生不同的簽章輸入」這個前提在型別層級成立。
 */
public final class HeaderCodec {

    private HeaderCodec() {
        throw new AssertionError("工具類別不應被實例化");
    }

    /** 編碼單一值，{@code null} 原樣回傳。 */
    public static String encodeValue(String value) {
        return value == null ? null : URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** 解碼單一值，{@code null} 原樣回傳。 */
    public static String decodeValue(String value) {
        return value == null ? null : URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    /** 逐一編碼後以分隔符串接，保留傳入順序。 */
    public static String encodeList(Collection<String> values) {
        return values.stream()
                .map(HeaderCodec::encodeValue)
                .collect(Collectors.joining(AuthHeaders.VALUE_DELIMITER));
    }

    /** {@link #encodeList} 的反向操作，空值與空白元素一律略過。 */
    public static Set<String> decodeList(String header) {
        if (header == null || header.isBlank()) {
            return Set.of();
        }
        return java.util.Arrays.stream(header.split(AuthHeaders.VALUE_DELIMITER))
                .map(String::trim)
                .filter(element -> !element.isEmpty())
                .map(HeaderCodec::decodeValue)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
}
