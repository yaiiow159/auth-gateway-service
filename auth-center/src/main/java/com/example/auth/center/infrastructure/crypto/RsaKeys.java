package com.example.auth.center.infrastructure.crypto;

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** PEM 金鑰材料的解析。 */
final class RsaKeys {

    private static final String PEM_BOUNDARY_PATTERN = "-----(BEGIN|END)[^-]*-----";
    private static final String ALGORITHM = "RSA";

    private RsaKeys() {
    }

    /**
     * 由 PEM 材料組出 JWK。
     *
     * @param privateKeyPem PKCS#8 私鑰；{@code null} 代表這是一把已退役、僅供驗證的金鑰
     * @param publicKeyPem  X.509 公鑰
     */
    static RSAKey parse(String keyId, String privateKeyPem, String publicKeyPem) {
        RSAKey.Builder builder = new RSAKey.Builder(readPublicKey(keyId, publicKeyPem))
                .keyID(keyId)
                .keyUse(KeyUse.SIGNATURE);
        if (privateKeyPem != null && !privateKeyPem.isBlank()) {
            builder.privateKey(readPrivateKey(keyId, privateKeyPem));
        }
        return builder.build();
    }

    private static RSAPublicKey readPublicKey(String keyId, String pem) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance(ALGORITHM)
                    .generatePublic(new X509EncodedKeySpec(decode(pem)));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("無法解析 RSA 公鑰，請確認為 X.509 (PEM) 格式: kid=" + keyId, e);
        }
    }

    private static RSAPrivateKey readPrivateKey(String keyId, String pem) {
        try {
            return (RSAPrivateKey) KeyFactory.getInstance(ALGORITHM)
                    .generatePrivate(new PKCS8EncodedKeySpec(decode(pem)));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("無法解析 RSA 私鑰，請確認為 PKCS#8 (PEM) 格式: kid=" + keyId, e);
        }
    }

    /**
     * 剝除 PEM 邊界與所有空白後解碼。
     *
     * <p>注意這裡的 {@code "\\s"}：Java 15 起 {@code "\s"} 是合法的字串跳脫（代表空格），
     * 少寫一個反斜線會編譯成功但只移除空格，換行留下來就會讓 Base64 解碼失敗。
     */
    private static byte[] decode(String pem) {
        String base64 = pem.replaceAll(PEM_BOUNDARY_PATTERN, "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }
}
