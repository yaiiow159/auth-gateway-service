package com.example.auth.center.domain.port;

/**
 * 密碼雜湊策略。
 *
 * <p>抽成介面的實際理由：雜湊演算法會隨著算力演進而汰換（BCrypt → Argon2id），
 * 屆時只需要新增一個 Adapter，領域層與應用層一行都不用改。
 */
public interface PasswordHasher {

    String hash(CharSequence rawPassword);

    boolean matches(CharSequence rawPassword, String hashedPassword);
}
