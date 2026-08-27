package com.example.auth.center.infrastructure.crypto;

import com.example.auth.center.domain.port.PasswordHasher;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * BCrypt 實作。
 *
 * <p>{@code matches} 在雜湊值格式錯誤時只會回傳 false 而不會拋例外，
 * 因此資料庫中的髒資料不會演變成 500 錯誤。
 */
public class BCryptPasswordHasher implements PasswordHasher {

    private final BCryptPasswordEncoder encoder;

    public BCryptPasswordHasher(int strength) {
        this.encoder = new BCryptPasswordEncoder(strength);
    }

    @Override
    public String hash(CharSequence rawPassword) {
        return encoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String hashedPassword) {
        return encoder.matches(rawPassword, hashedPassword);
    }
}
