package com.example.auth.center.domain.model;

import java.util.Objects;

/**
 * 使用者識別碼的 value object。
 *
 * <p>用它取代到處傳遞的 {@code String}，讓「使用者 ID」與「租戶 ID」在型別層級就不可能被互相傳錯。
 */
public record UserId(String value) {

    public UserId {
        Objects.requireNonNull(value, "使用者識別碼不可為 null");
        if (value.isBlank()) {
            throw new IllegalArgumentException("使用者識別碼不可為空白");
        }
    }

    public static UserId of(String value) {
        return new UserId(value);
    }

    public static UserId of(long value) {
        return new UserId(Long.toString(value));
    }

    @Override
    public String toString() {
        return value;
    }
}
