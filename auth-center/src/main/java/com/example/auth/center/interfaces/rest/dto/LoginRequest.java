package com.example.auth.center.interfaces.rest.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** 登入請求。長度上限同時是一道防線，避免超長輸入拖垮 BCrypt。 */
public record LoginRequest(
        @NotBlank @Size(max = 64) String username,
        @NotBlank @Size(max = 128) String password) {
}
