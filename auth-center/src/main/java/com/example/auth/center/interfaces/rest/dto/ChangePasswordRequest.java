package com.example.auth.center.interfaces.rest.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** 變更密碼請求。成功後該使用者所有 Refresh Token 都會失效。 */
public record ChangePasswordRequest(@NotBlank @Size(min = 12, max = 128) String password) {
}
