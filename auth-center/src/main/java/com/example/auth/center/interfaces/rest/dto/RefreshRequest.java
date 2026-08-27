package com.example.auth.center.interfaces.rest.dto;

import jakarta.validation.constraints.NotBlank;

/** 換發請求。 */
public record RefreshRequest(@NotBlank String refreshToken) {
}
