package com.example.auth.center.interfaces.rest.dto;

/** 登出請求；Access Token 由 Authorization Header 帶入，此處只需 Refresh Token。 */
public record LogoutRequest(String refreshToken) {
}
