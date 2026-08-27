package com.example.auth.center.interfaces.rest.dto;

import jakarta.validation.constraints.NotBlank;

/** Token 自省請求。 */
public record IntrospectionRequest(@NotBlank String token) {
}
