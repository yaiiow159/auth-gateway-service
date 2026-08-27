package com.example.auth.center.interfaces.rest.dto;

import com.example.auth.center.domain.model.AccountStatus;
import jakarta.validation.constraints.NotNull;

/** 變更帳號狀態請求。停用時會一併撤銷該使用者的 Refresh Token。 */
public record ChangeStatusRequest(@NotNull AccountStatus status) {
}
