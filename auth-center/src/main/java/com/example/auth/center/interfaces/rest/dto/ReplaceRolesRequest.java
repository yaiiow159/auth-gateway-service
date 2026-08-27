package com.example.auth.center.interfaces.rest.dto;

import jakarta.validation.constraints.NotNull;
import java.util.Set;

/** 覆寫角色請求。傳入空集合代表移除所有角色。 */
public record ReplaceRolesRequest(@NotNull Set<String> roleCodes) {
}
