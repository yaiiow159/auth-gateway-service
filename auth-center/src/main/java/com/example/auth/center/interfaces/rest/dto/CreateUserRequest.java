package com.example.auth.center.interfaces.rest.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.Set;

/**
 * 建立帳號請求。
 *
 * @param username  僅允許英數與少數符號：帳號會出現在日誌與 Header 中，限制字元集可以
 *                  一次排除控制字元注入與顯示相關的問題
 * @param password  長度下限是唯一在此強制的密碼規則；複雜度策略應由組織政策決定，
 *                  寫死在程式碼裡只會讓每次政策調整都變成一次發版
 * @param roleCodes 初始角色代碼，例如 ROLE_USER
 */
public record CreateUserRequest(
        @NotBlank @Size(min = 3, max = 64) @Pattern(regexp = "[A-Za-z0-9._@-]+") String username,
        @NotBlank @Size(min = 12, max = 128) String password,
        @Size(max = 64) String tenantId,
        Set<String> roleCodes) {
}
