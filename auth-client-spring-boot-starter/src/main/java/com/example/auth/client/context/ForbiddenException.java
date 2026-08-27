package com.example.auth.client.context;

import java.util.Set;

/** 身分存在但權限不足時拋出，最終被轉為 403。 */
public class ForbiddenException extends RuntimeException {

    private final transient Set<String> requiredPermissions;

    public ForbiddenException(Set<String> requiredPermissions) {
        super("缺少必要權限: " + requiredPermissions);
        this.requiredPermissions = Set.copyOf(requiredPermissions);
    }

    public Set<String> requiredPermissions() {
        return requiredPermissions;
    }
}
