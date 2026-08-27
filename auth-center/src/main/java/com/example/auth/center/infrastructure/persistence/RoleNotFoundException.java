package com.example.auth.center.infrastructure.persistence;

import java.util.Set;

/** 指定的角色代碼不存在。 */
public class RoleNotFoundException extends RuntimeException {

    private final transient Set<String> missingRoleCodes;

    public RoleNotFoundException(Set<String> missingRoleCodes) {
        super("找不到角色: " + missingRoleCodes);
        this.missingRoleCodes = Set.copyOf(missingRoleCodes);
    }

    public Set<String> missingRoleCodes() {
        return missingRoleCodes;
    }
}
