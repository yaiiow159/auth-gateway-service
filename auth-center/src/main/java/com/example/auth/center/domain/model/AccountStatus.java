package com.example.auth.center.domain.model;

/** 帳號狀態。除了 {@link #ACTIVE} 以外都不允許登入。 */
public enum AccountStatus {
    ACTIVE,
    DISABLED,
    LOCKED
}
