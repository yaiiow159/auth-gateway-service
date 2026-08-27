package com.example.auth.center.infrastructure.persistence;

/** 指定的使用者不存在。 */
public class UserNotFoundException extends RuntimeException {

    public UserNotFoundException(String userId) {
        super("找不到使用者: " + userId);
    }
}
