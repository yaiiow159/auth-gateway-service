package com.example.auth.center.application;

/** 帳號名稱重複。 */
public class UsernameAlreadyTakenException extends RuntimeException {

    public UsernameAlreadyTakenException(String username) {
        super("帳號已被使用: " + username);
    }
}
