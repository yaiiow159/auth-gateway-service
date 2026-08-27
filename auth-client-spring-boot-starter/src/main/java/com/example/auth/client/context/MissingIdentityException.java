package com.example.auth.client.context;

/** 需要身分但請求中沒有身分時拋出，最終被轉為 401。 */
public class MissingIdentityException extends RuntimeException {

    public MissingIdentityException(String message) {
        super(message);
    }
}
