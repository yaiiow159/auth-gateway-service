package com.example.auth.client.web;

/** 身分 Header 的簽章缺失或不正確時拋出，代表請求並非來自可信的網關。 */
public class InvalidIdentitySignatureException extends RuntimeException {

    public InvalidIdentitySignatureException(String message) {
        super(message);
    }
}
