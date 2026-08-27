package com.example.auth.center.domain.port;

import com.example.auth.center.domain.model.UserAccount;
import com.example.auth.center.domain.token.IssuedToken;

/** Access Token 的簽發出口，實作決定簽章演算法與金鑰來源。 */
public interface AccessTokenIssuer {

    IssuedToken issue(UserAccount account);
}
