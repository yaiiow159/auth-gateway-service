package com.example.auth.client.web;

import com.example.auth.client.context.UserContextHolder;
import com.example.auth.contract.ApiError;
import com.example.auth.contract.AuthErrorCode;
import com.example.auth.contract.AuthHeaders;
import com.example.auth.contract.AuthenticatedUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 解析網關身分 Header 的 Servlet Filter。
 *
 * <p>排在過濾器鏈的最前面，讓後續所有元件（包含存取日誌）都能取得身分。
 *
 * <p>{@code finally} 中的 {@link UserContextHolder#clear()} 是不可省略的：
 * Servlet 容器會重用執行緒，殘留的身分會被下一個請求撿走。
 */
public class GatewayIdentityFilter extends OncePerRequestFilter implements Ordered {

    /** 供 {@code HandlerMethodArgumentResolver} 讀取，避免重複解析 Header。 */
    public static final String IDENTITY_ATTRIBUTE = GatewayIdentityFilter.class.getName() + ".IDENTITY";

    private static final Logger log = LoggerFactory.getLogger(GatewayIdentityFilter.class);
    private static final int ORDER = Ordered.HIGHEST_PRECEDENCE + 10;

    private final GatewayIdentityReader identityReader;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    public GatewayIdentityFilter(GatewayIdentityReader identityReader, ObjectMapper objectMapper, Clock clock) {
        this.identityReader = identityReader;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        AuthenticatedUser user;
        try {
            user = identityReader.read(request::getHeader).orElse(null);
        } catch (InvalidIdentitySignatureException e) {
            log.warn("拒絕未通過簽章驗證的身分 Header: path={}, reason={}",
                    request.getRequestURI(), e.getMessage());
            writeError(request, response);
            return;
        }

        try {
            if (user != null) {
                UserContextHolder.set(user);
                request.setAttribute(IDENTITY_ATTRIBUTE, user);
            }
            chain.doFilter(request, response);
        } finally {
            UserContextHolder.clear();
        }
    }

    private void writeError(HttpServletRequest request, HttpServletResponse response) throws IOException {
        AuthErrorCode errorCode = AuthErrorCode.IDENTITY_SIGNATURE_INVALID;
        ApiError body = ApiError.of(errorCode, request.getRequestURI(),
                request.getHeader(AuthHeaders.REQUEST_ID), Instant.now(clock));

        response.setStatus(errorCode.httpStatus());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getOutputStream(), body);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
