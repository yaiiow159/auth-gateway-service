package com.example.auth.gateway.support;

import com.example.auth.contract.ApiError;
import com.example.auth.contract.AuthErrorCode;
import com.example.auth.contract.AuthHeaders;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 統一輸出錯誤回應。
 *
 * <p>網關在請求還沒進入任何微服務時就把它擋下，因此沒有 {@code @RestControllerAdvice} 可用；
 * 這個類別扮演的就是網關層的全域錯誤處理器，確保被網關拒絕的請求與被微服務拒絕的請求
 * 拿到的是同一種錯誤格式。
 */
public class ProblemResponseWriter {

    private static final Logger log = LoggerFactory.getLogger(ProblemResponseWriter.class);
    private static final String BEARER_CHALLENGE = "Bearer error=\"%s\"";

    private final ObjectMapper objectMapper;
    private final Clock clock;

    public ProblemResponseWriter(ObjectMapper objectMapper, Clock clock) {
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    public Mono<Void> write(ServerWebExchange exchange, AuthErrorCode errorCode, String logDetail) {
        HttpStatus status = HttpStatus.valueOf(errorCode.httpStatus());
        String path = exchange.getRequest().getPath().value();
        String requestId = exchange.getRequest().getHeaders().getFirst(AuthHeaders.REQUEST_ID);

        log.debug("請求被網關拒絕: status={}, code={}, path={}, detail={}",
                status.value(), errorCode.code(), path, logDetail);

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        if (status == HttpStatus.UNAUTHORIZED) {
            // 遵循 RFC 6750：401 必須帶上 WWW-Authenticate，客戶端才知道該如何重新取得授權
            response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, BEARER_CHALLENGE.formatted(errorCode.code()));
        }

        ApiError body = ApiError.of(errorCode, path, requestId, Instant.now(clock));
        return response.writeWith(Mono.just(serialize(response, body)));
    }

    private DataBuffer serialize(ServerHttpResponse response, ApiError body) {
        try {
            return response.bufferFactory().wrap(objectMapper.writeValueAsBytes(body));
        } catch (JsonProcessingException e) {
            // 錯誤回應本身序列化失敗是不該發生的情況，但絕不能因此讓連線懸著不回應
            log.error("錯誤回應序列化失敗", e);
            return response.bufferFactory().wrap(
                    ("{\"code\":\"" + body.code() + "\"}").getBytes(StandardCharsets.UTF_8));
        }
    }
}
