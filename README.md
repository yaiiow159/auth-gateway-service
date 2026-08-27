# auth-gateway-service

微服務架構下的 API Gateway 與授權中心，採「集中認證、網關校驗、服務明文」模式：
認證授權的複雜度收斂在網關與授權中心，業務微服務只需要面對一個已驗證的使用者物件。

Java 21 · Spring Boot 3.3 · Spring Cloud Gateway · Redis · RS256 JWT

## 架構

```
                         ┌──────────────────────────────────────┐
   [ Client ]            │            Auth Center               │
       │                 │  簽發 / 換發 / 撤銷 · RBAC · JWKS    │
       │  Bearer JWT     └──────────────────────────────────────┘
       ▼                        ▲                    │
┌─────────────────┐   /auth/**  │                    │ 公鑰 (JWKS，帶快取)
│   API Gateway   │─────────────┘                    │
│                 │◄─────────────────────────────────┘
│  1 驗簽 (本地)  │
│  2 查撤銷名單   │◄──────────► [ Redis ]  撤銷名單 · Refresh Token · 限流
│  3 粗粒度授權   │
│  4 消毒+注入身分│
└─────────────────┘
       │  X-User-Id / X-User-Roles / X-User-Permissions / X-Auth-Signature
       ▼
  [ 業務微服務 ]  @CurrentUser · @RequiresPermission，完全不碰 Token
```

網關驗簽是本地運算，不需要為了驗證而呼叫授權中心，因此授權中心的可用性
不會直接決定整站的可用性。

網關內的處理順序定義於 [`FilterOrder`](api-gateway/src/main/java/com/example/auth/gateway/support/FilterOrder.java)：
IP 限流 → 認證 → 授權 → 身分注入。

## 模組

| 模組 | 職責 |
|------|------|
| `auth-contract` | Header／Claim 名稱、錯誤碼、`AuthenticatedUser`、HMAC 簽章。不依賴 Spring |
| `auth-center` | 認證、RBAC、使用者管理、Token 生命週期、JWKS。六角架構 |
| `api-gateway` | 路由、驗簽、撤銷檢查、粗粒度授權、限流、身分注入 |
| `auth-client-spring-boot-starter` | 下游服務的 `@CurrentUser` 與 `@RequiresPermission` |
| `sample-order-service` | 示範微服務，沒有任何一行 Token 相關程式碼 |

## 快速開始

```bash
docker compose up -d && mvn -B clean package
```

分別在三個終端啟動：

```bash
java -jar auth-center/target/auth-center-1.0.0-SNAPSHOT.jar --spring.profiles.active=dev
```

```bash
java -jar sample-order-service/target/sample-order-service-1.0.0-SNAPSHOT.jar
```

```bash
java -jar api-gateway/target/api-gateway-1.0.0-SNAPSHOT.jar
```

`dev` profile 必須明確指定，它控制初始化 H2 結構與建立示範帳號。
預設不啟用任何 profile，避免忘記設定的部署把示範帳號寫進真實資料庫。

執行端到端驗證（24 項）：

```bash
bash scripts/smoke-test.sh
```

開發用示範帳號（僅 `dev` profile，密碼於執行期才雜湊）：

| 帳號 | 密碼 | 權限 |
|------|------|------|
| `admin` | `Passw0rd!` | `order:*` `user:manage` |
| `alice` | `Passw0rd!` | `order:read` `order:create` |

```bash
curl -s -X POST http://localhost:8080/auth/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"Passw0rd!"}'
```

## 部署注意事項

**三組必須跨服務一致的設定。** 不一致時的徵狀往往不明顯（例如「登出沒有生效」）：

| 網關／下游服務 | 授權中心 |
|---------------|----------|
| `gateway.auth.revocation.key-prefix` | `auth.token.revocation-key-prefix` |
| `gateway.auth.jwt.issuer` / `audience` | `auth.token.issuer` / `audience` |
| `gateway.auth.identity.signing-secret` | 下游 `auth.client.signing-secret` |

密鑰一律由環境變數或 Secret 注入。啟用簽章卻沒設密鑰時，服務會在啟動階段直接失敗。

**其他：**

- 資料庫結構由 Flyway 管理（`auth-center/src/main/resources/db/migration`）
- 金鑰輪替：先加入新金鑰讓 JWKS 提前發布，再切換 `active-key-id`，等舊 Token 過期才移除舊金鑰
- 分散式追蹤：`docker compose --profile tracing up -d`，以 `TRACING_ENABLED=true` 啟動後看 <http://localhost:16686>

## 設計決策

三個關鍵取捨的完整脈絡記錄在 ADR：

- [ADR-0001](docs/adr/0001-token-verification-strategy.md) — 本地驗簽 vs 每請求 RPC，以及撤銷機制的補救
- [ADR-0002](docs/adr/0002-identity-header-propagation.md) — 身分以 Header 傳遞，為何必須先剝除再簽章
- [ADR-0003](docs/adr/0003-authorization-layering.md) — 網關粗粒度 vs 服務細粒度，以及 fail-closed 的代價

程式碼中的設計模式與其解決的問題，寫在各類別的 Javadoc 中。

## 待辦

- [#3](https://github.com/yaiiow159/auth-gateway-service/issues/3) 整合測試（Testcontainers、WireMock）與 CI
- [#4](https://github.com/yaiiow159/auth-gateway-service/issues/4) KMS 直簽（私鑰不離開 HSM）
