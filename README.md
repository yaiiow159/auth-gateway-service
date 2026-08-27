# auth-gateway-service

微服務架構下的 API Gateway 與授權中心，採「**集中認證、網關校驗、服務明文**」模式：
認證與授權的複雜度收斂在兩個元件內，業務微服務只需要面對一個已驗證的使用者物件。

Java 21 · Spring Boot 3.3 · Spring Cloud Gateway 2023.0 · Redis · RS256 JWT

---

## 架構總覽

```
                         ┌──────────────────────────────────────┐
   [ Client ]            │            Auth Center               │
       │                 │  簽發 / 換發 / 撤銷 · RBAC · JWKS    │
       │  Bearer JWT     └──────────────────────────────────────┘
       ▼                        ▲                    │
┌─────────────────┐   /auth/**  │                    │ 公鑰 (JWKS，帶快取)
│   API Gateway   │─────────────┘                    │ 每次啟動或輪替才抓一次
│                 │◄─────────────────────────────────┘
│  1 驗簽 (本地)  │
│  2 查撤銷名單   │◄──────────► [ Redis ]  撤銷名單 · Refresh Token · 限流計數
│  3 粗粒度授權   │
│  4 消毒+注入身分│
└─────────────────┘
       │  X-User-Id / X-User-Roles / X-User-Permissions / X-Auth-Signature
       ▼
┌──────────────────────────────────────────────────────────────┐
│  業務微服務（引入 auth-client-spring-boot-starter）           │
│  @CurrentUser AuthenticatedUser · @RequiresPermission        │
│  完全不碰 Token、金鑰、JWKS                                   │
└──────────────────────────────────────────────────────────────┘
```

**關鍵設計：網關驗簽是本地運算，不需要為了驗證而呼叫授權中心。**
授權中心只在「登入、換發、登出」時被呼叫，不在每個請求的關鍵路徑上，
因此它的可用性不會直接決定整站的可用性。（見 [ADR-0001](docs/adr/0001-token-verification-strategy.md)）

## 請求在網關內的生命週期

順序定義於 [`FilterOrder`](api-gateway/src/main/java/com/example/auth/gateway/support/FilterOrder.java)，
任何調換都可能造成安全問題，因此集中成常數而非散落的魔術數字。

| 順序 | 過濾器 | 職責 |
|------|--------|------|
| -1000 | `RequestIdGlobalFilter` | 補齊 `X-Request-Id`，讓全鏈路日誌可串接 |
| -900 | `AuthenticationGlobalFilter` | 取出 Token → 驗簽 → 查撤銷名單 → 解析出身分 |
| -800 | `AuthorizationGlobalFilter` | 依路徑規則做粗粒度授權判定 |
| -700 | `IdentityPropagationGlobalFilter` | **剝除**偽造 Header → 注入可信身分 → HMAC 簽章 |
| 0+ | Spring Cloud Gateway 內建 | 限流、StripPrefix、路由轉發 |

## 模組職責

| 模組 | 職責 |
|------|------|
| `auth-contract` | Header 名稱、Claim 名稱、錯誤碼、`AuthenticatedUser`、HMAC 簽章演算法。不依賴 Spring，任何 JVM 服務都能引用 |
| `auth-center` | 身分認證、RBAC、Token 簽發／換發／撤銷、JWKS 發布。採六角架構（domain / application / infrastructure / interfaces） |
| `api-gateway` | 路由、本地驗簽、撤銷檢查、粗粒度授權、限流、身分注入 |
| `auth-client-spring-boot-starter` | 下游服務的整合套件：解析並驗證身分 Header，提供 `@CurrentUser` 與 `@RequiresPermission` |
| `sample-order-service` | 示範下游服務長什麼樣子 —— 沒有任何一行 Token 相關程式碼 |

## 技術選型與理由

| 選擇 | 理由 |
|------|------|
| **RS256（非對稱）而非 HS256** | 驗證方只需要公鑰。用 HS256 的話密鑰得分發給每個服務，任一服務被入侵等同於簽發能力外洩 |
| **JWKS + `NimbusReactiveJwtDecoder`** | 解碼器內建快取與 `kid` 未命中時的自動重抓，金鑰輪替不需要重啟網關 |
| **Refresh Token 用不透明隨機字串而非 JWT** | 它本來就必須被伺服端記錄才能支援輪替與撤銷；既然狀態無法避免，就不必再付 JWT 的體積與解析成本 |
| **撤銷名單 TTL = Token 剩餘壽命** | Token 過期後本來就無效，紀錄自然可以消失。黑名單大小因此是常數級而非隨時間膨脹 |
| **網關用 WebFlux，授權中心用 MVC + 虛擬執行緒** | 網關是 IO 轉發密集、連線數極高的場景，響應式是對的；授權中心是一般 CRUD，用虛擬執行緒即可拿到併發，不必付響應式的除錯與可讀性代價 |
| **Spring Cloud Gateway 內建 `RedisRateLimiter`** | Redis Lua 實作的權杖桶，跨副本一致。自己重寫分散式限流很難寫對，沒有必要 |
| **不引入 `spring-boot-starter-security`** | 網關的認證流程由自訂 `GlobalFilter` 主導；多一條 Spring Security 過濾器鏈只會讓「請求到底被誰擋下」難以追查。只取所需的 `spring-security-oauth2-jose` 與 `spring-security-crypto` |
| **Lettuce 不設連線池** | Lettuce 連線是執行緒安全且多工複用的，加連線池反而增加資源與延遲 |

## 設計模式使用索引

模式是用來解決具體問題的，不是為了用而用。以下每一項都對應一個實際的變更壓力：

| 模式 | 位置 | 解決什麼問題 |
|------|------|--------------|
| **策略 Strategy** | `TokenVerifier`（本地驗簽 / 遠端自省）、`TokenExtractor`、`PasswordHasher`、`RsaKeyProvider` | 驗證方式、憑證來源、雜湊演算法、金鑰來源都會隨需求與時間改變 |
| **裝飾器 Decorator** | `RevocationAwareTokenVerifier`、`CachingUserAccountRepository` | 「驗簽」與「查撤銷」、「取資料」與「快取」是各自獨立變化的關注點 |
| **責任鏈 Chain of Responsibility** | `AccessPolicyChain` + `AccessDecision.ABSTAIN` | 讓每個授權策略只回答自己管得到的部分，新增策略不必修改既有程式碼 |
| **組合 Composite** | `CompositeTokenExtractor` | 多來源憑證的取得順序，不該汙染認證過濾器的主流程 |
| **工廠 Factory** | `TokenPairFactory` | 登入與換發共用同一段憑證組裝，加新 Claim 時只有一個修改點 |
| **埠與轉接器 Ports & Adapters** | `auth-center` 的 `domain.port` 對 `infrastructure.*` | 領域規則不該知道資料存在 JPA、Redis 還是 KMS |
| **代數資料型別 (sealed + record)** | `AuthenticationResult.Success / Failure` | 把「可能的狀態」寫進型別，switch 由編譯器保證窮盡 |
| **值物件 Value Object** | `UserId`、`AuthenticatedUser` | 型別層級就避免把租戶 ID 傳成使用者 ID；不可變物件杜絕身分被中途竄改 |
| **樣板 + AOP** | `PermissionCheckAspect` | 權限檢查是橫切關注點，散落各處必然有人漏寫 |

## 快速開始

```bash
docker compose up -d
```

```bash
mvn -B clean package
```

分別在三個終端啟動（或用 IDE 執行）：

```bash
java -jar auth-center/target/auth-center-1.0.0-SNAPSHOT.jar
```

```bash
java -jar sample-order-service/target/sample-order-service-1.0.0-SNAPSHOT.jar
```

```bash
java -jar api-gateway/target/api-gateway-1.0.0-SNAPSHOT.jar
```

執行端到端驗證（涵蓋認證、授權、防偽造、Token 生命週期共 13 項）：

```bash
bash scripts/smoke-test.sh
```

開發用示範帳號（僅 `dev` profile，密碼於執行期才雜湊，不會出現在版控中）：

| 帳號 | 密碼 | 角色 | 權限 |
|------|------|------|------|
| `admin` | `Passw0rd!` | `ROLE_ADMIN` | `order:read` `order:create` `order:delete` `user:manage` |
| `alice` | `Passw0rd!` | `ROLE_USER` | `order:read` `order:create` |

手動試一次：

```bash
curl -s -X POST http://localhost:8080/auth/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"Passw0rd!"}'
```

## 必須成對一致的設定

以下三組設定分屬不同服務，值不一致時的故障徵狀往往不明顯（例如「登出沒有生效」），
上線前務必檢查：

| 網關 / 服務端 | 授權中心 | 不一致的後果 |
|---------------|----------|--------------|
| `gateway.auth.revocation.key-prefix` | `auth.token.revocation-key-prefix` | 撤銷名單查不到，登出形同無效 |
| `gateway.auth.jwt.issuer` / `audience` | `auth.token.issuer` / `audience` | 所有 Token 一律驗證失敗 |
| `gateway.auth.identity.signing-secret` | 下游服務 `auth.client.signing-secret` | 所有請求在下游被判為簽章失敗 |

正式環境的密鑰一律由環境變數或 Secret 注入。啟用簽章卻沒設密鑰時，
服務會在**啟動階段直接失敗**，而不是帶著「以為有驗、其實沒驗」的設定跑起來。

## 安全設計要點

1. **身分 Header 一律先剝除再注入。** 消毒動作對匿名請求同樣執行 —— 否則攻擊者只要挑一條公開端點，就能把偽造的 `X-User-Id` 送進後端。
2. **注入的身分帶 HMAC 簽章。** 下游即使被繞過網關直連也能識破偽造請求。（見 [ADR-0002](docs/adr/0002-identity-header-propagation.md)）
3. **授權預設 fail-closed。** 未被規則涵蓋的路徑一律 `DENY`。代價是新增路由必須同步加規則，好處是漏配的下場是 403 而不是裸奔。（見 [ADR-0003](docs/adr/0003-authorization-layering.md)）
4. **Token 類型檢查。** 驗證器要求 `typ=access`，擋下拿 Refresh Token 當 Access Token 用的提權手法。
5. **`jti` 為必要 Claim。** 沒有它的 Token 無法被撤銷，等於一張收不回來的通行證。
6. **Refresh Token 一次性輪替。** 以 Redis `GETDEL` 單一原子指令完成，併發重放只有一個會成功。
7. **登入錯誤訊息不區分「帳號不存在」與「密碼錯誤」**，避免成為帳號列舉的側信道。
8. **`/internal/**` 不建立網關路由**，內部端點在網關層就不可能被外部觸及。

## 上正式環境前尚須補齊

這是一份可運行的架構骨架，以下項目刻意留白，因為它們的正確做法高度依賴實際的基礎設施：

- **資料庫遷移**：目前用 `schema.sql` + `data.sql`，正式環境應改為 Flyway 或 Liquibase。
- **金鑰管理**：`InMemoryRsaKeyProvider` 僅供單機開發（多副本會各持一把私鑰）。正式環境請實作 KMS / Vault 的 `RsaKeyProvider` Adapter，並規劃輪替流程 —— `publicJwkSet()` 已預留同時發布新舊公鑰的能力。
- **使用者與角色管理 API**：目前只有讀取路徑，寫入路徑（建帳號、指派角色）尚未實作。
- **遠端驗證模式的斷路器**：`verification-mode: REMOTE` 目前只有逾時保護，正式使用需補上 Resilience4j 斷路器與結果快取。
- **可觀測性**：已暴露 Prometheus 端點，但尚未接上 OpenTelemetry 的分散式追蹤。
- **整合測試**：現有 27 個單元測試涵蓋核心邏輯，建議再補上 Testcontainers（Redis）與 WireMock（JWKS）的整合測試。

## 專案結構

```
auth-gateway-service/
├── auth-contract/                     共享契約（無 Spring 依賴）
├── auth-center/                       授權中心
│   └── domain / application / infrastructure / interfaces
├── api-gateway/                       網關
│   └── authentication / authorization / filter / identity / config / support
├── auth-client-spring-boot-starter/   下游服務整合套件
├── sample-order-service/              示範微服務
├── docs/adr/                          架構決策紀錄
└── scripts/smoke-test.sh              端到端驗證
```
