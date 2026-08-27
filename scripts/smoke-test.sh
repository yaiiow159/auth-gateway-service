#!/usr/bin/env bash
# 端到端煙霧測試：驗證整條認證授權鏈是否接通。
#
# 前置：docker compose up -d，且三個服務都已啟動
#   java -jar auth-center/target/auth-center-1.0.0-SNAPSHOT.jar --spring.profiles.active=dev
#   java -jar sample-order-service/target/sample-order-service-1.0.0-SNAPSHOT.jar
#   java -jar api-gateway/target/api-gateway-1.0.0-SNAPSHOT.jar
set -uo pipefail

GATEWAY=${GATEWAY:-http://localhost:8080}
ORDER_SERVICE=${ORDER_SERVICE:-http://localhost:9100}

passed=0
failed=0

check() {
  local name=$1 expected=$2 actual=$3
  if [ "$expected" = "$actual" ]; then
    printf '  [PASS] %-52s %s\n' "$name" "$actual"
    passed=$((passed + 1))
  else
    printf '  [FAIL] %-52s 預期 %s，實得 %s\n' "$name" "$expected" "$actual"
    failed=$((failed + 1))
  fi
}

status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

login() {
  curl -s -X POST "$GATEWAY/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}"
}

json_field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }

refresh_with() {
  status -X POST "$GATEWAY/auth/refresh" -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$1\"}"
}

# /auth/** 的配額是 5 req/s、burst 10，而本腳本走的全是同一個來源 IP。
# 不停頓的話，後段的斷言會拿到 429 而非受測端點的真實回應 —— 那是腳本自己造成的
# 假失敗，不是產品缺陷。在對限流敏感的區段之前先讓權杖桶回補。
pace() { sleep 3; }

echo '1. 認證'
check '未帶憑證存取受保護資源' 401 "$(status "$GATEWAY/api/orders")"
check '錯誤密碼被拒絕' 401 "$(status -X POST "$GATEWAY/auth/login" -H 'Content-Type: application/json' -d '{"username":"alice","password":"wrong"}')"

USER_TOKEN=$(login alice 'Passw0rd!' | json_field accessToken)
ADMIN_TOKEN=$(login admin 'Passw0rd!' | json_field accessToken)
check '登入成功並取得 Access Token' 'yes' "$([ -n "$USER_TOKEN" ] && echo yes || echo no)"

echo '2. 授權（網關粗粒度）'
check 'alice 具備 order:read，GET 放行' 200 "$(status -H "Authorization: Bearer $USER_TOKEN" "$GATEWAY/api/orders")"
check 'alice 缺少 order:delete，DELETE 被拒' 403 "$(status -X DELETE -H "Authorization: Bearer $USER_TOKEN" "$GATEWAY/api/orders/ORD-1")"
check 'admin 具備 order:delete，DELETE 放行' 200 "$(status -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" "$GATEWAY/api/orders/ORD-1")"

echo '3. 身分傳遞與防偽造'
FORGED=$(curl -s -H "Authorization: Bearer $USER_TOKEN" \
  -H 'X-User-Id: 1' -H 'X-User-Roles: ROLE_SUPER_ADMIN' \
  "$GATEWAY/api/orders/whoami" | json_field userId)
check '客戶端偽造的 X-User-Id 被網關剝除' '2048' "$FORGED"
check '繞過網關直連服務的偽造身分被驗章擋下' 401 \
  "$(status -H 'X-User-Id: 1' -H 'X-User-Roles: ROLE_SUPER_ADMIN' "$ORDER_SERVICE/orders/whoami")"
check '內部端點未經網關對外暴露' 404 \
  "$(status -X POST "$GATEWAY/internal/tokens/introspect" -H 'Content-Type: application/json' -d '{"token":"x"}')"

pace
echo '4. Token 生命週期'
REFRESH=$(login alice 'Passw0rd!' | json_field refreshToken)
check 'Refresh Token 首次換發成功' 200 \
  "$(status -X POST "$GATEWAY/auth/refresh" -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$REFRESH\"}")"
check 'Refresh Token 輪替後不可重複使用' 401 \
  "$(status -X POST "$GATEWAY/auth/refresh" -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$REFRESH\"}")"

# 重放偵測：攻擊者搶先換發成功後，受害者拿舊 Token 撞上 401，
# 此時攻擊者手上那條輪替鏈也必須一併失效，否則偵測形同虛設
pace
REPLAYED=$(login alice 'Passw0rd!' | json_field refreshToken)
ROTATED=$(curl -s -X POST "$GATEWAY/auth/refresh" -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$REPLAYED\"}" | json_field refreshToken)
refresh_with "$REPLAYED" > /dev/null
check '偵測到重放後整條憑證鏈被撤銷' 401 "$(refresh_with "$ROTATED")"

pace
SESSION=$(login alice 'Passw0rd!')
LOGOUT_TOKEN=$(echo "$SESSION" | json_field accessToken)
LOGOUT_REFRESH=$(echo "$SESSION" | json_field refreshToken)
check '登出成功' 204 \
  "$(status -X POST "$GATEWAY/auth/logout" -H "Authorization: Bearer $LOGOUT_TOKEN" -H 'Content-Type: application/json' -d '{}')"
check '登出後 Access Token 立即失效' 401 \
  "$(status -H "Authorization: Bearer $LOGOUT_TOKEN" "$GATEWAY/api/orders")"
check '登出後 Refresh Token 一併失效（未附於請求中）' 401 "$(refresh_with "$LOGOUT_REFRESH")"

pace
echo '5. 錯誤語意'
check '格式錯誤的 JSON 回 400 而非 503' 400 \
  "$(status -X POST "$GATEWAY/auth/login" -H 'Content-Type: application/json' -d 'not-json')"
check '不支援的方法回 405 而非 503' 405 \
  "$(status -X DELETE "$GATEWAY/auth/login")"

echo
echo "通過 $passed 項，失敗 $failed 項"
[ "$failed" -eq 0 ]
