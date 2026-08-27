#!/usr/bin/env bash
# 端到端煙霧測試：驗證整條認證授權鏈是否接通。
#
# 前置：docker compose up -d，且三個服務都已啟動
#   java -jar auth-center/target/auth-center-1.0.0-SNAPSHOT.jar
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

echo '4. Token 生命週期'
REFRESH=$(login alice 'Passw0rd!' | json_field refreshToken)
check 'Refresh Token 首次換發成功' 200 \
  "$(status -X POST "$GATEWAY/auth/refresh" -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$REFRESH\"}")"
check 'Refresh Token 輪替後不可重複使用' 401 \
  "$(status -X POST "$GATEWAY/auth/refresh" -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$REFRESH\"}")"

LOGOUT_TOKEN=$(login alice 'Passw0rd!' | json_field accessToken)
check '登出成功' 204 \
  "$(status -X POST "$GATEWAY/auth/logout" -H "Authorization: Bearer $LOGOUT_TOKEN" -H 'Content-Type: application/json' -d '{}')"
check '登出後 Access Token 立即失效' 401 \
  "$(status -H "Authorization: Bearer $LOGOUT_TOKEN" "$GATEWAY/api/orders")"

echo
echo "通過 $passed 項，失敗 $failed 項"
[ "$failed" -eq 0 ]
