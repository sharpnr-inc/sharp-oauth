#!/usr/bin/env bash
#
# Walks through the complete "Sign in with Sharpnr" flow with curl, playing
# both the user's browser and a third-party client application.
#
# Usage:
#   cargo run -- create-client --name "Demo App" \
#       --redirect-uri http://localhost:4000/callback \
#       --scopes "openid profile email offline_access"
#   cargo run            # in another terminal
#   CLIENT_ID=... CLIENT_SECRET=... scripts/demo-flow.sh
#
# Requires: curl, jq, openssl.

set -euo pipefail

BASE="${ISSUER_URL:-http://localhost:3000}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:4000/callback}"
: "${CLIENT_ID:?set CLIENT_ID}"
: "${CLIENT_SECRET:?set CLIENT_SECRET}"
EMAIL="${EMAIL:-demo-$RANDOM@example.com}"
PASSWORD="${PASSWORD:-demo-password-123}"

JAR="$(mktemp)"            # the "browser" cookie jar
trap 'rm -f "$JAR"' EXIT

step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
# Prints the value of a hidden form field from HTML on stdin.
hidden() { grep -o "name=\"$1\" value=\"[^\"]*\"" | head -1 | sed 's/.*value="\(.*\)"/\1/' | sed 's/&amp;/\&/g'; }
# Prints a query parameter from a URL.
param() { sed -n "s/.*[?&]$1=\([^&]*\).*/\1/p" | python3 -c 'import sys,urllib.parse;print(urllib.parse.unquote_plus(sys.stdin.read().strip()))'; }

step "Client app: create a PKCE verifier and challenge"
VERIFIER="$(openssl rand 32 | b64url)"
CHALLENGE="$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | b64url)"
STATE="$(openssl rand 16 | b64url)"
NONCE="$(openssl rand 16 | b64url)"
echo "code_verifier  = $VERIFIER   (kept secret by the client)"
echo "code_challenge = $CHALLENGE  (sent in the browser redirect)"

step "Browser: create a Sharpnr account ($EMAIL)"
SIGNUP_PAGE="$(curl -s -c "$JAR" -b "$JAR" "$BASE/signup")"
CSRF="$(hidden csrf_token <<<"$SIGNUP_PAGE")"
curl -s -o /dev/null -w 'POST /signup -> %{http_code} %{redirect_url}\n' -c "$JAR" -b "$JAR" \
  --data-urlencode "csrf_token=$CSRF" --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=$PASSWORD" --data-urlencode "display_name=Demo User" \
  "$BASE/signup"

step "Browser: follow the client's link to /oauth/authorize"
AUTHORIZE_URL="$BASE/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$(jq -rn --arg v "$REDIRECT_URI" '$v|@uri')&scope=openid%20profile%20email%20offline_access&state=$STATE&nonce=$NONCE&code_challenge=$CHALLENGE&code_challenge_method=S256"
CONSENT_PAGE="$(curl -s -c "$JAR" -b "$JAR" "$AUTHORIZE_URL")"
grep -o '<li>[^<]*</li>' <<<"$CONSENT_PAGE" | sed 's/<[^>]*>//g; s/^/  consent asks: /'

step "Browser: click Allow"
FORM_ARGS=()
for field in client_id redirect_uri response_type scope state code_challenge code_challenge_method nonce csrf_token; do
  FORM_ARGS+=(--data-urlencode "$field=$(hidden "$field" <<<"$CONSENT_PAGE")")
done
CALLBACK="$(curl -s -o /dev/null -w '%{redirect_url}' -c "$JAR" -b "$JAR" "${FORM_ARGS[@]}" \
  --data-urlencode "decision=approve" "$BASE/oauth/consent")"
echo "redirected to: $CALLBACK"
CODE="$(param code <<<"$CALLBACK")"
[[ "$(param state <<<"$CALLBACK")" == "$STATE" ]] && echo "state matches ✓"

step "Client app: exchange the code (with code_verifier) at /oauth/token"
TOKENS="$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode grant_type=authorization_code --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" --data-urlencode "code_verifier=$VERIFIER" \
  "$BASE/oauth/token")"
jq '{token_type, expires_in, scope, access_token: (.access_token[:24] + "…"), refresh_token: (.refresh_token[:12] + "…"), id_token: (.id_token[:24] + "…")}' <<<"$TOKENS"
ACCESS_TOKEN="$(jq -r .access_token <<<"$TOKENS")"
REFRESH_TOKEN="$(jq -r .refresh_token <<<"$TOKENS")"

step "Client app: decode the ID token payload (a real client also verifies the signature via JWKS)"
jq -rR 'split(".")[1] | gsub("-";"+") | gsub("_";"/") | . + ("=" * ((4 - length % 4) % 4)) | @base64d | fromjson' \
  <<<"$(jq -r .id_token <<<"$TOKENS")"
echo "(nonce should be $NONCE)"

step "Client app: call /oauth/userinfo"
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "$BASE/oauth/userinfo" | jq .

step "Client app: refresh (rotation gives a new refresh token)"
REFRESHED="$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode grant_type=refresh_token --data-urlencode "refresh_token=$REFRESH_TOKEN" "$BASE/oauth/token")"
jq 'if .error then . else {scope, new_refresh_token: (.refresh_token[:12] + "…")} end' <<<"$REFRESHED"

step "Attacker: replay the old refresh token (the whole family gets revoked)"
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode grant_type=refresh_token --data-urlencode "refresh_token=$REFRESH_TOKEN" "$BASE/oauth/token" | jq .

step "Client app: the newest refresh token is now revoked too"
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode grant_type=refresh_token --data-urlencode "refresh_token=$(jq -r .refresh_token <<<"$REFRESHED")" \
  "$BASE/oauth/token" | jq .

step "Attacker: redeem the same authorization code again (rejected; tokens it issued are revoked)"
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode grant_type=authorization_code --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" --data-urlencode "code_verifier=$VERIFIER" \
  "$BASE/oauth/token" | jq .

printf '\n\033[1;32mDone.\033[0m\n'
