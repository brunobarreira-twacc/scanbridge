#!/usr/bin/env bash
# Initialises a freshly-started local SonarQube for scanbridge testing.
#
# What it does:
#   1. Waits until SonarQube reports status=UP.
#   2. Changes the admin password (SonarQube forces a change on first login).
#   3. Creates a project named SONARQUBE_PROJECT (default: scanbridge-local).
#   4. Generates a USER_TOKEN and prints the three export statements needed
#      to run  scanbridge scan --adapter sonarqube.
#
# Usage:
#   ./setup.sh [project-key]
#
# Env vars (all optional — shown with defaults):
#   SONARQUBE_URL          http://localhost:9000
#   SONARQUBE_ADMIN_PASS   admin          (the SonarQube first-boot default)
#   SONARQUBE_NEW_PASS     SQlocal-pass1  (what the admin password is changed to)
#
# Prerequisites: bash, curl, python3 (standard on macOS/Linux).

set -euo pipefail

SQ_URL="${SONARQUBE_URL:-http://localhost:9000}"
ADMIN_USER="admin"
ADMIN_PASS="${SONARQUBE_ADMIN_PASS:-admin}"
NEW_PASS="${SONARQUBE_NEW_PASS:-SQlocal-pass1}"
PROJECT_KEY="${1:-scanbridge-local}"
TOKEN_NAME="scanbridge-$(date +%s)"

# ── helpers ──────────────────────────────────────────────────────────────────

sq_get_status() {
  curl -sf "$SQ_URL/api/system/status" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null \
    || echo ""
}

sq_api() {
  # sq_api METHOD PATH [-d body] — authenticates with current ADMIN_PASS
  local method="$1"; local path="$2"; shift 2
  curl -sf -X "$method" -u "$ADMIN_USER:$ADMIN_PASS" "$SQ_URL$path" "$@"
}

# ── 1. Wait for SonarQube ────────────────────────────────────────────────────

echo "[1/4] Waiting for SonarQube at $SQ_URL …" >&2
for attempt in $(seq 1 60); do
  status=$(sq_get_status)
  if [ "$status" = "UP" ]; then
    echo "      Ready." >&2
    break
  fi
  printf "      attempt %d/60 — status: '%s'\r" "$attempt" "$status" >&2
  sleep 5
done

if [ "$status" != "UP" ]; then
  echo "" >&2
  echo "ERROR: SonarQube did not reach UP state within 5 minutes." >&2
  exit 1
fi
echo "" >&2

# ── 2. Change admin password ─────────────────────────────────────────────────

echo "[2/4] Setting admin password …" >&2
http_code=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST -u "$ADMIN_USER:$ADMIN_PASS" \
  "$SQ_URL/api/users/change_password" \
  -d "login=$ADMIN_USER&previousPassword=$ADMIN_PASS&password=$NEW_PASS")

if [ "$http_code" = "204" ]; then
  echo "      Password updated." >&2
  ADMIN_PASS="$NEW_PASS"
elif [ "$http_code" = "401" ]; then
  # Already changed — try with the new password.
  echo "      Default password already changed; using SONARQUBE_NEW_PASS." >&2
  ADMIN_PASS="$NEW_PASS"
  # Verify we can authenticate with it.
  check=$(sq_get_status)
  if [ "$check" != "UP" ]; then
    echo "ERROR: Could not authenticate. Set SONARQUBE_ADMIN_PASS to the current password." >&2
    exit 1
  fi
else
  echo "      Password change returned HTTP $http_code — proceeding with current credentials." >&2
fi

# ── 3. Create project ────────────────────────────────────────────────────────

echo "[3/4] Creating project '$PROJECT_KEY' …" >&2
create_code=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST -u "$ADMIN_USER:$ADMIN_PASS" \
  "$SQ_URL/api/projects/create" \
  -d "project=$PROJECT_KEY&name=$PROJECT_KEY&visibility=public")

if [ "$create_code" = "200" ]; then
  echo "      Project created." >&2
elif [ "$create_code" = "400" ]; then
  echo "      Project already exists — skipping." >&2
else
  echo "      WARNING: projects/create returned HTTP $create_code." >&2
fi

# ── 4. Generate token ────────────────────────────────────────────────────────

echo "[4/4] Generating token '$TOKEN_NAME' …" >&2
token_json=$(sq_api POST /api/user_tokens/generate \
  -d "name=$TOKEN_NAME&type=USER_TOKEN")

TOKEN=$(echo "$token_json" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['token'])")

echo "      Token generated." >&2
echo "" >&2

# ── Output ───────────────────────────────────────────────────────────────────

echo "# ── Copy and run these exports, then run scanbridge ────────────────────────"
echo "export SONARQUBE_URL='$SQ_URL'"
echo "export SONARQUBE_TOKEN='$TOKEN'"
echo "export SONARQUBE_PROJECT='$PROJECT_KEY'"
echo ""
echo "# Then from your project root (with .pr-review/tools.yaml in place):"
echo "# node dist/src/cli/main.js scan --adapter sonarqube --output out"
