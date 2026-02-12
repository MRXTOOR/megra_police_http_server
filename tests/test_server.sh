#!/usr/bin/env bash

set -euo pipefail

readonly SERVER_BIN="${1:-}"
readonly SERVER_PORT="1616"
readonly SERVER_URL="http://127.0.0.1:${SERVER_PORT}"
readonly MAX_WAIT_TIME=30
readonly STARTUP_WAIT=3

if [[ -z "${SERVER_BIN}" ]]; then
  echo "Usage: test_server.sh /path/to/megra_police_http_server" >&2
  exit 1
fi

if [[ ! -x "${SERVER_BIN}" ]]; then
  echo "Server binary not found or not executable: ${SERVER_BIN}" >&2
  exit 1
fi

readonly TMP_DIR="$(mktemp -d)"
readonly TMP_FILE="${TMP_DIR}/upload_test.txt"
readonly UPLOADED_FILE_NAME="uploaded_from_test.txt"
readonly SERVER_LOG="${TMP_DIR}/server.log"

# Create test file with more comprehensive content
cat > "${TMP_FILE}" << 'EOF'
test payload
line 2 with special chars: !@#$%^&*()
русский текст для проверки encoding
binary data: 
EOF

# Function to check if server is responding
wait_for_server() {
  local retries=0
  local max_retries=$((MAX_WAIT_TIME / 2))
  
  while (( retries < max_retries )); do
    if curl -sS --max-time 2 --fail "${SERVER_URL}/info" >/dev/null 2>&1; then
      echo "Server is ready after ${retries} attempts"
      return 0
    fi
    
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
      echo "Server process died during startup" >&2
      echo "Server log:" >&2
      cat "${SERVER_LOG}" >&2
      return 1
    fi
    
    sleep 2
    ((retries++))
  done
  
  echo "Server failed to start within ${MAX_WAIT_TIME} seconds" >&2
  echo "Server log:" >&2
  cat "${SERVER_LOG}" >&2
  return 1
}

cleanup() {
  set +e
  
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "Stopping server (PID: ${SERVER_PID})"
    
    # Try graceful shutdown first
    sudo kill -TERM "${SERVER_PID}" 2>/dev/null || true
    sleep 1
    
    # Force kill if still running
    if kill -0 "${SERVER_PID}" 2>/dev/null; then
      sudo kill -KILL "${SERVER_PID}" 2>/dev/null || true
    fi
    
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  
  # Clean up uploaded files
  if [[ -f "/tmp/${UPLOADED_FILE_NAME}" ]]; then
    sudo rm -f "/tmp/${UPLOADED_FILE_NAME}" 2>/dev/null || true
  fi
  
  rm -rf "${TMP_DIR}"
}

trap cleanup EXIT

echo "Starting server: ${SERVER_BIN}"
sudo "${SERVER_BIN}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

echo "Server PID: ${SERVER_PID}"
echo "Waiting for server to start..."

if ! wait_for_server; then
  exit 1
fi

# Test 1: /info endpoint
echo "Testing /info endpoint..."
INFO_RESPONSE="$(curl -sS --max-time 5 --fail "${SERVER_URL}/info" 2>/dev/null)" || {
  echo "Failed to get /info response" >&2
  exit 1
}

# Normalize response (remove trailing newlines for comparison)
INFO_RESPONSE_NORMALIZED="${INFO_RESPONSE%$'\n'}"

if [[ "${INFO_RESPONSE_NORMALIZED}" != "Все ок" ]]; then
  echo "Unexpected /info response: '${INFO_RESPONSE}' (expected 'Все ок')" >&2
  exit 1
fi

echo "/info endpoint works correctly"

# Test 2: /upload endpoint
echo "Testing /upload endpoint..."
UPLOAD_RESPONSE="$(curl -sS --max-time 15 -X POST \
  -F "file=@${TMP_FILE};filename=${UPLOADED_FILE_NAME}" \
  "${SERVER_URL}/upload" 2>/dev/null)" || {
  echo "Failed to upload file" >&2
  exit 1
}

echo "Upload response: ${UPLOAD_RESPONSE}"

if ! grep -q "File uploaded successfully" <<<"${UPLOAD_RESPONSE}"; then
  echo "Upload failed according to server response" >&2
  echo "Full response: '${UPLOAD_RESPONSE}'" >&2
  exit 1
fi

readonly TARGET_PATH="/tmp/${UPLOADED_FILE_NAME}"

if [[ ! -f "${TARGET_PATH}" ]]; then
  echo "Uploaded file not found at ${TARGET_PATH}" >&2
  ls -la /tmp/ | head -10 >&2
  exit 1
fi

if ! diff -q "${TMP_FILE}" "${TARGET_PATH}" >/dev/null; then
  echo "Uploaded file content does not match original" >&2
  echo "Original file:" >&2
  hexdump -C "${TMP_FILE}" | head -5 >&2
  echo "Uploaded file:" >&2  
  hexdump -C "${TARGET_PATH}" | head -5 >&2
  exit 1
fi

echo "File upload works correctly"

# Test 3: /log endpoint
echo "Testing /log endpoint..."
LOG_RESPONSE="$(curl -sS --max-time 5 --fail "${SERVER_URL}/log" 2>/dev/null)" || {
  echo "Failed to get /log response" >&2
  exit 1
}

echo "Log response:"
echo "${LOG_RESPONSE}"
echo "--- End log ---"

# Check for required log entries
if ! grep -q "GET /info 200" <<<"${LOG_RESPONSE}"; then
  echo "Log does not contain 'GET /info 200' entry" >&2
  exit 1
fi

if ! grep -q "POST /upload 200" <<<"${LOG_RESPONSE}"; then
  echo "Log does not contain 'POST /upload 200' entry" >&2
  exit 1
fi

# Count log entries (should have at least 3: /info, /upload, /log)
LOG_LINES="$(echo "${LOG_RESPONSE}" | grep -c "127.0.0.1" || true)"
if (( LOG_LINES < 3 )); then
  echo "Expected at least 3 log entries, got ${LOG_LINES}" >&2
  exit 1
fi

echo "Logging works correctly"

# Test 4: Error handling (404)
echo "Testing 404 error handling..."
if curl -sS --max-time 5 --fail "${SERVER_URL}/nonexistent" >/dev/null 2>&1; then
  echo "Expected 404 error for /nonexistent, but request succeeded" >&2
  exit 1
fi

echo "404 error handling works correctly"

# Test 5: Invalid upload (empty file)
echo "Testing invalid upload handling..."
EMPTY_FILE="${TMP_DIR}/empty.txt"
touch "${EMPTY_FILE}"

INVALID_RESPONSE="$(curl -sS --max-time 10 -X POST \
  -F "file=@${EMPTY_FILE};filename=empty.txt" \
  "${SERVER_URL}/upload" 2>/dev/null || true)"

if grep -q "File uploaded successfully" <<<"${INVALID_RESPONSE}"; then
  echo "Empty file upload should not succeed, but it did" >&2
  exit 1
fi

echo "Invalid upload handling works correctly"

echo ""
echo "All tests passed successfully."
echo "Server startup and health check"
echo "/info endpoint functionality" 
echo "File upload functionality"
echo "Logging functionality"
echo "404 error handling"
echo "Invalid upload handling"

