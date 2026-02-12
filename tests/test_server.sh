#!/usr/bin/env bash

set -euo pipefail

SERVER_BIN="${1:-}"

if [[ -z "${SERVER_BIN}" ]]; then
  echo "Usage: test_server.sh /path/to/megra_police_http_server" >&2
  exit 1
fi

if [[ ! -x "${SERVER_BIN}" ]]; then
  echo "Server binary not found or not executable: ${SERVER_BIN}" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
TMP_FILE="${TMP_DIR}/upload_test.txt"
UPLOADED_FILE_NAME="uploaded_from_test.txt"

echo "test payload" > "${TMP_FILE}"

cleanup() {
  set +e
  if [[ -n "${SERVER_PID:-}" ]]; then
    sudo kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${TMP_DIR}"
}

trap cleanup EXIT

sudo "${SERVER_BIN}" >"${TMP_DIR}/server.log" 2>&1 &
SERVER_PID=$!

sleep 2

INFO_RESPONSE="$(curl -sS --max-time 5 http://127.0.0.1:1616/info)"

if [[ "${INFO_RESPONSE}" != "Все ок" && "${INFO_RESPONSE}" != "Все ок"$'\n' ]]; then
  echo "Unexpected /info response: '${INFO_RESPONSE}'" >&2
  exit 1
fi

UPLOAD_RESPONSE="$(curl -sS --max-time 10 -X POST -F "file=@${TMP_FILE};filename=${UPLOADED_FILE_NAME}" http://127.0.0.1:1616/upload)"

echo "Upload response: ${UPLOAD_RESPONSE}"

if ! grep -q "File uploaded successfully" <<<"${UPLOAD_RESPONSE}"; then
  echo "Upload failed according to server response" >&2
  exit 1
fi

TARGET_PATH="/tmp/${UPLOADED_FILE_NAME}"

if [[ ! -f "${TARGET_PATH}" ]]; then
  echo "Uploaded file not found at ${TARGET_PATH}" >&2
  exit 1
fi

if ! diff -q "${TMP_FILE}" "${TARGET_PATH}" >/dev/null; then
  echo "Uploaded file content does not match original" >&2
  exit 1
fi

LOG_RESPONSE="$(curl -sS --max-time 5 http://127.0.0.1:1616/log)"

echo "Log response:"
echo "${LOG_RESPONSE}"

if ! grep -q "/info 200" <<<"${LOG_RESPONSE}"; then
  echo "Log does not contain /info 200 entry" >&2
  exit 1
fi

if ! grep -q "/upload 200" <<<"${LOG_RESPONSE}"; then
  echo "Log does not contain /upload 200 entry" >&2
  exit 1
fi

echo "All tests passed."

