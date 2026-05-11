#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-10.0.0.30}"

echo "[1/4] Reconnaissance simulation against ${TARGET}"
if command -v nmap >/dev/null 2>&1; then
  nmap -Pn -sS -p 22,80,443,8080 "${TARGET}" || true
else
  echo "nmap not found; skipping active scan"
fi

echo "[2/4] Service probing simulation"
for path in / /login /admin; do
  curl -m 2 -s "http://${TARGET}${path}" >/dev/null || true
done

echo "[3/4] Authentication pressure simulation (safe)"
for i in $(seq 1 10); do
  timeout 1 bash -c "</dev/tcp/${TARGET}/22" >/dev/null 2>&1 || true
  sleep 0.2
done

echo "[4/4] Lateral movement simulation marker"
for i in $(seq 1 5); do
  ping -c 1 "${TARGET}" >/dev/null 2>&1 || true
  sleep 0.2
done

echo "Attack simulation sequence completed."
