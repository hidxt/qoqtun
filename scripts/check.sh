#!/usr/bin/env bash
# qoqtun one-shot verification: fmt -> vet -> build -> cross-build -> test -> race.
# Run from anywhere; fails on first error.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== gofmt -l . (must be empty) =="
out=$(gofmt -l .)
if [ -n "$out" ]; then
  echo "$out"
  echo "FAIL: gofmt reports unformatted files" >&2
  exit 1
fi

echo "== go vet ./... =="
go vet ./...

echo "== go build ./... =="
go build ./...

echo "== cross builds (windows/linux/darwin) =="
GOOS=windows GOARCH=amd64 go build ./...
GOOS=linux   GOARCH=amd64 go build ./...
GOOS=darwin  GOARCH=amd64 go build ./...

echo "== go test ./... =="
go test ./...

echo "== go test -race ./... =="
go test -race ./...

echo "ALL CHECKS PASSED"
