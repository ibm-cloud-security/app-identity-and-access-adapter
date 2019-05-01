#!/usr/bin/env bash
# This script builds the imcloudappid adapter executable

echo Building Linux Executable

# Remove old executable
rm -f bin/ibmcloudappid

# Compile new executable
env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a -installsuffix cgo -v -o bin/ibmcloudappid ./cmd/main.go
