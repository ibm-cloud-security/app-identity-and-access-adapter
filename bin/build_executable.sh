# This script builds the imcloudappid adapter executable

echo Building Linux Executable
rm -f bin/ibmcloudappid
env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a -installsuffix cgo -v -o bin/ibmcloudappid ./cmd/main.go
#chmod +x ibmcloudappid