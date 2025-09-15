build:
	@(GOARCH=arm64 GOOS=linux go build -o bootstrap main.go && zip main.zip bootstrap)

test:
	go test ./...
