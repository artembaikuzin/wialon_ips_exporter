build:
	go build -ldflags "-X main.version=$(shell cat VERSION)" .

run:
	go run .

test:
	go test ./...

checks:
	govulncheck ./...
	golangci-lint run ./...
