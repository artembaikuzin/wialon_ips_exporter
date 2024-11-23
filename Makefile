build:
	go build .

run:
	go run .

test:
	go test ./...

checks:
	govulncheck ./...
	golangci-lint run ./...
