VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build windows linux test vet vulncheck fmt clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/proctrace ./cmd/proctrace

windows:
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/proctrace.exe ./cmd/proctrace

linux:
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/proctrace-linux-amd64 ./cmd/proctrace

test:
	go test -race ./...

vet:
	go vet ./...
	GOOS=windows go vet ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	GOOS=windows go run golang.org/x/vuln/cmd/govulncheck@latest ./...

fmt:
	gofmt -w .

clean:
	rm -rf bin