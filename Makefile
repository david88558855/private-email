APP    := private-email
VERSION ?= $(shell date +%Y%m%d-%H%M)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build build-linux build-win test clean

build: build-linux build-win

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-linux-x64 ./cmd/server

build-win:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-win-x64.exe ./cmd/server

test:
	go test ./...

clean:
	rm -rf dist
