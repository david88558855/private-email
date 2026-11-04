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

# 双平台发布构建（linux + win 一次出齐）
VERSION ?= $(shell git log -1 --pretty=%h)
release:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(V)" -o dist/private-email-linux-x64 ./cmd/server
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(V)" -o dist/private-email-win-x64.exe ./cmd/server
	@echo "dist/ 双平台产物就绪：$(V)"
