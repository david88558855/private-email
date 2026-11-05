APP     := private-email
# 版本号优先级：make 传参 > git tag/短哈希 > 时间戳
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || date +%Y%m%d-%H%M)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build build-linux build-win release test clean version

build: build-linux build-win

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-linux-x64 ./cmd/server

build-win:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-win-x64.exe ./cmd/server

# 双平台发布构建（与 build 一致，保留别名以兼容旧用法）
release: build
	@echo "dist/ 双平台产物就绪：$(VERSION)"

test:
	go test ./...

version:
	@echo $(VERSION)

clean:
	rm -rf dist
