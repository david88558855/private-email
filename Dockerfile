# 多阶段：纯 Go 静态编译 → scratch 运行（单文件二进制）
FROM golang:1.27.3-alpine AS build
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags "-s -w -X main.version=$(date +%Y%m%d)" -o /out/private-email ./cmd/server

FROM scratch
COPY --from=build /out/private-email /private-email
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
WORKDIR /app
VOLUME /app/data
EXPOSE 9000 25 465 587 143 993 110 995
ENTRYPOINT ["/private-email", "-data", "/app/data"]
