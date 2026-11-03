// Package web 内嵌前端构建产物（web/dist），单文件二进制的 UI 载体。
package web

import "embed"

//go:embed dist
var Dist embed.FS
