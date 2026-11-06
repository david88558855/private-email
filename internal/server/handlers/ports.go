package handlers

import (
	"net"
	"net/http"
	"strings"

	"github.com/david88558855/private-email/internal/config"
	"github.com/gin-gonic/gin"
)

// 端口类设置键：value = ":25" / "127.0.0.1:25" / ""（关闭）
var listenerKeys = []string{
	"smtp_listen", "smtp_submission", "smtp_tls",
	"imap_listen", "imap_tls",
	"pop3_listen", "pop3_tls",
}

// Ports GET /api/v1/admin/ports —— 当前监听端口（设置表，缺省继承 config.yaml）。
func (h *MailHandler) Ports(c *gin.Context) {
	if !adminOK(c) {
		return
	}
	out := map[string]string{}
	for _, k := range listenerKeys {
		v, err := h.Store.GetSetting(k)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "读取设置失败"})
			return
		}
		out[k] = v
	}
	c.JSON(http.StatusOK, gin.H{"items": out})
}

// PortsPut PUT /api/v1/admin/ports —— 保存端口设置（重启后生效）。
func (h *MailHandler) PortsPut(c *gin.Context) {
	if !adminOK(c) {
		return
	}
	var req map[string]string
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	normalized := map[string]string{}
	for k, v := range req {
		valid := false
		for _, kk := range listenerKeys {
			if kk == k {
				valid = true
				break
			}
		}
		if !valid {
			c.JSON(http.StatusBadRequest, gin.H{"error": "未知设置项 " + k})
			return
		}
		v = strings.TrimSpace(v)
		// 纯数字 → 自动补冒号（UI 输入 25 即 :25）
		if v != "" && !strings.Contains(v, ":") {
			v = ":" + v
		}
		if v != "" && !validListen(v) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "端口格式错误：" + v + "（应为 25 或 0.0.0.0:25）"})
			return
		}
		normalized[k] = v
	}
	// 合并「本次修改 + 未提交的现值」后再查重：只提交一个键时也要能发现冲突。
	// HTTP 端口不在这里，由启动期 ValidateListenPorts 连同 7 个协议一起校验。
	final := map[string]string{}
	for _, k := range listenerKeys {
		if v, ok := normalized[k]; ok {
			final[k] = v
			continue
		}
		v, err := h.Store.GetSetting(k)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "读取设置失败"})
			return
		}
		final[k] = v
	}
	if err := config.ValidateListenPorts(final); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// 校验全部通过才写库，避免中途失败留下半套端口配置。
	for k, v := range normalized {
		if err := h.Store.SetSetting(k, v); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败"})
			return
		}
	}
	h.Store.DB.Exec(`INSERT INTO audit_logs(user_id, action, detail) VALUES(?,?,?)`,
		c.GetInt64("user_id"), "settings_ports", "update")
	c.JSON(http.StatusOK, gin.H{"ok": true, "note": "重启服务后生效"})
}

func validListen(s string) bool {
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	n := 0
	for _, ch := range port {
		if ch < '0' || ch > '9' {
			return false
		}
		n = n*10 + int(ch-'0')
		if n > 65535 {
			return false
		}
	}
	return n > 0
}
