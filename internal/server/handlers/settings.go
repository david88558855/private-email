package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Settings GET /api/v1/admin/settings —— 运行时设置（注册开关等）。
func (h *MailHandler) Settings(c *gin.Context) {
	if !adminOK(c) {
		return
	}
	reg := h.Store.GetSetting("registration_enabled") == "true"
	c.JSON(http.StatusOK, gin.H{"registration_enabled": reg})
}

// SettingsPut PUT /api/v1/admin/settings {registration_enabled: bool}
func (h *MailHandler) SettingsPut(c *gin.Context) {
	if !adminOK(c) {
		return
	}
	var req struct {
		RegistrationEnabled *bool `json:"registration_enabled"`
	}
	if c.ShouldBindJSON(&req) != nil || req.RegistrationEnabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	v := "false"
	if *req.RegistrationEnabled {
		v = "true"
	}
	h.Store.SetSetting("registration_enabled", v)
	h.Store.DB.Exec(`INSERT INTO audit_logs(user_id, action, detail) VALUES(?,?,?)`,
		c.GetInt64("user_id"), "settings_registration", v)
	c.JSON(http.StatusOK, gin.H{"ok": true, "registration_enabled": *req.RegistrationEnabled})
}

// PublicSettings GET /api/v1/settings —— 匿名可读（登录页判断注册入口显示）。
func (h *MailHandler) PublicSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"registration_enabled": h.Store.GetSetting("registration_enabled") == "true"})
}
