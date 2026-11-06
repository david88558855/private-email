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
	reg, err := h.Store.GetSetting("registration_enabled")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取设置失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"registration_enabled": reg == "true"})
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
	if err := h.Store.SetSetting("registration_enabled", v); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败"})
		return
	}
	h.Store.DB.Exec(`INSERT INTO audit_logs(user_id, action, detail) VALUES(?,?,?)`,
		c.GetInt64("user_id"), "settings_registration", v)
	c.JSON(http.StatusOK, gin.H{"ok": true, "registration_enabled": *req.RegistrationEnabled})
}

// PublicSettings GET /api/v1/settings —— 匿名可读（登录页判断注册入口显示）。
func (h *MailHandler) PublicSettings(c *gin.Context) {
	// 读失败时返回 false（关闭注册入口），fail-closed，不把匿名接口打挂。
	reg, _ := h.Store.GetSetting("registration_enabled")
	c.JSON(http.StatusOK, gin.H{"registration_enabled": reg == "true"})
}
