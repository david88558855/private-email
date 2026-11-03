package handlers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/david88558855/private-email/internal/mailutil"
	"github.com/david88558855/private-email/internal/store"
	"github.com/gin-gonic/gin"
)

type MailHandler struct {
	Store *store.Store
}

// Mailboxes GET /api/v1/mailboxes
func (h *MailHandler) Mailboxes(c *gin.Context) {
	uid := c.GetInt64("user_id")
	mbs, err := h.Store.MailboxesOf(uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": mbs})
}

// Folders GET /api/v1/mailboxes/:id/folders
func (h *MailHandler) Folders(c *gin.Context) {
	uid := c.GetInt64("user_id")
	mbID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if !h.Store.OwnsMailbox(mbID, uid) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问"})
		return
	}
	fs, err := h.Store.FoldersOf(mbID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": fs})
}

// List GET /api/v1/folders/:id/mails?q=&limit=&offset=
func (h *MailHandler) List(c *gin.Context) {
	uid := c.GetInt64("user_id")
	fID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if !h.ownsFolder(fID, uid) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问"})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	items, total, err := h.Store.ListMails(fID, c.Query("q"), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total})
}

// Get GET /api/v1/mails/:id —— 详情并自动置已读
func (h *MailHandler) Get(c *gin.Context) {
	uid := c.GetInt64("user_id")
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if !h.Store.OwnsMail(id, uid) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问"})
		return
	}
	if err := h.Store.MarkSeen(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	m, err := h.Store.GetMail(id)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "邮件不存在"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	p := mailutil.Parse(m.Raw)
	m.Text = p.TextBody
	m.HTML = p.HTMLBody
	m.Attach = make([]store.AttachmentRow, 0)
	for _, a := range p.Attachments {
		m.Attach = append(m.Attach, store.AttachmentRow{Filename: a.Filename, ContentType: a.ContentType, Size: a.Size})
	}
	h.Store.MarkSeen(id)
	c.JSON(http.StatusOK, m)
}

// Raw GET /api/v1/mails/:id/raw —— 下载原始 EML
func (h *MailHandler) Raw(c *gin.Context) {
	uid := c.GetInt64("user_id")
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if !h.Store.OwnsMail(id, uid) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问"})
		return
	}
	m, err := h.Store.GetMail(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "邮件不存在"})
		return
	}
	c.Data(http.StatusOK, "message/rfc822", m.Raw)
}

// Patch PATCH /api/v1/mails/:id {op: "seen"}
func (h *MailHandler) Patch(c *gin.Context) {
	uid := c.GetInt64("user_id")
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if !h.Store.OwnsMail(id, uid) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问"})
		return
	}
	var req struct {
		Op string `json:"op"`
	}
	if c.ShouldBindJSON(&req) != nil || req.Op != "seen" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	h.Store.MarkSeen(id)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Delete DELETE /api/v1/mails/:id
func (h *MailHandler) Delete(c *gin.Context) {
	uid := c.GetInt64("user_id")
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if !h.Store.OwnsMail(id, uid) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问"})
		return
	}
	if err := h.Store.DeleteMail(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *MailHandler) ownsFolder(fID, uid int64) bool {
	var n int
	h.Store.DB.QueryRow(`SELECT COUNT(*) FROM folders f JOIN mailboxes mb ON mb.id=f.mailbox_id
		WHERE f.id=? AND mb.user_id=?`, fID, uid).Scan(&n)
	return n > 0
}
