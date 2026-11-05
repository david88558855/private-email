package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/david88558855/private-email/internal/store"
	"github.com/gin-gonic/gin"
)

// Compose POST /api/v1/mailboxes/:id/compose {to, subject, text}
func (h *MailHandler) Compose(c *gin.Context) {
	uid := c.GetInt64("user_id")
	mbID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if !h.Store.OwnsMailbox(mbID, uid) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问"})
		return
	}
	var req struct {
		To      string `json:"to" binding:"required,email"`
		Subject string `json:"subject"`
		Text    string `json:"text"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	var mb store.Mailbox
	if err := h.Store.DB.QueryRow(`SELECT id, user_id, address, domain_id, is_active FROM mailboxes WHERE id=?`, mbID).
		Scan(&mb.ID, &mb.UserID, &mb.Address, &mb.DomainID, &mb.IsActive); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "邮箱不存在"})
		return
	}

	// 组装 RFC822
	buf := &bytes.Buffer{}
	now := time.Now()
	idb := make([]byte, 8)
	rand.Read(idb)
	msgID := fmt.Sprintf("<%s@%s>", hex.EncodeToString(idb), mb.Address[stringsIndex(mb.Address, "@")+1:])
	fmt.Fprintf(buf, "From: %s\r\n", mb.Address)
	fmt.Fprintf(buf, "To: %s\r\n", req.To)
	fmt.Fprintf(buf, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", req.Subject))
	fmt.Fprintf(buf, "Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(buf, "Message-ID: %s\r\n", msgID)
	fmt.Fprintf(buf, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(buf, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(buf, "Content-Transfer-Encoding: base64\r\n\r\n")
	buf.Write(encodeB64(req.Text))
	raw := buf.Bytes()

	// 存 Sent（失败仅记日志，不阻断投递）
	sentID, err := h.Store.FolderID(mbID, "Sent")
	if err == nil {
		if _, _, err := h.Store.InsertMail(sentID, mb.Address, req.To, req.Subject, raw, "\\Seen", "", 0, req.Text); err != nil {
			log.Printf("存 Sent 副本失败: %v", err)
		}
	}

	// 收件人在本机：直接投递到对方收件箱，不走进出站队列
	// （同域收发若依赖 MX 回环，需要域名有公网 DNS 且 25 端口可达，家庭/内网部署必然失败）
	if toID, active, found := h.Store.MailboxStateByAddress(req.To); found {
		if !active {
			c.JSON(http.StatusBadRequest, gin.H{"error": "收件邮箱已暂停收发，邮件未发送"})
			return
		}
		if err := h.Store.DeliverLocal(toID, mb.Address, req.To, req.Subject, raw, req.Text); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "本地投递失败：" + err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "local": true})
		return
	}

	// 外部地址：入投递队列（失败返回 500——用户需知道没发出去）
	if _, err := h.Store.DB.Exec(`INSERT INTO mail_queue(mailbox_id, from_addr, to_addr, raw_blob, next_try_at)
		VALUES(?,?,?,?,datetime('now'))`, mbID, mb.Address, req.To, raw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "入队失败，请重试"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "local": false})
}

func stringsIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func encodeB64(s string) []byte {
	const line = 76
	enc := base64Std(s)
	out := make([]byte, 0, len(enc)+len(enc)/line*2)
	for i := 0; i < len(enc); i += line {
		end := i + line
		if end > len(enc) {
			end = len(enc)
		}
		out = append(out, enc[i:end]...)
		out = append(out, '\r', '\n')
	}
	return out
}

// Queue GET /api/v1/queue（管理员）
func (h *MailHandler) Queue(c *gin.Context) {
	if c.GetString("role") != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "需要管理员权限"})
		return
	}
	rows, err := h.Store.DB.Query(`SELECT id, from_addr, to_addr, status, attempts, COALESCE(last_error,''), created_at
		FROM mail_queue ORDER BY id DESC LIMIT 100`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务异常"})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, attempts int64
		var from, to, status, lastErr, created string
		rows.Scan(&id, &from, &to, &status, &attempts, &lastErr, &created)
		items = append(items, map[string]any{"id": id, "from": from, "to": to, "status": status,
			"attempts": attempts, "last_error": lastErr, "created_at": created})
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}
