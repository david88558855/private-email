// Package mailutil MIME 解析与验证码提取。
package mailutil

import (
	"bytes"
	"io"
	"mime"
	netmail "net/mail"
	"strings"

	// 注册常见字符集解码器（GBK/GB18030/Big5/ISO-8859-* 等）。
	// 不导入这个包时，charset=gbk 的邮件会让正文读取直接报错，
	// 上层再把错误一吞，用户看到的就是一封空白邮件。
	_ "github.com/emersion/go-message/charset"

	gomessage "github.com/emersion/go-message"
	gomail "github.com/emersion/go-message/mail"
)

// 畸形 MIME 塞成千上万个 part 时，逐个 base64/charset 解码会放大 CPU。
// 单封邮件整体已受 smtp.max_size_mb（默认 25MB）约束，逐 part 读取总量不会
// 超过它，所以只限制 part 数量、不截断单个 part 的正文——否则 2MB 的纯文本
// 邮件会被静默截一半，污染 body_text、验证码提取与阅读区。
const maxMIMEParts = 64

// Parsed 解析结果。
type Parsed struct {
	Subject     string
	From        string
	To          string
	TextBody    string
	HTMLBody    string
	Attachments []Attachment
	// CharsetFallback 记录有部分内容因字符集无法解码而被丢弃，便于排障。
	CharsetFallback bool
}

// Attachment 附件元信息。
type Attachment struct {
	Filename    string
	ContentType string
	Size        int
}

// Parse 解析原始 MIME 报文（含编码解码）。
func Parse(raw []byte) *Parsed {
	p := &Parsed{}
	mr, err := gomail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		// 退化：仅取 Header 行
		if msg, e := netmail.ReadMessage(bytes.NewReader(raw)); e == nil {
			p.Subject = decodeSubject(msg.Header.Get("Subject"))
			p.From = msg.Header.Get("From")
			p.To = msg.Header.Get("To")
		}
		return p
	}
	if v, err := mr.Header.AddressList("From"); err == nil && len(v) > 0 {
		p.From = v[0].Address
	} else {
		p.From = decodeSubject(mr.Header.Get("From"))
	}
	if v, err := mr.Header.AddressList("To"); err == nil && len(v) > 0 {
		addrs := make([]string, 0, len(v))
		for _, a := range v {
			addrs = append(addrs, a.Address)
		}
		p.To = strings.Join(addrs, ", ")
	} else {
		p.To = decodeSubject(mr.Header.Get("To"))
	}
	p.Subject = decodeSubject(mr.Header.Get("Subject"))

	partsTruncated := true
	for i := 0; i < maxMIMEParts; i++ {
		part, err := mr.NextPart()
		if err != nil {
			partsTruncated = false // 正常读完（io.EOF）
			break
		}
		switch h := part.Header.(type) {
		case *gomail.InlineHeader:
			ct, _, _ := h.ContentType()
			b, err := io.ReadAll(part.Body)
			if err != nil {
				// 解码失败时保留已读出的部分，别让整封邮件变成空白
				p.CharsetFallback = true
			}
			if strings.HasPrefix(ct, "text/html") {
				if p.HTMLBody == "" {
					p.HTMLBody = string(b)
				}
			} else if p.TextBody == "" {
				p.TextBody = string(b)
			}
		case *gomail.AttachmentHeader:
			fn, _ := h.Filename()
			// 附件只需要大小，没必要把整段内容读进内存（25MB 附件 × N 个）
			n, err := io.Copy(io.Discard, part.Body)
			if err != nil {
				p.CharsetFallback = true
			}
			ct, _, _ := h.ContentType()
			p.Attachments = append(p.Attachments, Attachment{Filename: fn, ContentType: ct, Size: int(n)})
		}
	}
	if partsTruncated {
		// part 数达到上限，后续内容被丢弃；留标记便于排障，不再静默当完整邮件。
		p.CharsetFallback = true
	}
	// 只有 HTML 的邮件：抽一份纯文本供搜索/验证码使用，不能留空
	if strings.TrimSpace(p.TextBody) == "" && p.HTMLBody != "" {
		p.TextBody = StripHTML(p.HTMLBody)
	}
	return p
}

// decodeSubject 解码 =?gbk?B?...?= 这类 encoded-word。
func decodeSubject(s string) string {
	if s == "" {
		return ""
	}
	d := &mime.WordDecoder{CharsetReader: gomessage.CharsetReader}
	if out, err := d.DecodeHeader(s); err == nil {
		return out
	}
	return s
}
