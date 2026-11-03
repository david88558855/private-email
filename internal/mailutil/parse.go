// Package mailutil MIME 解析与验证码提取。
package mailutil

import (
	"bytes"
	"io"
	"mime"
	netmail "net/mail"
	"strings"

	gomail "github.com/emersion/go-message/mail"
)

// Parsed 解析结果。
type Parsed struct {
	Subject     string
	From        string
	To          string
	TextBody    string
	HTMLBody    string
	Attachments []Attachment
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
		p.From = mr.Header.Get("From")
	}
	if v, err := mr.Header.AddressList("To"); err == nil && len(v) > 0 {
		addrs := make([]string, 0, len(v))
		for _, a := range v {
			addrs = append(addrs, a.Address)
		}
		p.To = strings.Join(addrs, ", ")
	} else {
		p.To = mr.Header.Get("To")
	}
	p.Subject = decodeSubject(mr.Header.Get("Subject"))

	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		switch h := part.Header.(type) {
		case *gomail.InlineHeader:
			ct, _, _ := h.ContentType()
			b, _ := io.ReadAll(part.Body)
			if strings.HasPrefix(ct, "text/html") {
				p.HTMLBody = string(b)
			} else if p.TextBody == "" {
				p.TextBody = string(b)
			}
		case *gomail.AttachmentHeader:
			fn, _ := h.Filename()
			b, _ := io.ReadAll(part.Body)
			ct, _, _ := h.ContentType()
			p.Attachments = append(p.Attachments, Attachment{Filename: fn, ContentType: ct, Size: len(b)})
		}
	}
	return p
}

func decodeSubject(s string) string {
	if s == "" {
		return ""
	}
	if d, err := new(mime.WordDecoder).DecodeHeader(s); err == nil {
		return d
	}
	return s
}
