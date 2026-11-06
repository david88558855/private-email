package mailutil

import (
	"database/sql"
	"html"
	"log"
	"regexp"
)

// StripHTML 去除标签与实体，供正文匹配用。
func StripHTML(s string) string {
	re := regexp.MustCompile(`(?s)<[^>]*>`)
	s = re.ReplaceAllString(s, " ")
	return html.UnescapeString(s)
}

var defaultCodePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:verification code|verify code|code|验证码|校验码|动态码|code is)[^0-9A-Z]{0,12}([0-9]{4,8})`),
	regexp.MustCompile(`\b([0-9]{4,8})\b[^。.\n]{0,20}(?:验证码|verification code)`),
}

// maxCodeScan 限制参与匹配的文本长度，只为控制内存。
// Go 的 regexp 是 RE2，匹配时间与输入长度线性相关，不存在回溯爆炸，
// 所以不需要像 PCRE 那样为了防 ReDoS 直接放弃长文本——那只会让规则静默失效。
const maxCodeScan = 256 * 1024

// 规则条数上限：每条规则都要 Compile 并扫描正文，无上限会放大每封入站邮件的 CPU。
// 与 handlers/extra.go 的写入上限保持一致。
const maxCodeRules = 50

// ExtractCode 提取验证码：先按用户自定义规则（DB），未命中走内置规则。
func ExtractCode(text string, custom *sql.Rows) string {
	var patterns []string
	if custom != nil {
		defer custom.Close()
		for custom.Next() {
			if len(patterns) >= maxCodeRules {
				break
			}
			var pat string
			if custom.Scan(&pat) == nil {
				patterns = append(patterns, pat)
			}
		}
		if err := custom.Err(); err != nil {
			log.Printf("自定义验证码规则读取失败: %v", err)
		}
	}
	return ExtractCodeWith(text, patterns)
}

// ExtractCodeWith 按给定规则列表提取，便于单独测试。
func ExtractCodeWith(text string, patterns []string) string {
	if len(patterns) > maxCodeRules {
		patterns = patterns[:maxCodeRules]
	}
	if len(text) > maxCodeScan {
		text = text[:maxCodeScan]
		// 截断点可能落在 UTF-8 中间，退到完整字符边界
		for len(text) > 0 && text[len(text)-1]&0xC0 == 0x80 {
			text = text[:len(text)-1]
		}
	}
	for _, pat := range patterns {
		// 只限制模式长度（DB 里存的规则由 API 侧校验过 128 字符）。
		// 不再因为正文长度直接跳过——那会让所有自定义规则永远不生效。
		if len(pat) > 128 {
			continue
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			continue
		}
		if m := re.FindStringSubmatch(text); len(m) > 1 {
			return m[1]
		}
	}
	for _, re := range defaultCodePatterns {
		if m := re.FindStringSubmatch(text); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}
