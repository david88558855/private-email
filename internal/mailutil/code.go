package mailutil

import (
	"database/sql"
	"html"
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

// ExtractCode 提取验证码：先按用户自定义规则（DB），未命中走内置规则。
func ExtractCode(text string, custom *sql.Rows) string {
	// custom rows: pattern string
	if custom != nil {
		defer custom.Close()
		for custom.Next() {
			var pat string
			if custom.Scan(&pat) == nil {
				if re, err := regexp.Compile(pat); err == nil {
					if m := re.FindStringSubmatch(text); len(m) > 1 {
						return m[1]
					}
				}
			}
		}
	}
	for _, re := range defaultCodePatterns {
		if m := re.FindStringSubmatch(text); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}
