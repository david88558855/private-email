package handlers

import "encoding/base64"

func base64Std(s string) []byte { return []byte(base64.StdEncoding.EncodeToString([]byte(s))) }
