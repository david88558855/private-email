package store

// GetSetting 读取运行时设置（settings 表）。
func (s *Store) GetSetting(key string) string {
	var v string
	s.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	return v
}

// SetSetting 写入运行时设置（幂等）。
func (s *Store) SetSetting(key, value string) {
	s.DB.Exec(`INSERT INTO settings(key, value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
}
