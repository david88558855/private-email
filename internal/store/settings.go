package store

import (
	"database/sql"
	"log"
)

// GetSetting 读取运行时设置；键不存在返回空串和 nil。
// 查询失败必须把错误交给调用方：端口类设置一旦拿到空串会被当成「关闭监听」，
// 服务照常打印就绪却没有协议端口在听。
func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		log.Printf("读取设置失败 key=%s: %v", key, err)
	}
	return v, err
}

// SetSetting 写入运行时设置（幂等）。
func (s *Store) SetSetting(key, value string) error {
	_, err := s.DB.Exec(`INSERT INTO settings(key, value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	if err != nil {
		log.Printf("写入设置失败 key=%s: %v", key, err)
	}
	return err
}

// HasSetting 判断设置键是否存在。
func (s *Store) HasSetting(key string) (bool, error) {
	var one int
	err := s.DB.QueryRow(`SELECT 1 FROM settings WHERE key=?`, key).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		log.Printf("查询设置失败 key=%s: %v", key, err)
	}
	return one == 1, err
}
