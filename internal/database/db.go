package database

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Open 打开 SQLite 单库（全量数据：元数据 + 邮件 BLOB，决策 D1=B）。
// WAL 提升并发读，busy_timeout 规避写锁竞争。
func Open(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// 纯 Go 驱动无连接池并发写收益，单写连接最稳
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}
