package database

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Open 打开 SQLite 单库（全量数据：元数据 + 邮件 BLOB，决策 D1=B）。
//
// _txlock=immediate：事务一开始就拿写锁。默认的 deferred 事务在
// 「SELECT uid_next → INSERT」这种先读后写的模式下，会在升级写锁时
// 直接返回 SQLITE_BUSY，而且 busy_timeout 对锁升级无效（实测 4 路并发
// 就有 30% 收信失败）。immediate 让并发写在这里排队，由 busy_timeout 兜底。
func Open(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(15000)"+
		"&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// WAL 下读并发不受限；写由 immediate 事务 + busy_timeout 串行化
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(0)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}
