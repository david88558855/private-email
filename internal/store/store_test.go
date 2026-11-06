package store_test

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/david88558855/private-email/internal/database"
	"github.com/david88558855/private-email/internal/store"
)

// newStore 建一个临时库并跑完迁移。
func newStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO domains(domain, status) VALUES('example.test','verified')`); err != nil {
		t.Fatalf("domain: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &store.Store{DB: db}
}

// seedMailbox 建用户 + 邮箱 + 默认文件夹，返回 mailboxID 与 INBOX folderID。
func seedMailbox(t *testing.T, s *store.Store, addr string) (int64, int64) {
	t.Helper()
	res, err := s.DB.Exec(`INSERT INTO users(username, password) VALUES(?, 'x')`, addr)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	uid, _ := res.LastInsertId()
	res, err = s.DB.Exec(`INSERT INTO mailboxes(user_id, address, domain_id, password) VALUES(?,?,1,'x')`, uid, addr)
	if err != nil {
		t.Fatalf("mailbox: %v", err)
	}
	mbID, _ := res.LastInsertId()
	if err := s.EnsureFolders(mbID); err != nil {
		t.Fatalf("folders: %v", err)
	}
	fid, err := s.FolderID(mbID, "INBOX")
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	return mbID, fid
}

func insert(t *testing.T, s *store.Store, folderID int64, subject, body string) {
	t.Helper()
	raw := []byte("From: a@b.test\r\nTo: c@d.test\r\nSubject: " + subject + "\r\n\r\n" + body + "\r\n")
	if _, _, err := s.InsertMail(folderID, "a@b.test", "c@d.test", subject, raw, "", "", 0, body); err != nil {
		t.Fatalf("insert: %v", err)
	}
}

// TestChineseSearch 中文检索：trigram 负责 3 字以上，2 字词走 LIKE 回退。
func TestChineseSearch(t *testing.T) {
	s := newStore(t)
	_, fid := seedMailbox(t, s, "alice@example.test")
	insert(t, s, fid, "登录提醒", "您的验证码是 992211，5 分钟内有效。")
	insert(t, s, fid, "账单", "本月账单已生成，请查收。")

	cases := []struct {
		q    string
		want int
	}{
		{"验证码", 1},
		{"您的", 1},
		{"992211", 1},
		{"登录", 1},
		{"账单", 1},
		{"不存在的词", 0},
	}
	for _, c := range cases {
		items, total, err := s.ListMails(fid, c.q, 50, 0)
		if err != nil {
			t.Fatalf("search %q: %v", c.q, err)
		}
		if total != c.want || len(items) != c.want {
			t.Errorf("search %q: total=%d items=%d want=%d", c.q, total, len(items), c.want)
		}
	}
}

// TestSearchSurvivesFlagUpdate 标记已读不能破坏全文索引。
// 迁移 004 把触发器收窄到 AFTER UPDATE OF subject,sender,body_text 之前，
// 每次改 flags 都会 delete+insert 一遍 FTS。
func TestSearchSurvivesFlagUpdate(t *testing.T) {
	s := newStore(t)
	_, fid := seedMailbox(t, s, "alice@example.test")
	insert(t, s, fid, "验证码邮件", "您的验证码是 123456")
	items, _, _ := s.ListMails(fid, "验证码", 10, 0)
	if len(items) != 1 {
		t.Fatalf("before mark: got %d", len(items))
	}
	if err := s.MarkSeen(items[0].ID); err != nil {
		t.Fatalf("mark: %v", err)
	}
	items, total, err := s.ListMails(fid, "验证码", 10, 0)
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("after mark: total=%d items=%d err=%v", total, len(items), err)
	}
}

// TestConcurrentInsert 并发写入不能出现 SQLITE_BUSY。
// 原实现用默认 deferred 事务，4 路并发就有 30% 失败。
func TestConcurrentInsert(t *testing.T) {
	s := newStore(t)
	_, fid := seedMailbox(t, s, "alice@example.test")

	const workers, per = 10, 10
	var wg sync.WaitGroup
	errCh := make(chan error, workers*per)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				raw := []byte(fmt.Sprintf("From: a@b.test\r\nSubject: c%d-%d\r\n\r\nbody\r\n", n, i))
				if _, _, err := s.InsertMail(fid, "a@b.test", "c@d.test", "c", raw, "", "", 0, "body"); err != nil {
					errCh <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent insert: %v", err)
	}
	_, total, _ := s.ListMails(fid, "", 100, 0)
	if total != workers*per {
		t.Fatalf("total=%d want=%d", total, workers*per)
	}
}

// TestDeliverInboundAtomic 多收件人必须整体成功或整体失败，不能部分落库。
func TestDeliverInboundAtomic(t *testing.T) {
	s := newStore(t)
	mb1, fid1 := seedMailbox(t, s, "alice@example.test")
	seedMailbox(t, s, "bob@example.test") // 再建一个，制造多邮箱场景

	raw := []byte("From: x@y.test\r\nSubject: batch\r\n\r\nhello\r\n")
	good := store.LocalDelivery{MailboxID: mb1, Address: "alice@example.test", Subject: "batch", TextBody: "hello"}
	bad := store.LocalDelivery{MailboxID: 999999, Address: "ghost@example.test", Subject: "batch", TextBody: "hello"}

	if err := s.DeliverInbound("x@y.test", raw, []store.LocalDelivery{good, bad}, 0, nil); err == nil {
		t.Fatal("expected error for unknown mailbox")
	}
	_, total, _ := s.ListMails(fid1, "", 10, 0)
	if total != 0 {
		t.Fatalf("partial delivery leaked: %d mails", total)
	}

	if err := s.DeliverInbound("x@y.test", raw, []store.LocalDelivery{good}, 0, []string{"out@example.com"}); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	_, total, _ = s.ListMails(fid1, "", 10, 0)
	if total != 1 {
		t.Fatalf("delivered=%d want=1", total)
	}
	var queued int
	s.DB.QueryRow(`SELECT COUNT(*) FROM mail_queue WHERE to_addr='out@example.com'`).Scan(&queued)
	if queued != 1 {
		t.Fatalf("queue rows=%d want=1", queued)
	}
}

// TestMoveToTrashClearsDeleted 移入垃圾箱必须清掉 \Deleted，否则下一次 EXPUNGE 会物理删除。
func TestMoveToTrashClearsDeleted(t *testing.T) {
	s := newStore(t)
	_, fid := seedMailbox(t, s, "alice@example.test")
	insert(t, s, fid, "x", "body")
	var id int64
	s.DB.QueryRow(`SELECT id FROM mails WHERE folder_id=? LIMIT 1`, fid).Scan(&id)
	if err := s.SetFlags(id, `\Seen \Deleted`); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteMail(id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var flags string
	s.DB.QueryRow(`SELECT flags FROM mails WHERE id=?`, id).Scan(&flags)
	if flags != `\Seen` {
		t.Fatalf("flags=%q want \\Seen", flags)
	}
}
