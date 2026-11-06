package imap

import (
	"testing"

	imapbackend "github.com/emersion/go-imap"
)

// TestNeedsSeen BODY[] 必须隐式置已读，BODY.PEEK[] 不能。
func TestNeedsSeen(t *testing.T) {
	cases := []struct {
		item imapbackend.FetchItem
		want bool
	}{
		{"BODY[]", true},
		{"BODY.PEEK[]", false},
		{"BODY[HEADER]", true},
		{"BODY.PEEK[HEADER]", false},
		{"BODY[1]", true},
		{"RFC822", true},
		{"RFC822.HEADER", false},
		{"FLAGS", false},
		{"ENVELOPE", false},
	}
	for _, c := range cases {
		if got := needsSeen([]imapbackend.FetchItem{c.item}); got != c.want {
			t.Errorf("needsSeen(%s)=%v want %v", c.item, got, c.want)
		}
	}
}

// TestNeedsRaw 只取元数据时不能读整封原文。
func TestNeedsRaw(t *testing.T) {
	meta := []imapbackend.FetchItem{imapbackend.FetchFlags, imapbackend.FetchUid,
		imapbackend.FetchInternalDate, imapbackend.FetchRFC822Size}
	if needsRaw(meta) {
		t.Fatal("metadata-only fetch should not read raw blob")
	}
	for _, it := range []imapbackend.FetchItem{imapbackend.FetchEnvelope, imapbackend.FetchBody, "BODY[]"} {
		if !needsRaw(append(meta[:2:2], it)) {
			t.Errorf("needsRaw(%s)=false", it)
		}
	}
}

func TestApplyFlags(t *testing.T) {
	cur := `\Seen \Flagged`
	if got := applyFlags(cur, imapbackend.AddFlags, []string{`\Deleted`}); got != `\Deleted \Flagged \Seen` {
		t.Errorf("add: %q", got)
	}
	if got := applyFlags(cur, imapbackend.RemoveFlags, []string{`\Seen`}); got != `\Flagged` {
		t.Errorf("remove: %q", got)
	}
	if got := applyFlags(cur, imapbackend.SetFlags, []string{`\Draft`}); got != `\Draft` {
		t.Errorf("set: %q", got)
	}
}

// TestSimpleCriteria 只带 flag/序号的 SEARCH 不应退化成逐封解析原文。
func TestSimpleCriteria(t *testing.T) {
	c := &imapbackend.SearchCriteria{WithFlags: []string{`\Seen`}}
	if !simpleCriteria(c) {
		t.Fatal("flag-only criteria should be simple")
	}
	text := &imapbackend.SearchCriteria{Text: []string{"hello"}}
	if simpleCriteria(text) {
		t.Fatal("text criteria needs full parse")
	}
}
