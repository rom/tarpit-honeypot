package creds

import "testing"

func TestMatchKnownDefaults(t *testing.T) {
	cases := []struct {
		user, pass string
		wantCat    string
	}{
		{"admin", "admin", "generic"},
		{"root", "calvin", "bmc"},
		{"cisco", "cisco", "router"},
		{"root", "xc3511", "camera"},
		{"postgres", "postgres", "database"},
		{"ADMIN", "ADMIN", "bmc"},
	}
	for _, c := range cases {
		got, ok := Match(c.user, c.pass)
		if !ok {
			t.Errorf("Match(%q,%q) = not found; want hit", c.user, c.pass)
			continue
		}
		if got.Category != c.wantCat {
			t.Errorf("Match(%q,%q).Category = %q; want %q", c.user, c.pass, got.Category, c.wantCat)
		}
	}
}

func TestMatchCaseInsensitiveUser(t *testing.T) {
	if _, ok := Match("Admin", "admin"); !ok {
		t.Errorf("username match should be case-insensitive")
	}
	// Password is exact: root/calvin is a Dell iDRAC default, but
	// root/CALVIN is not in the corpus and must miss.
	if _, ok := Match("root", "CALVIN"); ok {
		t.Errorf("password match should be case-sensitive")
	}
	if _, ok := Match("ROOT", "calvin"); !ok {
		t.Errorf("username case should not matter for root/calvin")
	}
}

// Guard against accidental duplicate (user,pass) pairs in the corpus —
// the map index silently drops the earlier category otherwise.
func TestNoDuplicatePairs(t *testing.T) {
	seen := map[string]string{}
	for _, c := range All() {
		k := key(c.User, c.Pass)
		if prev, dup := seen[k]; dup {
			t.Errorf("duplicate pair %q/%q (categories %q and %q)", c.User, c.Pass, prev, c.Category)
		}
		seen[k] = c.Category
	}
}

func TestMatchUnknown(t *testing.T) {
	if _, ok := Match("alice", "S3cr3t!particular"); ok {
		t.Errorf("random credential should not match")
	}
}

func TestAcceptsPolicies(t *testing.T) {
	if Accepts("none", "admin", "admin") {
		t.Errorf("none policy should never accept")
	}
	if Accepts("", "admin", "admin") {
		t.Errorf("empty policy should never accept")
	}
	if !Accepts("defaults", "admin", "admin") {
		t.Errorf("defaults policy should accept a known default")
	}
	if Accepts("defaults", "alice", "uniquepw") {
		t.Errorf("defaults policy should reject a non-default")
	}
	if !Accepts("any", "alice", "uniquepw") {
		t.Errorf("any policy should accept anything")
	}
}

func TestAcceptsCustomList(t *testing.T) {
	list := []string{"root:hunter2", "admin:*", "svc", "*:letmein"}
	cases := []struct {
		user, pass string
		want       bool
	}{
		{"root", "hunter2", true},    // exact
		{"root", "wrong", false},     // exact pass mismatch
		{"ROOT", "hunter2", true},    // case-insensitive user
		{"admin", "anything", true},  // admin:* — any pass
		{"svc", "whatever", true},    // bare user — any pass
		{"anybody", "letmein", true}, // *:letmein — any user
		{"nobody", "nopw", false},    // no match
	}
	for _, c := range cases {
		if got := AcceptsCustom(list, c.user, c.pass); got != c.want {
			t.Errorf("AcceptsCustom(%q,%q) = %v; want %v", c.user, c.pass, got, c.want)
		}
	}
	// AcceptsWith combines policy OR custom list.
	if !AcceptsWith("none", list, "root", "hunter2") {
		t.Errorf("AcceptsWith should accept a custom-list cred even with policy none")
	}
	if !AcceptsWith("defaults", nil, "admin", "admin") {
		t.Errorf("AcceptsWith should still honor the policy with no custom list")
	}
	if AcceptsWith("none", nil, "x", "y") {
		t.Errorf("AcceptsWith(none, nil) should reject")
	}
}

func TestNoEmptyEntries(t *testing.T) {
	for _, c := range All() {
		if c.User == "" && c.Pass == "" {
			t.Errorf("corpus has a fully-empty entry")
		}
		if c.Category == "" {
			t.Errorf("entry %q/%q has no category", c.User, c.Pass)
		}
	}
}
