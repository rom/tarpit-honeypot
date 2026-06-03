package ui

import (
	"testing"
	"time"
)

func TestCompileSearchRegex(t *testing.T) {
	if re, err := compileSearch(""); re != nil || err != nil {
		t.Errorf("empty pattern should yield nil,nil; got %v,%v", re, err)
	}
	re, err := compileSearch("10.0.")
	if err != nil || re == nil {
		t.Fatalf("plain partial IP should compile: %v", err)
	}
	if !re.MatchString("10X0Y") || !re.MatchString("192.168 10.0.5") {
		t.Error("unanchored partial pattern should match substrings")
	}
	// Case-insensitive.
	if cre, _ := compileSearch("SQLMAP"); !cre.MatchString("sqlmap/1.7") {
		t.Error("pattern should be case-insensitive")
	}
	// Invalid regex surfaces an error.
	if _, err := compileSearch("(unclosed"); err == nil {
		t.Error("invalid regex should error")
	}
}

func TestSearchWindow(t *testing.T) {
	// Relative duration.
	since, until, err := searchWindow(searchQuery{Since: "48h"})
	if err != nil || until != (time.Time{}) || time.Since(since) < 47*time.Hour {
		t.Errorf("since=48h window wrong: %v %v %v", since, until, err)
	}
	// Absolute after/before.
	since, until, err = searchWindow(searchQuery{After: "2024-01-02", Before: "2024-01-05T12:00"})
	if err != nil {
		t.Fatal(err)
	}
	if since.Format("2006-01-02") != "2024-01-02" || until.Format("2006-01-02 15:04") != "2024-01-05 12:00" {
		t.Errorf("after/before window wrong: %v..%v", since, until)
	}
	// "on" a date pins both ends to that whole UTC day.
	since, until, _ = searchWindow(searchQuery{On: "2024-03-10"})
	if since.Format("2006-01-02 15:04") != "2024-03-10 00:00" || until.Format("2006-01-02 15:04") != "2024-03-11 00:00" {
		t.Errorf("on-day window wrong: %v..%v", since, until)
	}
	// "on" a minute pins a one-minute window.
	since, until, _ = searchWindow(searchQuery{On: "2024-03-10 14:30"})
	if until.Sub(since) != time.Minute {
		t.Errorf("on-minute window should be 1m, got %v", until.Sub(since))
	}
	// Bad time is a user-input error.
	if _, _, err := searchWindow(searchQuery{After: "not-a-time"}); !isUserInputErr(err) {
		t.Errorf("bad time should be a user-input error, got %v", err)
	}
}

func TestIsUserInputErr(t *testing.T) {
	if !isUserInputErr(inputError{"x"}) {
		t.Error("inputError should be detected")
	}
	if isUserInputErr(nil) {
		t.Error("nil is not a user-input error")
	}
}
