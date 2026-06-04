package store

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func bannerEvent(id, banner string) *event.Event {
	return &event.Event{
		ID: id, Time: time.Now().UTC(), Sensor: "s", RuleID: "r",
		Severity: event.SeverityLow, Proto: "tcp", Handler: "ssh",
		Source: event.Endpoint{IP: "1.2.3.4"}, BannerSent: banner,
	}
}

// Banners must round-trip unchanged while being stored only once, no matter how
// many events share the same banner.
func TestBannerInterningRoundTripAndDedup(t *testing.T) {
	st, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	const banner = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n"
	for i := 0; i < 25; i++ {
		if err := st.Insert(ctx, bannerEvent("e"+string(rune('a'+i)), banner)); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	// A different banner + an empty-banner event.
	if err := st.Insert(ctx, bannerEvent("other", "220 (vsFTPd 3.0.5)\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := st.Insert(ctx, bannerEvent("nob", "")); err != nil {
		t.Fatal(err)
	}

	// Read-back: every event reports the exact banner it was stored with.
	evs, err := st.Query(ctx, Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var withBanner, empties int
	for _, e := range evs {
		switch e.ID {
		case "other":
			if e.BannerSent != "220 (vsFTPd 3.0.5)\r\n" {
				t.Errorf("ftp banner = %q", e.BannerSent)
			}
		case "nob":
			if e.BannerSent != "" {
				t.Errorf("empty banner came back %q", e.BannerSent)
			}
			empties++
		default:
			if e.BannerSent != banner {
				t.Errorf("ssh banner = %q; want %q", e.BannerSent, banner)
			}
			withBanner++
		}
	}
	if withBanner != 25 || empties != 1 {
		t.Errorf("counts: ssh=%d empty=%d", withBanner, empties)
	}

	// Dedup: only 2 distinct banner strings should exist in the banners table.
	var n int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM banners`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("banners table has %d rows; want 2 (deduped)", n)
	}
	// And no event row should carry an inline banner_sent copy anymore.
	var inline int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE banner_sent != ''`).Scan(&inline); err != nil {
		t.Fatal(err)
	}
	if inline != 0 {
		t.Errorf("%d events still store an inline banner copy", inline)
	}

	// Full-text search must still match interned banner content.
	hits, err := st.Query(ctx, Filter{Text: "openssh_8.4", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 25 {
		t.Errorf("banner full-text search matched %d; want 25", len(hits))
	}
}

// A legacy row (inline banner_sent, NULL banner_id) must still read back — the
// dedup scheme is backward compatible.
func TestBannerLegacyRowReadback(t *testing.T) {
	st, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	_, err = st.DB().ExecContext(ctx, `INSERT INTO events
(id, time, sensor, rule_id, severity, src_ip, src_port, dst_ip, dst_port, proto, handler,
 banner_sent, payload_b64, payload_len, meta_json)
VALUES ('legacy', ?, 's', 'r', 1, '1.1.1.1', 5, '2.2.2.2', 21, 'tcp', 'ftp',
 '220 legacy banner', '', 0, '')`,
		time.Now().UTC().UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if got.BannerSent != "220 legacy banner" {
		t.Errorf("legacy banner = %q; want '220 legacy banner'", got.BannerSent)
	}
}
