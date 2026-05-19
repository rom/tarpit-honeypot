//go:build linux

package canary

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// startFanotify tries to set up fanotify notification (FAN_OPEN / FAN_MODIFY)
// for the canary paths and stream events to bus. Returns an error if
// fanotify can't be initialized (e.g. not running as root, kernel < 5.x,
// CAP_SYS_ADMIN missing) so the caller can fall back to fsnotify-only.
//
// We use FAN_CLASS_NOTIF (no permission decisions, just observation) and
// FAN_REPORT_FID so we can correlate events back to specific files.
func startFanotify(ctx context.Context, cfg []fanotifyTarget, sensorName string, bus chan<- *event.Event) error {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC, uint(unix.O_RDONLY))
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return fmt.Errorf("fanotify: needs CAP_SYS_ADMIN: %w", err)
		}
		return fmt.Errorf("fanotify: init: %w", err)
	}

	mask := uint64(unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE)
	registered := 0
	for _, t := range cfg {
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, t.path); err != nil {
			slog.Warn("fanotify: failed to mark", "path", t.path, "err", err)
			continue
		}
		registered++
		slog.Info("fanotify mark", "id", t.id, "path", t.path)
	}
	if registered == 0 {
		_ = unix.Close(fd)
		return fmt.Errorf("fanotify: no paths registered")
	}

	go func() {
		<-ctx.Done()
		_ = unix.Close(fd)
	}()

	go readLoop(fd, cfg, sensorName, bus)
	return nil
}

func readLoop(fd int, cfg []fanotifyTarget, sensorName string, bus chan<- *event.Event) {
	f := os.NewFile(uintptr(fd), "fanotify")
	defer f.Close()
	br := bufio.NewReader(f)
	for {
		// fanotify_event_metadata layout from <linux/fanotify.h>:
		// __u32 event_len; __u8 vers; __u8 reserved; __u16 metadata_len;
		// __aligned_u64 mask; __s32 fd; __s32 pid;
		var meta [24]byte
		if _, err := br.Read(meta[:]); err != nil {
			return
		}
		evLen := binary.LittleEndian.Uint32(meta[0:4])
		mask := binary.LittleEndian.Uint64(meta[8:16])
		evFD := int32(binary.LittleEndian.Uint32(meta[16:20]))
		pid := int32(binary.LittleEndian.Uint32(meta[20:24]))
		// Skip any extra info records (we don't request them; this is defensive).
		if evLen > 24 {
			skip := make([]byte, evLen-24)
			if _, err := br.Read(skip); err != nil {
				return
			}
		}
		if evFD < 0 {
			continue
		}
		path := readlinkFD(int(evFD))
		_ = unix.Close(int(evFD))
		if path == "" {
			continue
		}
		id := bestMatch(cfg, path)
		if id == "" {
			continue
		}
		ops := []string{}
		if mask&unix.FAN_OPEN != 0 {
			ops = append(ops, "OPEN")
		}
		if mask&unix.FAN_MODIFY != 0 {
			ops = append(ops, "MODIFY")
		}
		if mask&unix.FAN_CLOSE_WRITE != 0 {
			ops = append(ops, "CLOSE_WRITE")
		}
		opStr := "?"
		if len(ops) > 0 {
			opStr = ops[0]
			for _, o := range ops[1:] {
				opStr += "+" + o
			}
		}
		ev := &event.Event{
			ID:       event.NewID(),
			Time:     time.Now().UTC(),
			Sensor:   sensorName,
			RuleID:   "canary:" + id,
			Severity: cfgSeverity(cfg, id),
			Proto:    "file",
			Meta: map[string]any{
				"path":   path,
				"op":     opStr,
				"pid":    pid,
				"source": "fanotify",
			},
		}
		select {
		case bus <- ev:
		default:
			// bus full — drop rather than block the kernel reader
		}
	}
}

func readlinkFD(fd int) string {
	target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return ""
	}
	return target
}

func bestMatch(cfg []fanotifyTarget, path string) string {
	best, bestLen := "", -1
	for _, t := range cfg {
		if path == t.path || bytes.HasPrefix([]byte(path), []byte(t.path+"/")) {
			if len(t.path) > bestLen {
				bestLen = len(t.path)
				best = t.id
			}
		}
	}
	return best
}

func cfgSeverity(cfg []fanotifyTarget, id string) event.Severity {
	for _, t := range cfg {
		if t.id == id {
			return t.sev
		}
	}
	return event.SeverityHigh
}
