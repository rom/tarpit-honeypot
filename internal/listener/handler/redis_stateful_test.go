package handler

import (
	"bufio"
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// respMultiBulk encodes a command as a RESP multi-bulk array — how redis-cli
// and attack tooling actually send commands, so a value may contain spaces.
func respMultiBulk(args ...string) string {
	var b strings.Builder
	b.WriteString("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, a := range args {
		b.WriteString("$" + strconv.Itoa(len(a)) + "\r\n" + a + "\r\n")
	}
	return b.String()
}

// driveRedis runs the redis handler and feeds it a sequence of commands (each a
// list of args, multi-bulk-encoded), returning the concatenated replies + Result.
func driveRedis(t *testing.T, commands [][]string) (string, Result) {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "redis", ReadTimeout: 2 * time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&redis{}).Handle(context.Background(), server, cfg)
	}()
	var out strings.Builder
	br := bufio.NewReader(client)
	for _, c := range commands {
		if _, err := client.Write([]byte(respMultiBulk(c...))); err != nil {
			break
		}
		// Read one reply chunk (bounded) so replies interleave with writes.
		_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 8192)
		n, _ := br.Read(buf)
		out.Write(buf[:n])
	}
	client.Close()
	<-done
	return out.String(), res
}

// The decoy keyspace is stateful within a connection: a value SET is returned
// by a later GET — so an attacker's tooling keeps going instead of bailing on
// an empty reply.
func TestRedisStatefulSetGet(t *testing.T) {
	out, _ := driveRedis(t, [][]string{
		{"SET", "greeting", "hello-world"},
		{"GET", "greeting"},
		{"STRLEN", "greeting"},
		{"EXISTS", "greeting"},
		{"DEL", "greeting"},
		{"GET", "greeting"},
	})
	if !strings.Contains(out, "hello-world") {
		t.Errorf("GET did not return the SET value; replies:\n%q", out)
	}
	if !strings.Contains(out, ":11\r\n") {
		t.Errorf("STRLEN of hello-world should be 11; replies:\n%q", out)
	}
	if !strings.Contains(out, ":1\r\n") {
		t.Errorf("EXISTS should report 1; replies:\n%q", out)
	}
	// After DEL, the final GET must be nil ($-1).
	if !strings.HasSuffix(strings.TrimRight(out, "\r\n"), "$-1") {
		t.Errorf("GET after DEL should be nil; replies:\n%q", out)
	}
}

// The full redis-rogue-server webshell drop chain is captured end to end: the
// payload body, the exact target path, and the completion marker.
func TestRedisDropChainCaptured(t *testing.T) {
	_, res := driveRedis(t, [][]string{
		{"CONFIG", "SET", "dir", "/var/www/html"},
		{"CONFIG", "SET", "dbfilename", "shell.php"},
		{"SET", "x", "<?php system($_GET[0]); ?>"},
		{"SAVE"},
	})
	if res.Meta["redis_config_dir"] != "/var/www/html" {
		t.Errorf("redis_config_dir = %v; want /var/www/html", res.Meta["redis_config_dir"])
	}
	if res.Meta["redis_config_dbfilename"] != "shell.php" {
		t.Errorf("redis_config_dbfilename = %v; want shell.php", res.Meta["redis_config_dbfilename"])
	}
	if res.Meta["redis_drop_path"] != "/var/www/html/shell.php" {
		t.Errorf("redis_drop_path = %v; want /var/www/html/shell.php", res.Meta["redis_drop_path"])
	}
	pl, _ := res.Meta["redis_set_payload"].(string)
	if !strings.Contains(pl, "system(") {
		t.Errorf("redis_set_payload did not capture the webshell body: %q", pl)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "redis-drop-chain-complete") || !containsStr(anoms, "redis-payload-staged") {
		t.Errorf("drop-chain anomalies missing: %v", anoms)
	}
}
