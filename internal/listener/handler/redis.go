package handler

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

type redis struct{ id *identity.Identity }

func (r *redis) Name() string { return "redis" }

// Redis RESP protocol (port 6379). Clients open with either:
//   - inline command:  "AUTH foo\r\n" / "PING\r\n"
//   - multi-bulk array: "*N\r\n$len\r\nVAL\r\n..."
//
// Common scanner workflow: AUTH <password>, INFO, CONFIG GET *,
// and the "unprotected mode" abuse — SET / CONFIG SET dir / etc.
//
// We answer the read-only recon commands (INFO / CONFIG GET / CLIENT /
// COMMAND / HELLO / DBSIZE / TYPE / SCAN …) with believable values so a
// scanner records a real, unprotected Redis, capture the first handful of
// commands, and never execute or store anything.
func (r *redis) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	ver := "7.2.4"
	if r.id != nil {
		ver = r.id.RedisVersion()
	}

	br := bufio.NewReader(conn)
	var commands []string
	for i := 0; i < 12; i++ {
		cmd, err := readRESPCommand(br)
		if err != nil {
			if i == 0 {
				res.Meta["read_err"] = err.Error()
			}
			break
		}
		if len(cmd) == 0 {
			break
		}
		res.Payload = append(res.Payload, []byte(strings.Join(cmd, " ")+"\n")...)
		commands = append(commands, strings.Join(cmd, " "))
		// Dangerous-command detection: the redis-rogue-server abuse
		// chain (CONFIG SET dir/dbfilename to drop a webshell or cron
		// job, SLAVEOF/REPLICAOF + MODULE LOAD for RCE, FLUSHALL to
		// wipe). Flagging the command class is high-signal.
		if marker := redisDangerousCommand(cmd); marker != "" {
			flagAnomaly(&res, marker)
		}
		if r.dispatch(conn, &res, cmd, ver) {
			res.Meta["commands"] = commands
			return res, nil
		}
	}
	if len(commands) > 0 {
		res.Meta["commands"] = commands
	}
	res.BannerSent = "redis RESP (" + ver + ")"
	return res, nil
}

// dispatch writes the reply for one parsed command and reports whether the
// connection should close (QUIT). It mirrors enough of a real, unprotected
// Redis that recon commands return plausible data instead of errors.
func (r *redis) dispatch(conn net.Conn, res *Result, cmd []string, ver string) (done bool) {
	verb := strings.ToUpper(cmd[0])
	sub := ""
	if len(cmd) >= 2 {
		sub = strings.ToUpper(cmd[1])
	}
	switch verb {
	case "AUTH":
		// "AUTH pass" or ACL "AUTH user pass" — capture, then reject so the
		// password lands in meta while the box still looks password-protected.
		pw := cmd[len(cmd)-1]
		res.Meta["auth_password"] = pw
		user := "default"
		if len(cmd) >= 3 {
			user = cmd[1]
		}
		flagDefaultCred(res, user, pw)
		_, _ = conn.Write([]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n"))
	case "PING":
		if len(cmd) >= 2 {
			writeRESPBulk(conn, cmd[1])
		} else {
			_, _ = conn.Write([]byte("+PONG\r\n"))
		}
	case "ECHO":
		if len(cmd) >= 2 {
			writeRESPBulk(conn, cmd[1])
		} else {
			_, _ = conn.Write([]byte("$0\r\n\r\n"))
		}
	case "INFO":
		writeRESPBulk(conn, redisINFO(ver, sub))
	case "CONFIG":
		switch sub {
		case "GET":
			pat := "*"
			if len(cmd) >= 3 {
				pat = cmd[2]
			}
			writeRESPArray(conn, redisConfigGet(pat, ver))
		case "SET", "REWRITE", "RESETSTAT":
			_, _ = conn.Write([]byte("+OK\r\n"))
		default:
			_, _ = conn.Write([]byte("-ERR Unknown CONFIG subcommand\r\n"))
		}
	case "CLIENT":
		switch sub {
		case "SETNAME", "SETINFO", "NO-EVICT", "NO-TOUCH":
			// CLIENT SETNAME <name> / SETINFO lib-name <v> volunteers the
			// connecting client's app/library identity — capture it.
			if (sub == "SETNAME" || sub == "SETINFO") && len(cmd) >= 3 {
				res.Meta["redis_client_name"] = clipStr(strings.Join(cmd[2:], " "), 256)
			}
			_, _ = conn.Write([]byte("+OK\r\n"))
		case "GETNAME":
			_, _ = conn.Write([]byte("$0\r\n\r\n"))
		case "ID":
			_, _ = conn.Write([]byte(":17\r\n"))
		case "INFO":
			writeRESPBulk(conn, "id=17 addr=127.0.0.1:0 name= age=0 idle=0 flags=N db=0 cmd=client|info")
		case "LIST":
			writeRESPBulk(conn, "id=17 addr=127.0.0.1:0 name= age=0 idle=0 flags=N db=0 cmd=client|list\n")
		default:
			_, _ = conn.Write([]byte("+OK\r\n"))
		}
	case "HELLO":
		// RESP3 handshake (redis-cli, many scanners). Reply with a map
		// (RESP3) or a flat array (RESP2) carrying the server identity.
		resp3 := len(cmd) >= 2 && cmd[1] == "3"
		_, _ = conn.Write([]byte(redisHello(ver, resp3)))
	case "COMMAND":
		switch sub {
		case "COUNT":
			_, _ = conn.Write([]byte(":240\r\n"))
		default:
			_, _ = conn.Write([]byte("*0\r\n"))
		}
	case "DBSIZE":
		_, _ = conn.Write([]byte(":0\r\n"))
	case "SELECT":
		_, _ = conn.Write([]byte("+OK\r\n"))
	case "TYPE":
		_, _ = conn.Write([]byte("+none\r\n"))
	case "TTL", "PTTL":
		_, _ = conn.Write([]byte(":-2\r\n"))
	case "GET", "GETDEL":
		_, _ = conn.Write([]byte("$-1\r\n"))
	case "EXISTS", "DEL", "UNLINK", "STRLEN", "LLEN", "SCARD", "HLEN":
		_, _ = conn.Write([]byte(":0\r\n"))
	case "KEYS", "HGETALL", "SMEMBERS", "LRANGE", "ACL":
		if verb == "ACL" && sub == "WHOAMI" {
			writeRESPBulk(conn, "default")
		} else if verb == "ACL" && sub == "LIST" {
			writeRESPArray(conn, []string{"user default on nopass ~* &* +@all"})
		} else {
			_, _ = conn.Write([]byte("*0\r\n"))
		}
	case "SCAN":
		// cursor 0 (iteration complete) + empty key list.
		_, _ = conn.Write([]byte("*2\r\n$1\r\n0\r\n*0\r\n"))
	case "SET", "SETEX", "HSET", "LPUSH", "RPUSH", "SADD", "EXPIRE":
		_, _ = conn.Write([]byte("+OK\r\n"))
	case "SLAVEOF", "REPLICAOF":
		_, _ = conn.Write([]byte("+OK\r\n"))
	case "SAVE", "BGSAVE", "BGREWRITEAOF":
		_, _ = conn.Write([]byte("+OK\r\n"))
	case "MODULE":
		if sub == "LIST" {
			_, _ = conn.Write([]byte("*0\r\n"))
		} else {
			_, _ = conn.Write([]byte("-ERR Error loading the extension. Please check the server logs.\r\n"))
		}
	case "LOLWUT":
		writeRESPBulk(conn, "Redis ver. "+ver+"\n")
	case "QUIT":
		_, _ = conn.Write([]byte("+OK\r\n"))
		return true
	default:
		_, _ = conn.Write([]byte(fmt.Sprintf("-ERR unknown command '%s'\r\n", cmd[0])))
	}
	return false
}

// writeRESPBulk writes a RESP bulk string ($<len>\r\n<data>\r\n).
func writeRESPBulk(conn net.Conn, s string) {
	_, _ = conn.Write([]byte("$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n"))
}

// writeRESPArray writes a RESP array of bulk strings.
func writeRESPArray(conn net.Conn, items []string) {
	var b strings.Builder
	b.WriteString("*" + strconv.Itoa(len(items)) + "\r\n")
	for _, it := range items {
		b.WriteString("$" + strconv.Itoa(len(it)) + "\r\n" + it + "\r\n")
	}
	_, _ = conn.Write([]byte(b.String()))
}

// redisConfigGet returns the key/value pairs a CONFIG GET would yield for a
// pattern. The famous attack-relevant keys (dir / dbfilename / save /
// requirepass / protected-mode) are always present so the recon looks real.
func redisConfigGet(pattern, ver string) []string {
	all := [][2]string{
		{"maxmemory", "0"},
		{"maxmemory-policy", "noeviction"},
		{"save", "3600 1 300 100 60 10000"},
		{"appendonly", "no"},
		{"dir", "/var/lib/redis"},
		{"dbfilename", "dump.rdb"},
		{"logfile", "/var/log/redis/redis-server.log"},
		{"bind", "127.0.0.1 -::1"},
		{"protected-mode", "yes"},
		{"requirepass", ""},
		{"databases", "16"},
		{"tcp-keepalive", "300"},
		{"timeout", "0"},
	}
	pat := strings.ToLower(strings.TrimSpace(pattern))
	var out []string
	for _, kv := range all {
		if pat == "*" || pat == "" || kv[0] == pat {
			out = append(out, kv[0], kv[1])
		}
	}
	return out
}

// redisHello renders a HELLO reply: a RESP3 map or a RESP2 flat array of the
// server-identity fields a client reads after the protocol handshake.
func redisHello(ver string, resp3 bool) string {
	fields := [][2]string{
		{"server", "redis"},
		{"version", ver},
		{"proto", "2"},
		{"id", "17"},
		{"mode", "standalone"},
		{"role", "master"},
	}
	if resp3 {
		fields[2][1] = "3"
	}
	var b strings.Builder
	if resp3 {
		b.WriteString("%" + strconv.Itoa(len(fields)+1) + "\r\n")
	} else {
		b.WriteString("*" + strconv.Itoa((len(fields)+1)*2) + "\r\n")
	}
	for _, kv := range fields {
		b.WriteString("$" + strconv.Itoa(len(kv[0])) + "\r\n" + kv[0] + "\r\n")
		if kv[0] == "proto" || kv[0] == "id" {
			b.WriteString(":" + kv[1] + "\r\n")
		} else {
			b.WriteString("$" + strconv.Itoa(len(kv[1])) + "\r\n" + kv[1] + "\r\n")
		}
	}
	// modules: empty array.
	b.WriteString("$7\r\nmodules\r\n*0\r\n")
	return b.String()
}

// redisINFO renders an INFO reply (optionally a single section). It carries
// the per-deployment version plus believable server/clients/memory/stats/
// replication/keyspace fields — the first thing a redis scanner reads.
func redisINFO(ver, section string) string {
	sections := map[string]string{
		"server":      "# Server\r\nredis_version:" + ver + "\r\nredis_mode:standalone\r\nos:Linux 5.15.0-91-generic x86_64\r\narch_bits:64\r\nrun_id:" + redisRunID(ver) + "\r\ntcp_port:6379\r\nuptime_in_seconds:864231\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\n",
		"clients":     "# Clients\r\nconnected_clients:1\r\nblocked_clients:0\r\nmaxclients:10000\r\n",
		"memory":      "# Memory\r\nused_memory:1048576\r\nused_memory_human:1.00M\r\nused_memory_rss:5242880\r\nmaxmemory:0\r\nmaxmemory_policy:noeviction\r\nmem_allocator:jemalloc-5.3.0\r\n",
		"persistence": "# Persistence\r\nloading:0\r\nrdb_changes_since_last_save:0\r\nrdb_last_save_time:1700000000\r\naof_enabled:0\r\n",
		"stats":       "# Stats\r\ntotal_connections_received:42\r\ntotal_commands_processed:128\r\ninstantaneous_ops_per_sec:0\r\nkeyspace_hits:0\r\nkeyspace_misses:0\r\n",
		"replication": "# Replication\r\nrole:master\r\nconnected_slaves:0\r\nmaster_failover_state:no-failover\r\n",
		"keyspace":    "# Keyspace\r\n",
	}
	order := []string{"server", "clients", "memory", "persistence", "stats", "replication", "keyspace"}
	want := strings.ToLower(strings.TrimSpace(section))
	var b strings.Builder
	for _, s := range order {
		if want != "" && want != "default" && want != "all" && want != "everything" && want != s {
			continue
		}
		b.WriteString(sections[s])
		b.WriteString("\r\n")
	}
	return b.String()
}

// redisRunID derives a stable 40-hex run_id-shaped string from the version
// so it looks like a real server id without leaking anything.
func redisRunID(seed string) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 40)
	// FNV-1-style mix in uint32 (wraps cleanly; 32-bit-safe so the arm
	// cross builds compile — int would overflow on 32-bit platforms).
	h := uint32(0x811c9dc5)
	for i := 0; i < 40; i++ {
		h = (h ^ uint32(seed[i%len(seed)]) ^ uint32(i*7)) * 0x01000193
		out[i] = hexd[(h>>8)&0x0f]
	}
	return string(out)
}

// redisDangerousCommand classifies a redis command into an anomaly
// marker for the well-known abuse primitives, or "" for benign ones.
func redisDangerousCommand(cmd []string) string {
	if len(cmd) == 0 {
		return ""
	}
	switch strings.ToUpper(cmd[0]) {
	case "CONFIG":
		// CONFIG SET dir / dbfilename is the webshell/cron drop vector.
		if len(cmd) >= 2 && strings.EqualFold(cmd[1], "SET") {
			return "redis-config-set"
		}
	case "SLAVEOF", "REPLICAOF":
		// Rogue-master replication -> module-load RCE.
		return "redis-replication-takeover"
	case "MODULE":
		if len(cmd) >= 2 && strings.EqualFold(cmd[1], "LOAD") {
			return "redis-module-load"
		}
	case "FLUSHALL", "FLUSHDB":
		return "redis-flush"
	case "SAVE", "BGSAVE":
		return "redis-save" // pairs with CONFIG SET in the drop chain
	case "EVAL", "EVALSHA", "FUNCTION":
		return "redis-script-exec"
	}
	return ""
}

// readRESPCommand parses one Redis command from br as a list of strings.
// Handles both inline ("PING\r\n") and multi-bulk ("*N\r\n$len\r\nVAL\r\n...").
func readRESPCommand(br *bufio.Reader) ([]string, error) {
	first, err := br.Peek(1)
	if err != nil {
		return nil, err
	}
	if first[0] != '*' {
		// Inline command
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		return strings.Fields(strings.TrimRight(line, "\r\n")), nil
	}
	header, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimRight(header[1:], "\r\n"))
	if err != nil || n < 0 || n > 64 {
		return nil, fmt.Errorf("bad array length")
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		dollar, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if len(dollar) < 1 || dollar[0] != '$' {
			return nil, fmt.Errorf("expected $-prefixed bulk")
		}
		blen, err := strconv.Atoi(strings.TrimRight(dollar[1:], "\r\n"))
		if err != nil || blen < 0 || blen > 8192 {
			return nil, fmt.Errorf("bad bulk length")
		}
		buf := make([]byte, blen)
		if _, err := br.Read(buf); err != nil {
			return nil, err
		}
		// consume trailing CRLF
		_, _ = br.ReadByte()
		_, _ = br.ReadByte()
		out = append(out, string(buf))
	}
	return out, nil
}
