package handler

import "strings"

// ftpGlobDoS reports whether an FTP command argument looks like the vsftpd 2.3.2
// recursive-glob denial of service (Metasploit auxiliary/dos/ftp/vsftpd_232):
// a path crammed with glob metacharacters (* ? [ {) or traversal segments, long
// enough to make the server's glob expansion spin while it fills its ~4096-byte
// buffer. vsftpd 2.3.0–2.3.2 burn a whole CPU core unwinding such a pattern.
func ftpGlobDoS(arg string) bool {
	if arg == "" {
		return false
	}
	meta := strings.Count(arg, "*") + strings.Count(arg, "?") +
		strings.Count(arg, "[") + strings.Count(arg, "{")
	// A long argument stuffed with glob metacharacters / traversals is the tell;
	// a legitimate path is short and has at most one or two wildcards.
	if len(arg) >= 200 && (meta >= 10 || strings.Count(arg, "../") >= 20) {
		return true
	}
	// An absurd number of wildcards even in a shorter string, or an argument
	// approaching the 4096-byte command buffer, is abnormal on its own.
	if meta >= 30 || len(arg) >= 2048 {
		return true
	}
	return false
}

// flagFTPGlobDoS records the vsftpd-2.3.2 glob-DoS attempt on res when arg
// matches. ftpGlobDoS-positive commands are LIST/NLST/STAT/SIZE/RETR and the
// like (anything that globs a path), but the shape is detected on the argument
// regardless of the verb.
func flagFTPGlobDoS(res *Result, cmd, arg string) {
	if !ftpGlobDoS(arg) {
		return
	}
	flagAnomaly(res, "ftp-glob-dos")
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	res.Meta["ftp_glob_dos_cmd"] = cmd
	res.Meta["ftp_glob_dos_len"] = len(arg)
}
