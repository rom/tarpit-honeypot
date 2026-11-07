package shell

import (
	"path"
	"strings"
	"time"
)

// A persistent, per-attacker mutation-overlay filesystem for the interactive
// shell. The canned response table (responses.go) still answers reads of the
// believable base image (/etc/passwd, a home listing, …); this overlay records
// what the ATTACKER changes — files they touch/mkdir/echo-into, payloads they
// wget/curl, things they rm — and the handler persists it keyed by source IP.
// So an attacker who drops a bot and reconnects finds their own dropper still
// there, and the operator gets the dropper name + URL preserved across sessions.
//
// It is deliberately a thin overlay, not a real kernel FS: unknown commands and
// reads of untouched base paths fall through to the canned table, so behaviour
// stays believable without emulating all of coreutils. Everything is bounded
// (node count + total bytes) so a flood can't exhaust memory or disk.

const (
	vfsMaxNodes   = 256
	vfsMaxBytes   = 64 << 10 // total overlay content kept per attacker
	vfsMaxPerFile = 8 << 10
)

// FSNode is one overlay file or directory.
type FSNode struct {
	Dir     bool      `json:"dir,omitempty"`
	Content string    `json:"content,omitempty"`
	Size    int64     `json:"size,omitempty"` // reported size (may exceed stored Content)
	Src     string    `json:"src,omitempty"`  // download URL, when fetched via wget/curl
	Exec    bool      `json:"exec,omitempty"` // chmod +x applied
	Mtime   time.Time `json:"mtime,omitempty"`
}

// FS is the overlay. It is JSON-serializable so the handler can persist it under
// <data_dir>/shell-fs/<ip>.json and reload it on the attacker's next session.
type FS struct {
	Cwd       string             `json:"cwd"`
	Home      string             `json:"home"`
	Nodes     map[string]*FSNode `json:"nodes"`               // absolute path -> node
	Deleted   map[string]bool    `json:"deleted,omitempty"`   // tombstones (canned paths rm'd)
	Downloads []string           `json:"downloads,omitempty"` // URLs fetched into the fs (capture)
	bytes     int                // live content byte count (not persisted)
}

// NewFS builds an empty overlay rooted at home (default /root).
func NewFS(home string) *FS {
	if home == "" {
		home = "/root"
	}
	return &FS{Cwd: home, Home: home, Nodes: map[string]*FSNode{}, Deleted: map[string]bool{}}
}

// normalize repairs a loaded/zero FS so its maps are non-nil and recomputes the
// live byte count. Call after JSON unmarshal.
func (fs *FS) normalize() {
	if fs.Home == "" {
		fs.Home = "/root"
	}
	if fs.Cwd == "" {
		fs.Cwd = fs.Home
	}
	if fs.Nodes == nil {
		fs.Nodes = map[string]*FSNode{}
	}
	if fs.Deleted == nil {
		fs.Deleted = map[string]bool{}
	}
	fs.bytes = 0
	for _, n := range fs.Nodes {
		fs.bytes += len(n.Content)
	}
}

// resolve turns a user path (relative, absolute, ~, ., ..) into a clean
// absolute path against the current directory.
func (fs *FS) resolve(p string) string {
	p = strings.TrimSpace(p)
	switch {
	case p == "" || p == "~":
		return fs.Home
	case strings.HasPrefix(p, "~/"):
		p = fs.Home + "/" + p[2:]
	case !strings.HasPrefix(p, "/"):
		p = fs.Cwd + "/" + p
	}
	c := path.Clean(p)
	if c == "" {
		c = "/"
	}
	return c
}

// Apply handles the filesystem-mutating and navigation commands. It returns the
// output to send and whether it owned the command; (…, false) means "not mine,
// let the canned table answer".
func (fs *FS) Apply(cmd string, argv []string, line string) (string, bool) {
	switch cmd {
	case "cd":
		target := ""
		if len(argv) > 1 {
			target = argv[1]
		}
		fs.Cwd = fs.resolve(target)
		return "", true
	case "pwd":
		return fs.Cwd + "\r\n", true
	case "mkdir":
		for _, a := range fileArgs(argv[1:]) {
			fs.put(fs.resolve(a), &FSNode{Dir: true, Mtime: time.Now().UTC()})
		}
		return "", true
	case "rmdir":
		for _, a := range fileArgs(argv[1:]) {
			fs.remove(fs.resolve(a))
		}
		return "", true
	case "rm":
		for _, a := range fileArgs(argv[1:]) {
			fs.remove(fs.resolve(a))
		}
		return "", true
	case "touch":
		for _, a := range fileArgs(argv[1:]) {
			p := fs.resolve(a)
			if _, ok := fs.Nodes[p]; !ok {
				fs.put(p, &FSNode{Mtime: time.Now().UTC()})
			}
		}
		return "", true
	case "chmod":
		for _, a := range fileArgs(argv[1:]) {
			if n := fs.Nodes[fs.resolve(a)]; n != nil && strings.Contains(line, "+x") {
				n.Exec = true
			}
		}
		return "", true
	case "echo":
		return fs.echo(argv, line)
	case "wget", "curl":
		return fs.fetch(cmd, argv)
	case "cat":
		return fs.cat(argv)
	case "mv", "cp":
		return fs.moveCopy(cmd, argv)
	}
	return "", false
}

// echo implements `echo ... [> | >>] file`; without redirection it just prints.
func (fs *FS) echo(argv []string, line string) (string, bool) {
	redir, append := -1, false
	for i, a := range argv {
		if a == ">" || a == ">>" {
			redir = i
			append = a == ">>"
			break
		}
	}
	if redir < 0 {
		return strings.Join(argv[1:], " ") + "\r\n", true
	}
	if redir+1 >= len(argv) {
		return "", true
	}
	text := strings.Join(argv[1:redir], " ") + "\n"
	p := fs.resolve(argv[redir+1])
	n := fs.Nodes[p]
	if n == nil || !append {
		n = &FSNode{Mtime: time.Now().UTC()}
	}
	n.Content = capStr(n.Content+text, vfsMaxPerFile)
	n.Size = int64(len(n.Content))
	n.Mtime = time.Now().UTC()
	fs.put(p, n)
	return "", true
}

// fetch implements wget/curl: it "downloads" into a file named for the URL (or
// -O target), captures the URL, and prints a believable transfer summary. The
// dropped file persists so a reconnecting attacker (and the operator) sees it.
func (fs *FS) fetch(cmd string, argv []string) (string, bool) {
	url, out := "", ""
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-O" || a == "-o" || a == "--output" || a == "--output-document":
			if i+1 < len(argv) {
				out = argv[i+1]
				i++
			}
		case strings.HasPrefix(a, "http://"), strings.HasPrefix(a, "https://"), strings.HasPrefix(a, "ftp://"):
			url = a
		}
	}
	if url == "" {
		return "", false // not a fetch we recognize; let the canned table answer
	}
	name := out
	if name == "" {
		name = path.Base(strings.SplitN(strings.TrimRight(url, "/"), "?", 2)[0])
		if name == "" || name == "." || name == "/" {
			name = "index.html"
		}
	}
	p := fs.resolve(name)
	fs.put(p, &FSNode{
		Content: "\x7fELF\x02\x01\x01\x00(downloaded " + capStr(url, 160) + ")\n",
		Size:    102400, Src: url, Exec: false, Mtime: time.Now().UTC(),
	})
	fs.Downloads = appendUnique(fs.Downloads, url)
	if cmd == "curl" {
		return "  % Total    % Received % Xferd  Average Speed\r\n100  100k  100  100k    0     0   512k      0\r\n", true
	}
	// wget-style summary.
	return "--" + time.Now().UTC().Format("2006-01-02 15:04:05") + "--  " + url + "\r\n" +
		"Resolving host... connected.\r\n" +
		"HTTP request sent, awaiting response... 200 OK\r\n" +
		"Saving to: '" + name + "'\r\n\r\n'" + name + "' saved [102400/102400]\r\n", true
}

// cat serves an overlay file's content; a tombstoned path reports not-found;
// anything else falls through to the canned table.
func (fs *FS) cat(argv []string) (string, bool) {
	files := fileArgs(argv[1:])
	if len(files) == 0 {
		return "", false
	}
	var b strings.Builder
	owned := false
	for _, a := range files {
		p := fs.resolve(a)
		if n := fs.Nodes[p]; n != nil && !n.Dir {
			b.WriteString(strings.ReplaceAll(n.Content, "\n", "\r\n"))
			owned = true
		} else if fs.Deleted[p] {
			b.WriteString("cat: " + a + ": No such file or directory\r\n")
			owned = true
		} else {
			return "", false // untouched base path → canned dynCat
		}
	}
	return b.String(), owned
}

func (fs *FS) moveCopy(cmd string, argv []string) (string, bool) {
	files := fileArgs(argv[1:])
	if len(files) < 2 {
		return "", true
	}
	src := fs.resolve(files[0])
	dst := fs.resolve(files[len(files)-1])
	if n := fs.Nodes[src]; n != nil {
		cp := *n
		fs.put(dst, &cp)
		if cmd == "mv" {
			fs.remove(src)
		}
	}
	return "", true
}

// AugmentLs appends the overlay files/dirs living in the ls target directory to
// the canned base listing, so an attacker's own created/downloaded files show
// up. It never hides canned entries.
func (fs *FS) AugmentLs(argv []string, base string) string {
	dir := fs.Cwd
	for _, a := range fileArgs(argv[1:]) {
		dir = fs.resolve(a)
		break
	}
	have := map[string]bool{}
	for _, f := range strings.Fields(strings.ReplaceAll(base, "\r\n", "\n")) {
		have[f] = true
	}
	var extra []string
	for p, n := range fs.Nodes {
		parent := path.Dir(p)
		if parent != dir {
			continue
		}
		name := path.Base(p)
		if have[name] {
			continue
		}
		if n.Dir {
			name += "/"
		}
		extra = append(extra, name)
	}
	if len(extra) == 0 {
		return base
	}
	sortStrings(extra)
	out := base
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\r\n"
	}
	return out + strings.Join(extra, "  ") + "\r\n"
}

// prompt rewrites the base prompt's directory token to reflect the cwd.
func (fs *FS) prompt(base string) string {
	disp := "~"
	if fs.Cwd != fs.Home {
		disp = fs.Cwd
	}
	if strings.Contains(base, "~") {
		return strings.Replace(base, "~", disp, 1)
	}
	return base
}

// put inserts/updates a node, enforcing the node-count and byte caps.
func (fs *FS) put(p string, n *FSNode) {
	if p == "" || p == "/" {
		return
	}
	delete(fs.Deleted, p)
	if old := fs.Nodes[p]; old != nil {
		fs.bytes -= len(old.Content)
	} else if len(fs.Nodes) >= vfsMaxNodes {
		return // cap reached; drop silently (still looks like success to the attacker)
	}
	if fs.bytes+len(n.Content) > vfsMaxBytes {
		n.Content = "" // keep the node (name/metadata) but shed content under pressure
	}
	fs.Nodes[p] = n
	fs.bytes += len(n.Content)
}

func (fs *FS) remove(p string) {
	if n := fs.Nodes[p]; n != nil {
		fs.bytes -= len(n.Content)
		delete(fs.Nodes, p)
		return
	}
	if len(fs.Deleted) < vfsMaxNodes {
		fs.Deleted[p] = true // tombstone a canned path
	}
}

// fileArgs drops flag tokens (-rf, --force, …) from a command's arguments.
func fileArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "-") || a == ">" || a == ">>" {
			continue
		}
		out = append(out, a)
	}
	return out
}

func capStr(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
