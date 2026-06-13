# Lua service personas

`tarpit-honeypot` ships a `lua` protocol handler that lets you define a fake
service — a "persona" — as a small [Lua](https://www.lua.org/) script instead of
Go code. A persona reads what an attacker sends, records the interesting parts,
flags the attack, and writes back a believable response. **240 personas ship in
the box** (under [`configs/scripts/`](../configs/scripts/)); you can add your own
without recompiling.

> New here? [`scripting.md`](scripting.md) is the big-picture map of how Lua,
> YAML and YARA divide the work in a deployment — read it first if you're not
> sure whether your idea wants a Lua persona, a `scripted` YAML service, or a
> detection rule.

## What Lua is

Lua is a tiny, fast, embeddable scripting language. tarpit-honeypot embeds it
with [gopher-lua](https://github.com/yuin/gopher-lua) — a pure-Go Lua 5.1 VM —
so a script runs in-process with no external interpreter and no extra
dependencies. You do not need to know Lua deeply: a persona is usually 20–60
lines of straight-line "read a line, match a path, write a response" code.

## Lua in 60 seconds (syntax cheat-sheet)

Enough Lua to write a persona without prior Lua experience:

```lua
-- comments start with two dashes
local x = 5                 -- 'local' scopes a variable (always use it)
local s = "hi" .. "there"   -- '..' concatenates strings; '#s' is length
local t = {"a", "b", "c"}   -- tables are the only data structure; 1-INDEXED
t[1]                        --   → "a"   (not t[0]!)
local m = {name = "db", port = 3306}   -- tables double as maps:  m.name / m["name"]

if x > 3 then  ... elseif x == 0 then ... else ... end
for i = 1, 10 do ... end                 -- numeric loop, inclusive
for _, v in ipairs(t) do ... end         -- iterate a list
while cond do ... break ... end
local function f(a, b) return a + b end   -- functions

tostring(3306)   tonumber("3306")        -- conversions; nil if not a number
nil  true  false                          -- 'nil' is absence; only nil/false are falsy
```

**The one big gotcha: Lua patterns are NOT regular expressions.** `string.match`
/ `:find` / `:gsub` use Lua's own lightweight pattern syntax. It is *similar* but
different — no alternation, no `{n,m}`, and the escape char is `%`, not `\`:

| Lua pattern | Meaning | Regex equivalent |
|---|---|---|
| `%d %a %s %w` | digit / letter / space / alphanumeric | `\d \a \s \w` |
| `%u %l %p` | upper / lower / punctuation | `[A-Z] [a-z]` … |
| `.` | any character | `.` |
| `%.` `%-` `%(` | a **literal** `.` `-` `(` (escape magic chars with `%`) | `\.` `\-` `\(` |
| `*` `+` `-` `?` | 0+ (greedy) / 1+ / 0+ (lazy) / optional | `*` `+` `*?` `?` |
| `^pat` `pat$` | anchor to start / end of subject | `^` `$` |
| `( )` | a capture (returned by `match`) | capture group |
| `[%d.]` | a class set (digit or dot) | `[0-9.]` |

There is **no `|` alternation and no `{2,5}`** — write alternatives as separate
`match` attempts. Common idioms a persona uses:

```lua
local method, path = reqline:match("^(%u+)%s+(%S+)")   -- "GET /x"  → "GET", "/x"
local n = header:match("^[Cc]ontent%-[Ll]ength:%s*(%d+)")   -- note %- for the dash
local clean = line:gsub("[\r\n]", "")                  -- strip CR/LF (returns string, count)
if path:find("/admin", 1, true) then ... end           -- plain substring (4th arg true = no patterns)
local user = body:match("username=([^&]+)")            -- capture up to the next '&'
```

(`:find(needle, 1, true)` does a *plain* substring search — use it whenever the
needle contains magic characters like `.` or `-` and you don't want pattern
semantics.)

## How it works with this tool

```
                      ┌─ one gopher-lua VM per connection ─┐
TCP connection ─────► │  your script runs top-to-bottom    │ ─► Result
(handler: lua)        │   conn:read/write  ·  meta()/flag() │   (event)
                      └────────────────────────────────────┘
```

1. A listener with `handler: lua` and a `script:` path loads + **compiles the
   script once** at startup (a compile error aborts the run with a clear
   message).
2. For **each connection**, the engine creates a fresh sandboxed VM, installs
   the persona API (below), and executes the script top-to-bottom. There is no
   `main()` — the whole file is the entry point.
3. Whatever the script records via `meta()` / `flag()` and the bytes it sends
   become the event the sensor stores, correlates, and ships to your sinks.

Wire it up in the config:

```yaml
listeners:
  - { id: phpmyadmin, proto: tcp, bind: 0.0.0.0:8080, mode: banner,
      handler: lua, script: configs/scripts/phpmyadmin.lua,
      severity: high, capture: true }
```

`script:` is a path (relative to the working directory or absolute). The
`scripted` handler is a *declarative* (YAML) alternative for simple
request/response protocols; reach for `lua` when you need logic.

## The persona API

These globals/objects are installed in every script's VM:

### Connection I/O — `conn`
| Call | Returns | Notes |
|---|---|---|
| `conn:read(n)` | string or nil | read up to `n` bytes (capped at 4096/call) |
| `conn:readline()` | string or nil | read one line (up to 8192 bytes, or to `\n`) |
| `conn:write(s)` | — | write `s` to the socket |

Always handle EOF: `local line = conn:readline(); if not line then return end`.

### Recording — `meta()`, `flag()`, `log()`
| Call | Effect |
|---|---|
| `meta(key, value)` | record a key/value on the event (any Lua scalar) |
| `flag(marker)` | raise an anomaly `lua:<marker>` (the SIEM/correlators pivot on it) |
| `log(s)` | append a sanitized debug string to `meta.lua_log` |

**Credentials you record with a sensibly-named key are surfaced automatically**
on the `/captures` page and attacker profiles (the captures pipeline recognizes
keys containing `user`/`pass`/`token`/`auth`/`secret`/`key`/`hash`/`cookie`/…).
So `meta("auth_user", u)` and `meta("auth_pass", p)` "just work".

### Identity & state
| Call | Returns |
|---|---|
| `peer` | the source IP string (a global) |
| `session` | a per-connection table (scratch space, cleared when the conn closes) |
| `personality()` | a stable-per-source table `{hostname, version, firmware, serial}` |
| `host:get(key)` / `host:set(key, v)` | persistent per-source state (TTL ~1h, ≤256 keys) |
| `archetype.name` / `archetype.family` | the listener/sensor archetype (read-only) |

### Deterministic randomness — `rng`
Seeded per `(deployment, source, script)`, so a re-query from the same attacker
is consistent and two deployments differ (defeats banner-clustering):
`rng:int(n)` (0..n-1), `rng:choice(table)`, `rng:hex(n)` (n hex bytes).

### Time & pacing
`time.now()` (unix s), `time.ms()`, `time.utc()` (HTTP-date string),
`time.uptime()` (process uptime s), `sleep(ms)` (cooperative, bounded — see below).

## Restrictions & limits (read this)

The VM is **deliberately locked down** — it processes hostile input from the
internet:

- **No `io`, `os`, `debug`, `package`/`require`, `load`/`loadstring`, `dofile`,
  `print`.** Only the safe `base`, `string`, `table` and `math` libraries are
  open. A persona cannot touch the filesystem, run a process, open a socket, or
  load more code. This is the whole point — even a buggy persona can't be turned
  into RCE on the sensor.
- **Read budget 64 KiB, write budget 256 KiB** per connection. `conn:read`
  caps at 4096 bytes/call; `conn:readline` at 8192. The write cap is an
  **anti-amplification** guarantee — a persona can never be coerced into
  emitting a huge reply to a spoofed peer.
- **Sleep budget 30 s** total per execution; the call returns early if the
  connection's deadline (the listener `read_timeout`) fires.
- **A wall-clock deadline** (the listener timeout) bounds the whole run; an
  infinite loop is killed.
- One VM **per connection** — no shared mutable globals between connections
  (use `host:get/set` for cross-connection per-source state, which is bounded).

### Warnings — what NOT to do
- **Never claim to execute attacker input.** A persona *emulates* — return canned
  output, never run a command. (You can't anyway: there's no `os.execute`.)
- **Don't write unbounded data** in a loop; respect that the write budget is
  finite and that a believable service is small.
- **Don't busy-loop or `sleep` long** hoping to tarpit — use the listener's
  `tarpit:` strategy for that; a persona that wastes its budget just gets cut off.
- **Don't leak your own secrets** into responses; fabricate decoy values with
  `rng:hex()` so nothing real is exposed.
- **Sanitize nothing yourself** — `meta()` values are centrally sanitized before
  they reach a sink; just record the raw captured bytes.

## Recipes

### Minimal HTTP login persona
```lua
-- read the request line + headers
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
end
-- capture a posted login
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  local body = conn:read(clen) or ""
  local u, p = body:match("user=([^&]*)"), body:match("pass=([^&]*)")
  if u then meta("auth_user", u) end
  if p then meta("auth_pass", p) end
  if u or p then flag("myapp-login-attempt") end
end
flag("myapp-access")
-- answer like the real product
local body = "<html><title>MyApp</title><body>MyApp 4.2</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: MyApp/4.2\r\nContent-Type: text/html\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#body) .. "\r\n\r\n" .. body)
```

### Stable identity + per-source state
```lua
local id = personality()            -- same hostname/serial for this source every time
meta("device_serial", id.serial)
local hits = (host:get("hits") or 0) + 1
host:set("hits", hits)              -- survives across this source's reconnects (~1h)
if hits > 5 then flag("myapp-repeat-probe") end
```

### Banner-first protocol (server speaks first)
```lua
conn:write("220 " .. personality().hostname .. " MyFTP 2.3.4 ready\r\n")
for _ = 1, 30 do
  local line = conn:readline()
  if not line then break end
  local cmd = line:match("^(%u+)")
  if cmd == "USER" then meta("user_line", line:gsub("[\r\n]", "")); conn:write("331 password please\r\n")
  elseif cmd == "PASS" then meta("pass_line", line:gsub("[\r\n]", "")); flag("ftp-login-attempt"); conn:write("530 denied\r\n")
  elseif cmd == "QUIT" then conn:write("221 bye\r\n"); break
  else conn:write("500 unknown\r\n") end
end
```

## The personas that ship

240 personas ship under [`configs/scripts/`](../configs/scripts/) — run
`ls configs/scripts/` for the full list. They span:

- **Web apps / CMS**: phpMyAdmin, Adminer, WordPress, Drupal, Joomla, TYPO3,
  Magento, MediaWiki, Redmine, ThinkPHP, Strapi, Craft, …
- **Enterprise / DevOps**: Jenkins, GitLab, Gitea, Confluence, Jira, Bitbucket,
  SonarQube, Nexus, Artifactory, Harbor, Argo CD, Rancher, Portainer, AWX,
  Rundeck, Vault, Consul, Nomad, Keycloak, Kong, NetBox, phpIPAM, …
- **VPN / security appliances**: FortiOS, GlobalProtect, NetScaler, Ivanti,
  Cisco ASA/IOS-XE/ISE, F5 BIG-IP, Check Point, Sophos, Zyxel, SonicWall,
  FortiManager, GoAnywhere, CrushFTP, Serv-U, WhatsUp Gold, …
- **Infra / virtualization / storage**: VMware ESXi/vCenter/NSX, Proxmox,
  Cockpit, Kubernetes, OpenShift, Synology, QNAP, ownCloud, Seafile, MinIO, …
- **Monitoring / data / mail**: Grafana, Kibana, Splunk, Zabbix, Cacti,
  Nagios XI, LibreNMS, PRTG, Graylog, Centreon, Prometheus, Elasticsearch-ish,
  Redis, ClickHouse, InfluxDB, Roundcube, Horde, SquirrelMail, Zimbra, …
- **OT / ICS / IoT panels**: Niagara, Ignition, WinCC, Moxa, SEL relay,
  Codesys, historian/HMI panels, BMS login, generic IoT login, …
- **Telephony**: 3CX, FreePBX, FusionPBX, Issabel, Vicidial, CUCM, Avaya,
  Yealink/Polycom phones, …

Each persona captures the credentials/paths an attacker sends and flags the
product's signature exploit attempt (e.g. `lua:fortios-cve-2018-13379-probe`).

## Testing a persona

Every shipped script is compiled + run against representative input by
`TestShippedScriptsCompileAndRun`, and many have a behaviour test asserting they
flag the right marker. To check your own script:

```
go test ./internal/luaengine/ -run TestShippedScriptsCompileAndRun
```

or just point a listener at it and probe it with `curl`/`nc`.
