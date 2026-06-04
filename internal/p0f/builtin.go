package p0f

// builtinSignatures is a curated subset of the p0f v3 database (p0f.fp
// `[tcp:request]` section), enough to name the common stacks a honeypot sees
// without any operator-supplied file. Operators can add the full p0f.fp via
// DB.LoadFile for broader coverage. Format is verbatim p0f.fp so the parser is
// exercised by the built-ins.
const builtinSignatures = `
[tcp:request]

label = Linux 3.11 and newer
sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0

label = Linux 3.1-3.10
sig   = *:64:0:*:mss*10,4:mss,sok,ts,nop,ws:df,id+:0

label = Linux 2.6.x
sig   = *:64:0:*:mss*4,6:mss,sok,ts,nop,ws:df,id+:0

label = Linux 2.4.x
sig   = *:64:0:*:mss*4,0:mss,sok,ts,nop,ws:df,id+:0

label = Linux (no timestamps)
sig   = *:64:0:*:mss*10,7:mss,sok,nop,ws:df,id+:0

label = Windows XP
sig   = *:128:0:*:65535,0:mss,nop,nop,sok:df,id+:0

label = Windows 7 or 8
sig   = *:128:0:*:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0

label = Windows 7/8/10
sig   = *:128:0:*:8192,2:mss,nop,ws,nop,nop,sok:df,id+:0

label = Windows 10
sig   = *:128:0:*:64240,8:mss,nop,ws,nop,nop,sok:df,id+:0

label = Mac OS X
sig   = *:64:0:*:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0

label = FreeBSD
sig   = *:64:0:*:65535,6:mss,nop,ws,sok,ts:df,id+:0

label = OpenBSD
sig   = *:64:0:*:16384,3:mss,nop,nop,sok,nop,nop,ts:df,id+:0

label = Android
sig   = *:64:0:*:mss*44,8:mss,sok,ts,nop,ws:df,id+:0

label = Cisco / router
sig   = *:255:0:*:4128,0:mss:0:0

label = Embedded / IoT
sig   = *:255:0:*:5840,0:mss,sok,ts,nop,ws:df,id+:0
`
