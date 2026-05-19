# Fuzz corpus and known-good fixtures

Per Go convention, anything under this directory is excluded from `go list`
and `go build`. Fuzz tests automatically use `testdata/fuzz/FuzzXxx/` to
persist failing inputs (`go test -fuzz=FuzzXxx` writes them here).

When the CI run finds a regression, the failing input file should be
committed alongside the fix so we never lose the test case.

## Hand-curated fixtures

If you add a hand-curated wire-format sample (a TLS ClientHello from a
specific client tool, or a known-bad SSH KEXINIT we saw in the wild),
drop it as a plain `.bin` next to this README. Use it via:

    b, err := os.ReadFile("testdata/<file>.bin")
