// Package systemd exists only to host unit_hardening_test.go, a drift guard
// that asserts every shipped systemd unit carries the full set of security
// hardening directives. It has no runtime code.
package systemd
