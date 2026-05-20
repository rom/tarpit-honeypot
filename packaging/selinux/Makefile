# Build + install the tarpit-honeypot SELinux policy module.
# Requires selinux-policy-devel (Fedora/RHEL) or selinux-policy-dev (Debian).
MODULE = tarpit_honeypot
DEVEL  = /usr/share/selinux/devel/Makefile

all: $(MODULE).pp

$(MODULE).pp: $(MODULE).te $(MODULE).fc $(MODULE).if
	make -f $(DEVEL) $(MODULE).pp

install: all
	semodule -i $(MODULE).pp
	restorecon -Rv \
		/usr/local/bin/tarpit-honeypot \
		/etc/tarpit-honeypot \
		/var/lib/tarpit-honeypot \
		/var/log/tarpit-honeypot 2>/dev/null || true

uninstall:
	semodule -r $(MODULE) || true

clean:
	make -f $(DEVEL) clean || true
	rm -f $(MODULE).pp

.PHONY: all install uninstall clean
