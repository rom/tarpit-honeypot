# RPM spec file. Build with:
#
#   rpmbuild --define "_topdir $PWD/dist/rpmbuild" \
#            --define "version $(git describe --tags --always)" \
#            --define "src_root $PWD" \
#            --define "bin_path dist/tarpit-honeypot-linux-amd64" \
#            -bb packaging/rpm/tarpit-honeypot.spec
#
# Or use packaging/rpm/build.sh which wraps the boilerplate.

Name:           tarpit-honeypot
Version:        %{version}
Release:        1%{?dist}
Summary:        Low-to-medium interaction deception sensor

License:        ASL 2.0
URL:            https://github.com/rom/tarpit-honeypot
BuildArch:      x86_64

# We ship a pre-built static binary; no Go toolchain on the build host.
%global debug_package %{nil}
AutoReqProv:    no
Requires:       systemd

%description
Single static Go binary that runs protocol-shaped honeypots,
file / URL / DNS canary tokens, port-scan / brute-force / slow-scan
correlation, per-event pcap capture, and SIEM-friendly outbound
channels (CEF / LEEF / OCSF / JSON / MQTT / SMS / SNS).

%prep
# Nothing to unpack — `bin_path` is consumed directly in %%install.

%install
rm -rf %{buildroot}
install -d -m 0755 %{buildroot}%{_bindir}
install -d -m 0755 %{buildroot}%{_sysconfdir}/tarpit-honeypot
install -d -m 0755 %{buildroot}%{_sysconfdir}/tarpit-honeypot/conf.d
install -d -m 0755 %{buildroot}%{_unitdir}
install -d -m 0750 %{buildroot}/var/lib/tarpit-honeypot
install -d -m 0755 %{buildroot}%{_datadir}/bash-completion/completions
install -d -m 0755 %{buildroot}%{_datadir}/zsh/site-functions
install -d -m 0755 %{buildroot}%{_datadir}/fish/vendor_completions.d

install -m 0755 %{src_root}/%{bin_path}                                   %{buildroot}%{_bindir}/tarpit-honeypot
install -m 0640 %{src_root}/configs/tarpit-honeypot.example.yaml          %{buildroot}%{_sysconfdir}/tarpit-honeypot/config.yaml
install -m 0644 %{src_root}/packaging/systemd/tarpit-honeypot.service     %{buildroot}%{_unitdir}/tarpit-honeypot.service

%{buildroot}%{_bindir}/tarpit-honeypot completion bash > %{buildroot}%{_datadir}/bash-completion/completions/tarpit-honeypot
%{buildroot}%{_bindir}/tarpit-honeypot completion zsh  > %{buildroot}%{_datadir}/zsh/site-functions/_tarpit-honeypot
%{buildroot}%{_bindir}/tarpit-honeypot completion fish > %{buildroot}%{_datadir}/fish/vendor_completions.d/tarpit-honeypot.fish

%files
%license %{src_root}/LICENSE
%doc %{src_root}/README.md %{src_root}/CHANGELOG.md
%{_bindir}/tarpit-honeypot
%config(noreplace) %{_sysconfdir}/tarpit-honeypot/config.yaml
%dir %{_sysconfdir}/tarpit-honeypot/conf.d
%{_unitdir}/tarpit-honeypot.service
%dir %attr(0750, honey, honeypot) /var/lib/tarpit-honeypot
%{_datadir}/bash-completion/completions/tarpit-honeypot
%{_datadir}/zsh/site-functions/_tarpit-honeypot
%{_datadir}/fish/vendor_completions.d/tarpit-honeypot.fish

%pre
# Service account must match the shipped systemd unit (User=honey,
# Group=honeypot) or the service won't start.
getent group honeypot >/dev/null 2>&1 || groupadd --system honeypot
getent passwd honey >/dev/null 2>&1 || \
    useradd --system --gid honeypot --no-create-home --shell /sbin/nologin honey

%post
%systemd_post tarpit-honeypot.service

%preun
%systemd_preun tarpit-honeypot.service

%postun
%systemd_postun_with_restart tarpit-honeypot.service

%changelog
* Mon May 19 2026 tarpit-honeypot <noreply@example.com> - %{version}-1
- See CHANGELOG.md
