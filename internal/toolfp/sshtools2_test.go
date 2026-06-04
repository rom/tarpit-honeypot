package toolfp

import "testing"

// TestSSHToolSignaturesBatch2 pins the second batch of 40 SSH client/stack
// banners: cross-language SSH libraries, enterprise/MFT SSH servers & clients,
// PAM/zero-trust bastions, network-device SSH stacks, and SSH attack tools.
func TestSSHToolSignaturesBatch2(t *testing.T) {
	cases := []struct{ banner, tool string }{
		{"SSH-2.0-J2SSH_Maverick", "j2ssh"},
		{"SSH-2.0-Chilkat_1.0", "chilkat-ssh"},
		{"SSH-2.0-IPWorks_SSH", "ipworks-ssh"},
		{"SSH-2.0-6.2.0.0 SSH Tectia Server", "tectia-ssh"},
		{"SSH-2.0-3.2.0 F-Secure SSH", "f-secure-ssh"},
		{"SSH-2.0-OpenSSH_9.6 PKIX[13.5]", "pkix-ssh"},
		{"SSH-2.0-OpenSSH_8.5p1-hpn15v1", "hpn-ssh"},
		{"SSH-2.0-RedSSH_1.0", "redssh"},
		{"SSH-2.0-SharpSSH-1.1.1.13", "sharpssh"},
		{"SSH-2.0-CrushFTPSSHD", "crushftp"},
		{"SSH-2.0-GoAnywhere", "goanywhere-ssh"},
		{"SSH-2.0-GlobalSCAPE", "globalscape-ssh"},
		{"SSH-2.0-CompleteFTP_22.0", "completeftp"},
		{"SSH-2.0-TitanFTP", "titanftp"},
		{"SSH-2.0-Serv-U_15.4", "serv-u"},
		{"SSH-2.0-WingFTP", "wingftp"},
		{"SSH-2.0-FileZilla_server_1.7", "filezilla-ssh"},
		{"SSH-2.0-Termius", "termius"},
		{"SSH-2.0-RoyalTS", "royalts"},
		{"SSH-2.0-Devolutions", "devolutions"},
		{"SSH-2.0-2.0 FlowSsh: Bitvise SSH Server 9.31", "bitvise"},
		{"SSH-2.0-MobaXterm_24.0", "mobaxterm"},
		{"SSH-2.0-Teleport", "teleport-ssh"},
		{"SSH-2.0-Warpgate 0.9", "warpgate"},
		{"SSH-2.0-sshpiper", "sshpiper"},
		{"SSH-2.0-WALLIX-Bastion", "wallix"},
		{"SSH-2.0-CyberArk-PSM", "cyberark-ssh"},
		{"SSH-2.0-ScaleFT_1.0", "scaleft"},
		{"SSH-2.0-smallstep_ssh", "smallstep-ssh"},
		{"SSH-2.0-Boundary", "boundary-ssh"},
		{"SSH-2.0-ROSSSH", "mikrotik-ssh"},
		{"SSH-2.0-Cisco-1.25", "cisco-ssh"},
		{"SSH-2.0-Comware-7.1", "comware-ssh"},
		{"SSH-2.0-HUAWEI-1.5", "huawei-ssh"},
		{"SSH-2.0-NetScreen", "netscreen-ssh"},
		{"SSH-2.0-Ncrack", "ncrack"},
		{"SSH-2.0-sshprank", "sshprank"},
		{"SSH-2.0-ssh-snake", "ssh-snake"},
		{"SSH-2.0-crassh", "crassh"},
		{"SSH-2.0-ssh-auditor", "ssh-auditor"},
	}
	if len(cases) != 40 {
		t.Fatalf("expected 40 SSH signatures, have %d", len(cases))
	}
	for _, c := range cases {
		got := IdentifySSH(c.banner)
		ok := false
		for _, tl := range got {
			if tl == c.tool {
				ok = true
			}
		}
		if !ok {
			t.Errorf("banner %q: %q not identified (%v)", c.banner, c.tool, got)
		}
	}
}

// TestIdentifyDNS pins the DNS QNAME tool/service fingerprints.
func TestIdentifyDNS(t *testing.T) {
	cases := []struct{ qname, tool string }{
		{"version.bind", "fpdns"},
		{"version.server", "fpdns"},
		{"hostname.bind", "dns-recon-probe"},
		{"id.server", "dns-recon-probe"},
		{"authors.bind", "dns-recon-probe"},
		{"abc.burpcollaborator.net", "burp-collaborator"},
		{"x.oast.fun", "interactsh"},
		{"y.oast.site", "interactsh"},
		{"z.oast.online", "interactsh"},
		{"q.interact.sh", "interactsh"},
		{"a.dnslog.cn", "dnslog"},
		{"b.ceye.io", "ceye"},
		{"tok.canarytokens.com", "canarytoken"},
		{"10.0.0.1.nip.io", "dns-rebind-service"},
		{"127.0.0.1.sslip.io", "dns-rebind-service"},
		{"1.2.3.4.xip.io", "dns-rebind-service"},
		{"make.1u.ms", "dns-rebind-service"},
		{"dnscat.evil.com", "dnscat2"},
		{"abc.dns2tcp.example", "dns2tcp"},
		{"node.tcpoverdns.net", "tcp-over-dns"},
	}
	if len(cases) != 20 {
		t.Fatalf("expected 20 DNS signatures, have %d", len(cases))
	}
	for _, c := range cases {
		got := IdentifyDNS(c.qname)
		ok := false
		for _, tl := range got {
			if tl == c.tool {
				ok = true
			}
		}
		if !ok {
			t.Errorf("qname %q: %q not identified (%v)", c.qname, c.tool, got)
		}
	}
	if IdentifyDNS("www.example.com") != nil {
		t.Error("benign qname should not be fingerprinted")
	}
}
