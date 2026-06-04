package toolfp

import "testing"

// TestSSHToolSignatures pins the batch of 20 SSH stacks/libraries that attack
// tooling rides on, plus SSH-specific offensive tools, identified from the
// cleartext SSH-2.0 client banner.
func TestSSHToolSignatures(t *testing.T) {
	cases := []struct {
		banner, tool string
	}{
		{"SSH-2.0-dropbear_2022.83", "dropbear"},
		{"SSH-2.0-TinySSH_20230101", "tinyssh"},
		{"SSH-2.0-wolfSSHv1.4.15", "wolfssh"},
		{"SSH-2.0-AsyncSSH_2.14.2", "asyncssh"},
		{"SSH-2.0-Ruby/Net::SSH_7.2.0 x86_64-linux", "ruby-net-ssh"},
		{"SSH-2.0-SSHJ_0.38.0", "sshj"},
		{"SSH-2.0-Ganymed Build_261", "ganymed-ssh2"},
		{"SSH-2.0-Granados-1.0", "granados"},
		{"SSH-2.0-FlowSsh: Bitvise SSH Client 9.31", "flowssh"},
		{"SSH-2.0-cryptlib", "cryptlib"},
		{"SSH-2.0-TTSSH/2.112 Win32", "teraterm"},
		{"SSH-2.0-ssh2js1.15.0", "node-ssh2"},
		{"SSH-2.0-sshamble_0.0.1", "sshamble"},
		{"SSH-2.0-ssh-mitm-3.0.2", "ssh-mitm"},
		{"SSH-2.0-SSHD-CORE-2.12.1", "apache-mina-sshd"},
		{"SSH-2.0-WeOnlyDo 2.4.3", "weonlydo-ssh"},
		{"SSH-2.0-Syncplify_me_Server!", "syncplify-ssh"},
		{"SSH-2.0-SmartFTP", "smartftp-ssh"},
		{"SSH-2.0-Xshell 7", "xshell"},
		{"SSH-2.0-SecureCRT_9.4", "securecrt"},
	}
	if len(cases) != 20 {
		t.Fatalf("expected 20 SSH signatures, have %d", len(cases))
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
