package toolfp

import "testing"

// TestNewToolSignaturesBatch4 pins the fourth batch of 75 offensive-tooling
// fingerprints: each UA must identify the expected tool and resolve to the
// right severity category (c2 > vuln-scanner > tool).
func TestNewToolSignaturesBatch4(t *testing.T) {
	cases := []struct{ ua, tool, cat string }{
		// AD / Windows post-exploitation → "tool".
		{"mitm6", "mitm6", "tool"},
		{"Pcredz", "pcredz", "tool"},
		{"lsassy/3.1.1", "lsassy", "tool"},
		{"nanodump", "nanodump", "tool"},
		{"DonPAPI", "donpapi", "tool"},
		{"Coercer", "coercer", "tool"},
		{"PetitPotam", "petitpotam", "tool"},
		{"secretsdump.py", "secretsdump", "tool"},
		{"GetNPUsers", "getnpusers", "tool"},
		{"GetUserSPNs", "getuserspns", "tool"},
		{"psexec.py", "psexec", "tool"},
		{"wmiexec.py", "wmiexec", "tool"},
		{"smbexec.py", "smbexec", "tool"},
		{"mssqlclient.py", "mssqlclient", "tool"},
		{"ticketer.py", "ticketer", "tool"},
		{"ntlmrelayx", "ntlmrelayx", "tool"},
		{"Rubeus", "rubeus", "tool"},
		{"SharpHound", "sharphound", "tool"},
		// Java / deserialization → "tool".
		{"ysoserial", "ysoserial", "tool"},
		{"marshalsec", "marshalsec", "tool"},
		// Web / product / CMS exploit + vuln scanners → "vuln-scanner".
		{"JexBoss/1.0", "jexboss", "vuln-scanner"},
		{"WeblogicScan", "weblogicscan", "vuln-scanner"},
		{"VBScan", "vbscan", "vuln-scanner"},
		{"Typo3Scan", "typo3scan", "vuln-scanner"},
		{"struts-scan", "struts-scan", "vuln-scanner"},
		{"tomcatWarDeployer", "tomcatwardeployer", "vuln-scanner"},
		{"Corsy/1.0", "corsy", "vuln-scanner"},
		{"smuggler", "smuggler", "vuln-scanner"},
		{"dontgo403", "dontgo403", "vuln-scanner"},
		{"nomore403", "nomore403", "vuln-scanner"},
		{"lfimap", "lfimap", "vuln-scanner"},
		{"fimap/1.0", "fimap", "vuln-scanner"},
		// TLS / SSL / IKE scanners → "vuln-scanner".
		{"sslscan", "sslscan", "vuln-scanner"},
		{"cipherscan", "cipherscan", "vuln-scanner"},
		{"a2sv", "a2sv", "vuln-scanner"},
		{"ike-scan/1.9", "ike-scan", "vuln-scanner"},
		// Subdomain / DNS / asset recon → "tool".
		{"gauplus", "gauplus", "tool"},
		{"waymore", "waymore", "tool"},
		{"urlfinder", "urlfinder", "tool"},
		{"findomain", "findomain", "tool"},
		{"knockpy", "knockpy", "tool"},
		{"zdns", "zdns", "tool"},
		{"dnsvalidator", "dnsvalidator", "tool"},
		{"Photon/1.3", "photon", "tool"},
		// JavaScript / endpoint discovery → "tool".
		{"LinkFinder", "linkfinder", "tool"},
		{"SecretFinder", "secretfinder", "tool"},
		{"getJS", "getjs", "tool"},
		{"xnLinkFinder", "xnlinkfinder", "tool"},
		{"crawley", "crawley", "tool"},
		// Secret / repo scrapers → "tool".
		{"noseyparker", "noseyparker", "tool"},
		{"GitDorker", "gitdorker", "tool"},
		{"DumpsterDiver", "dumpsterdiver", "tool"},
		// Cloud / k8s recon → "tool".
		{"Pacu", "pacu", "tool"},
		{"ScoutSuite", "scoutsuite", "tool"},
		{"prowler", "prowler", "tool"},
		{"S3Scanner", "s3scanner", "tool"},
		{"kube-hunter", "kube-hunter", "tool"},
		// Pivot / tunnel / relay → "tool".
		{"stowaway", "stowaway", "tool"},
		{"neo-reGeorg", "neo-regeorg", "tool"},
		{"reGeorg", "regeorg", "tool"},
		{"pivotnacci", "pivotnacci", "tool"},
		{"revsocks", "revsocks", "tool"},
		// Brute-force + phishing → "tool".
		{"crowbar", "crowbar", "tool"},
		{"BruteX", "brutex", "tool"},
		{"changeme", "changeme", "tool"},
		{"zphisher", "zphisher", "tool"},
		{"onesixtyone", "onesixtyone", "tool"},
		{"smtp-user-enum", "smtp-user-enum", "tool"},
		// DNS / HTTP C2 + webshells → highest-severity "c2".
		{"chashell", "chashell", "c2"},
		{"godoh", "godoh", "c2"},
		{"shad0w", "shad0w", "c2"},
		{"CALDERA", "caldera", "c2"},
		{"supershell", "supershell", "c2"},
		{"phpsploit", "phpsploit", "c2"},
		{"weevely", "weevely", "c2"},
	}
	if len(cases) != 75 {
		t.Fatalf("expected 75 new signatures in this batch, have %d", len(cases))
	}
	for _, c := range cases {
		v := IdentifyHTTP(HTTPSignals{Method: "GET", Path: "/", UserAgent: c.ua})
		ok := false
		for _, tl := range v.Tools {
			if tl == c.tool {
				ok = true
			}
		}
		if !ok {
			t.Errorf("UA %q: %q not identified (%v)", c.ua, c.tool, v.Tools)
		} else if v.Category != c.cat {
			t.Errorf("UA %q: category %q, want %q (tools %v)", c.ua, v.Category, c.cat, v.Tools)
		}
	}
}
