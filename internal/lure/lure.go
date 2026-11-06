// Package lure generates believable, structurally-correct secret/credential
// decoy files to seed honeypot loot (fake home dirs, served downloads, decoy
// mounts, agent bait). Attackers and agentic tooling grep for exactly these
// filenames — ~/.aws/credentials, id_rsa, .env, kubeconfig, service-account
// JSON — because they convert straight to access. Each lure is a convincing
// decoy whose headline value is a CANARY: if it later reappears in a captured
// auth attempt, it proves the loot was taken and acted on.
//
// Everything is deterministic in a per-deployment seed; nothing grants real
// access (the key material is random decoy bytes with the correct framing).
// Wallet files live in the sibling internal/walletdecoy package.
package lure

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Lure is one generated decoy credential file + its canary value.
type Lure struct {
	Kind     string
	Filename string
	MIME     string
	Content  []byte
	Canary   string // the headline secret to track
	Desc     string
}

// Kinds returns the supported lure kinds, sorted.
func Kinds() []string {
	out := make([]string, 0, len(generators))
	for k := range generators {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Generate builds one lure of the given kind, deterministic in seed.
func Generate(kind, seed string) (Lure, error) {
	g, ok := generators[kind]
	if !ok {
		return Lure{}, fmt.Errorf("lure: unknown kind %q", kind)
	}
	return g(seed), nil
}

// All generates one lure of every kind, deterministic in seed.
func All(seed string) []Lure {
	ks := Kinds()
	out := make([]Lure, 0, len(ks))
	for _, k := range ks {
		out = append(out, generators[k](seed))
	}
	return out
}

type genFunc func(seed string) Lure

var generators = map[string]genFunc{
	"aws-credentials":     genAWS,
	"ssh-private-key":     genSSHKey,
	"dotenv":              genDotenv,
	"kubeconfig":          genKubeconfig,
	"gcp-service-account": genGCPSA,
	"npmrc":               genNpmrc,
	"pypirc":              genPypirc,
	"git-credentials":     genGitCreds,
	"dockerconfig":        genDockerConfig,
	"pgpass":              genPgpass,
	"netrc":               genNetrc,
	"terraform-state":     genTFState,
	"jwt-token":           genJWT,
	"slack-token":         genSlack,
}

// derive returns n deterministic bytes from (seed,label).
func derive(seed, label string, n int) []byte {
	out := make([]byte, 0, n)
	var ctr uint32
	for len(out) < n {
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], ctr)
		h := sha256.Sum256([]byte("tarpit-lure\x00" + seed + "\x00" + label + "\x00" + string(c[:])))
		out = append(out, h[:]...)
		ctr++
	}
	return out[:n]
}
func dhex(seed, label string, n int) string { return hex.EncodeToString(derive(seed, label, n)) }
func db64(seed, label string, n int) string {
	return base64.StdEncoding.EncodeToString(derive(seed, label, n))
}

// b62 maps bytes to [A-Za-z0-9] — for AWS-key-shaped tokens.
func b62(seed, label string, n int) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := derive(seed, label, n)
	out := make([]byte, n)
	for i := range b {
		out[i] = a[int(b[i])%len(a)]
	}
	return string(out)
}

func genAWS(seed string) Lure {
	ak := "AKIA" + strings.ToUpper(b62(seed, "aws:ak", 16))
	sk := db64(seed, "aws:sk", 30) // 40-char base64 secret
	body := "[default]\naws_access_key_id = " + ak + "\naws_secret_access_key = " + sk +
		"\nregion = us-east-1\n\n[prod]\naws_access_key_id = AKIA" + strings.ToUpper(b62(seed, "aws:ak2", 16)) +
		"\naws_secret_access_key = " + db64(seed, "aws:sk2", 30) + "\n"
	return Lure{"aws-credentials", "credentials", "text/plain", []byte(body), ak, "AWS CLI credentials (~/.aws/credentials)"}
}

func genSSHKey(seed string) Lure {
	blob := db64(seed, "ssh:key", 1200)
	var b strings.Builder
	b.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for i := 0; i < len(blob); i += 70 {
		end := i + 70
		if end > len(blob) {
			end = len(blob)
		}
		b.WriteString(blob[i:end] + "\n")
	}
	b.WriteString("-----END OPENSSH PRIVATE KEY-----\n")
	return Lure{"ssh-private-key", "id_rsa", "text/plain", []byte(b.String()), blob[:32], "OpenSSH private key (id_rsa)"}
}

func genDotenv(seed string) Lure {
	dbURL := "postgres://app:" + b62(seed, "env:dbpw", 20) + "@db.internal:5432/app"
	body := "NODE_ENV=production\n" +
		"DATABASE_URL=" + dbURL + "\n" +
		"SECRET_KEY=" + dhex(seed, "env:secret", 32) + "\n" +
		"JWT_SECRET=" + dhex(seed, "env:jwt", 32) + "\n" +
		"STRIPE_SECRET_KEY=sk_live_" + b62(seed, "env:stripe", 24) + "\n" +
		"SENDGRID_API_KEY=SG." + b62(seed, "env:sg1", 22) + "." + b62(seed, "env:sg2", 43) + "\n" +
		"AWS_ACCESS_KEY_ID=AKIA" + strings.ToUpper(b62(seed, "env:ak", 16)) + "\n"
	return Lure{"dotenv", ".env", "text/plain", []byte(body), dbURL, "Application .env with DB URL + API keys"}
}

func genKubeconfig(seed string) Lure {
	tok := b62(seed, "k8s:tok", 40)
	body := "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443\n" +
		"    certificate-authority-data: " + db64(seed, "k8s:ca", 400) + "\n  name: prod\n" +
		"contexts:\n- context:\n    cluster: prod\n    user: admin\n  name: prod\ncurrent-context: prod\n" +
		"users:\n- name: admin\n  user:\n    token: " + tok + "\n"
	return Lure{"kubeconfig", "kubeconfig", "text/yaml", []byte(body), tok, "Kubernetes admin kubeconfig (bearer token)"}
}

func genGCPSA(seed string) Lure {
	pk := "-----BEGIN PRIVATE KEY-----\\n" + db64(seed, "gcp:pk", 1200) + "\\n-----END PRIVATE KEY-----\\n"
	id := dhex(seed, "gcp:keyid", 20)
	proj := "prod-" + b62(seed, "gcp:proj", 6)
	email := "svc-deploy@" + proj + ".iam.gserviceaccount.com"
	js := `{"type":"service_account","project_id":"` + proj + `","private_key_id":"` + id +
		`","private_key":"` + pk + `","client_email":"` + email +
		`","client_id":"` + dhex(seed, "gcp:cid", 10) + `","token_uri":"https://oauth2.googleapis.com/token"}`
	return Lure{"gcp-service-account", "service-account.json", "application/json", []byte(js), email, "GCP service-account key JSON"}
}

func genNpmrc(seed string) Lure {
	tok := "npm_" + b62(seed, "npm:tok", 36)
	body := "//registry.npmjs.org/:_authToken=" + tok + "\n" +
		"@acme:registry=https://npm.pkg.github.com\n//npm.pkg.github.com/:_authToken=ghp_" + b62(seed, "npm:ghp", 36) + "\n"
	return Lure{"npmrc", ".npmrc", "text/plain", []byte(body), tok, "npm registry auth token (.npmrc)"}
}

func genPypirc(seed string) Lure {
	tok := "pypi-" + b62(seed, "pypi:tok", 48)
	body := "[pypi]\n  username = __token__\n  password = " + tok + "\n"
	return Lure{"pypirc", ".pypirc", "text/plain", []byte(body), tok, "PyPI upload token (.pypirc)"}
}

func genGitCreds(seed string) Lure {
	tok := "ghp_" + b62(seed, "git:tok", 36)
	url := "https://acme-deploy:" + tok + "@github.com"
	body := url + "\nhttps://gitlab-ci-token:glpat-" + b62(seed, "git:gl", 20) + "@gitlab.com\n"
	return Lure{"git-credentials", ".git-credentials", "text/plain", []byte(body), tok, "Stored git credentials (GitHub/GitLab tokens)"}
}

func genDockerConfig(seed string) Lure {
	auth := base64.StdEncoding.EncodeToString([]byte("deploy:" + b62(seed, "dkr:pw", 24)))
	js := `{"auths":{"registry.acme.io":{"auth":"` + auth + `"},"https://index.docker.io/v1/":{"auth":"` +
		base64.StdEncoding.EncodeToString([]byte("acmebot:"+b62(seed, "dkr:pw2", 24))) + `"}}}`
	return Lure{"dockerconfig", ".dockerconfigjson", "application/json", []byte(js), auth, "Docker registry auth (config.json)"}
}

func genPgpass(seed string) Lure {
	pw := b62(seed, "pg:pw", 24)
	body := "db.internal:5432:app:app:" + pw + "\nreplica.internal:5432:*:postgres:" + b62(seed, "pg:pw2", 24) + "\n"
	return Lure{"pgpass", ".pgpass", "text/plain", []byte(body), pw, "PostgreSQL password file (.pgpass)"}
}

func genNetrc(seed string) Lure {
	pw := b62(seed, "netrc:pw", 24)
	body := "machine api.acme.io\n  login deploy\n  password " + pw + "\nmachine ftp.acme.io\n  login backup\n  password " + b62(seed, "netrc:pw2", 20) + "\n"
	return Lure{"netrc", ".netrc", "text/plain", []byte(body), pw, "Credentials file (.netrc)"}
}

func genTFState(seed string) Lure {
	pw := b62(seed, "tf:pw", 28)
	js := `{"version":4,"terraform_version":"1.8.0","serial":12,"lineage":"` + dhex(seed, "tf:lin", 16) +
		`","resources":[{"type":"aws_db_instance","name":"main","instances":[{"attributes":{"username":"admin","password":"` +
		pw + `","endpoint":"db.internal:5432"}}]}]}`
	return Lure{"terraform-state", "terraform.tfstate", "application/json", []byte(js), pw, "Terraform state with plaintext DB password"}
}

func genJWT(seed string) Lure {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"svc-admin","role":"admin","iss":"acme","exp":4102444800}`))
	sigv := base64.RawURLEncoding.EncodeToString(derive(seed, "jwt:sig", 32))
	jwt := hdr + "." + pl + "." + sigv
	body := "SERVICE_JWT=" + jwt + "\n"
	return Lure{"jwt-token", "service.jwt", "text/plain", []byte(body), jwt, "Service JWT (admin role)"}
}

func genSlack(seed string) Lure {
	tok := "xoxb-" + dec(seed, "slack:1", 12) + "-" + dec(seed, "slack:2", 12) + "-" + b62(seed, "slack:3", 24)
	hook := "https://hooks.slack.com/services/T" + strings.ToUpper(b62(seed, "slack:h1", 8)) + "/B" +
		strings.ToUpper(b62(seed, "slack:h2", 8)) + "/" + b62(seed, "slack:h3", 24)
	body := "SLACK_BOT_TOKEN=" + tok + "\nSLACK_WEBHOOK_URL=" + hook + "\n"
	return Lure{"slack-token", "slack.env", "text/plain", []byte(body), tok, "Slack bot token + incoming webhook"}
}

// dec returns n deterministic decimal digits.
func dec(seed, label string, n int) string {
	b := derive(seed, label, n)
	out := make([]byte, n)
	for i := range b {
		out[i] = byte('0' + b[i]%10)
	}
	return string(out)
}
