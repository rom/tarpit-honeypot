// Package walletdecoy generates believable, structurally-correct cryptocurrency
// wallet files to seed a honeypot's filesystem (shell loot, served downloads,
// decoy mounts). Attackers and their automated/agentic tooling hunt for wallet
// files — wallet.dat, keystore JSON, seed phrases — because they convert
// directly to money, so a convincing decoy is strong bait: it attracts and
// occupies the attacker, and every value we hand out (address / key / mnemonic)
// is a canary — if it later reappears in captured traffic (an exfil, a reused
// credential, a blockchain lookup proxied through us) it is near-irrefutable
// proof the loot was taken and acted on.
//
// Everything is deterministic in a per-deployment seed, so a scanner re-observes
// the same wallets, and nothing here holds real funds: the files have the
// correct magic/field structure a tool fingerprints on, but the key material is
// random decoy bytes.
package walletdecoy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Wallet is one generated decoy file plus the canary value(s) worth tracking.
type Wallet struct {
	Kind     string // stable id, e.g. "ethereum-keystore"
	Filename string // the name it would have on disk
	MIME     string
	Content  []byte
	// Canary is the headline secret the file exposes (address / key / first
	// mnemonic word-run) — the value to register with the token tracker.
	Canary string
	// Desc is a one-line human description for the UI / docs.
	Desc string
}

// Kinds returns the supported decoy wallet kinds, sorted.
func Kinds() []string {
	out := make([]string, 0, len(generators))
	for k := range generators {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Generate builds one decoy wallet of the given kind, deterministic in seed.
func Generate(kind, seed string) (Wallet, error) {
	g, ok := generators[kind]
	if !ok {
		return Wallet{}, fmt.Errorf("walletdecoy: unknown kind %q", kind)
	}
	return g(seed), nil
}

// All generates one decoy of every kind, deterministic in seed.
func All(seed string) []Wallet {
	ks := Kinds()
	out := make([]Wallet, 0, len(ks))
	for _, k := range ks {
		out = append(out, generators[k](seed))
	}
	return out
}

type genFunc func(seed string) Wallet

var generators = map[string]genFunc{
	"bitcoin-core":      genBitcoinCore,
	"ethereum-keystore": genEthKeystore,
	"electrum":          genElectrum,
	"bip39-seed":        genBIP39Seed,
	"metamask-vault":    genMetaMaskVault,
	"monero":            genMonero,
	"wif-privkeys":      genWIFPrivKeys,
	"solana-keypair":    genSolanaKeypair,
	"paper-wallet":      genPaperWallet,
	"ledger-recovery":   genLedgerRecovery,
	"exodus":            genExodus,
}

// ---- deterministic byte derivation -----------------------------------------

// derive returns n deterministic bytes from (seed,label) by hashing with a
// counter, so every field is stable per deployment but unrelated across labels.
func derive(seed, label string, n int) []byte {
	out := make([]byte, 0, n)
	var ctr uint32
	for len(out) < n {
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], ctr)
		h := sha256.Sum256([]byte("tarpit-walletdecoy\x00" + seed + "\x00" + label + "\x00" + string(c[:])))
		out = append(out, h[:]...)
		ctr++
	}
	return out[:n]
}

func deriveHex(seed, label string, n int) string { return hex.EncodeToString(derive(seed, label, n)) }

// ---- base58 / base58check (Bitcoin alphabet) -------------------------------

const b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(b []byte) string {
	// count leading zero bytes → leading '1's
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	// base-256 → base-58 (big-int long division on a byte copy)
	in := append([]byte(nil), b...)
	var out []byte
	for start := zeros; start < len(in); {
		rem := 0
		for i := start; i < len(in); i++ {
			acc := rem*256 + int(in[i])
			in[i] = byte(acc / 58)
			rem = acc % 58
		}
		out = append(out, b58[rem])
		if in[start] == 0 {
			start++
		}
	}
	// reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	lead := strings.Repeat("1", zeros)
	return lead + string(out)
}

// base58Check appends the 4-byte double-SHA256 checksum and base58-encodes —
// the real Bitcoin address / WIF encoding, so the output passes a format check.
func base58Check(payload []byte) string {
	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])
	return base58Encode(append(append([]byte(nil), payload...), h2[:4]...))
}

// btcP2PKH builds a valid-format P2PKH address (version 0x00 → starts with "1").
func btcP2PKH(seed, label string) string {
	h160 := derive(seed, label+":h160", 20)
	return base58Check(append([]byte{0x00}, h160...))
}

// wifKey builds a valid-format compressed WIF private key (0x80 prefix, 0x01
// compression flag → starts with K or L).
func wifKey(seed, label string) string {
	k := derive(seed, label+":wif", 32)
	payload := append([]byte{0x80}, k...)
	payload = append(payload, 0x01)
	return base58Check(payload)
}

func ethAddress(seed, label string) string { return "0x" + deriveHex(seed, label+":eth", 20) }

// ---- generators ------------------------------------------------------------

// Bitcoin Core wallet.dat — a Berkeley DB (the on-disk format `file` reports as
// "Berkeley DB (Btree ...)"). We stamp the BDB magic + a btree page so a scanner
// that fingerprints wallet.dat sees a real one, with decoy key bytes embedded.
func genBitcoinCore(seed string) Wallet {
	buf := make([]byte, 0, 4096)
	page := make([]byte, 4096)
	// BDB metadata page: magic 0x00053162 at offset 12 (little-endian), btree.
	binary.LittleEndian.PutUint32(page[12:16], 0x00053162)
	binary.LittleEndian.PutUint32(page[16:20], 9)    // version
	binary.LittleEndian.PutUint32(page[20:24], 4096) // pagesize
	page[25] = 5                                     // btree type
	copy(page[32:], []byte("\x62\x31\x05\x00"))
	// Embed a believable BerkeleyDB "main" + a few key/value hints a wallet.dat
	// carries (so strings(1) on the file reveals wallet-ish markers + decoy keys).
	markers := "main\x00\x04key\x00" + wifKey(seed, "btc0") + "\x00\x04name\x00" +
		btcP2PKH(seed, "btc0") + "\x00defaultkey\x00" + deriveHex(seed, "btc:pub", 33) +
		"\x00minversion\x00\x00orderposnext\x00"
	copy(page[72:], markers)
	buf = append(buf, page...)
	buf = append(buf, derive(seed, "btc:bdb-pad", 4096)...) // a second (data) page
	return Wallet{
		Kind: "bitcoin-core", Filename: "wallet.dat", MIME: "application/octet-stream",
		Content: buf, Canary: btcP2PKH(seed, "btc0"),
		Desc: "Bitcoin Core wallet.dat (Berkeley DB) with a decoy default key/address",
	}
}

// Ethereum keystore v3 (the UTC--<ts>--<addr> JSON geth/web3 writes).
func genEthKeystore(seed string) Wallet {
	addr := deriveHex(seed, "ethks:addr", 20)
	iv := deriveHex(seed, "ethks:iv", 16)
	salt := deriveHex(seed, "ethks:salt", 32)
	ct := deriveHex(seed, "ethks:ct", 32)
	mac := deriveHex(seed, "ethks:mac", 32)
	uuid := uuidFrom(derive(seed, "ethks:uuid", 16))
	js := `{"address":"` + addr + `","crypto":{"cipher":"aes-128-ctr","ciphertext":"` + ct +
		`","cipherparams":{"iv":"` + iv + `"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"` + salt +
		`"},"mac":"` + mac + `"},"id":"` + uuid + `","version":3}`
	ts := time.Unix(0, 0).UTC().Format("2006-01-02T15-04-05.000000000Z")
	return Wallet{
		Kind: "ethereum-keystore", Filename: "UTC--" + ts + "--" + addr, MIME: "application/json",
		Content: []byte(js), Canary: "0x" + addr,
		Desc: "Ethereum/geth keystore v3 (scrypt) for a decoy account",
	}
}

// Electrum default_wallet (its JSON wallet-file format).
func genElectrum(seed string) Wallet {
	xprv := "xprv9s21ZrQH143K" + base58Pad(seed, "el:xprv", 95)
	xpub := "xpub661MyMwAqRbc" + base58Pad(seed, "el:xpub", 95)
	js := `{
    "addresses": {"change": [], "receiving": ["` + btcP2PKH(seed, "el0") + `", "` + btcP2PKH(seed, "el1") + `"]},
    "keystore": {
        "type": "bip32",
        "xprv": "` + xprv + `",
        "xpub": "` + xpub + `",
        "pw_hash_version": 1
    },
    "seed_version": 18,
    "use_encryption": false,
    "wallet_type": "standard"
}`
	return Wallet{
		Kind: "electrum", Filename: "default_wallet", MIME: "application/json",
		Content: []byte(js), Canary: xprv,
		Desc: "Electrum standard wallet (BIP32 xprv/xpub) with decoy addresses",
	}
}

// BIP39 mnemonic seed phrase file (24 words from the BIP39 English vocabulary).
func genBIP39Seed(seed string) Wallet {
	words := mnemonic(seed, "bip39", 24)
	body := "# wallet recovery — KEEP OFFLINE\n" + strings.Join(words, " ") + "\n\npassphrase: \nderivation: m/44'/0'/0'\n"
	return Wallet{
		Kind: "bip39-seed", Filename: "seed_phrase.txt", MIME: "text/plain",
		Content: []byte(body), Canary: strings.Join(words, " "),
		Desc: "24-word BIP39 recovery phrase",
	}
}

// MetaMask browser-extension vault (the {data,iv,salt} AES-GCM blob it stores).
func genMetaMaskVault(seed string) Wallet {
	b64 := func(label string, n int) string {
		return base64.StdEncoding.EncodeToString(derive(seed, "mm:"+label, n))
	}
	js := `{"data":"` + b64("data", 256) + `","iv":"` + b64("iv", 16) + `","salt":"` + b64("salt", 32) + `"}`
	return Wallet{
		Kind: "metamask-vault", Filename: "metamask-vault.json", MIME: "application/json",
		Content: []byte(js), Canary: b64("salt", 32),
		Desc: "MetaMask extension vault (encrypted {data,iv,salt})",
	}
}

// Monero wallet: the primary address (starts with 4) + a .keys blob.
func genMonero(seed string) Wallet {
	addr := moneroAddress(seed, "xmr")
	body := "address: " + addr + "\nview_key: " + deriveHex(seed, "xmr:view", 32) +
		"\nspend_key: " + deriveHex(seed, "xmr:spend", 32) + "\n"
	return Wallet{
		Kind: "monero", Filename: "monero.wallet.keys.txt", MIME: "text/plain",
		Content: []byte(body), Canary: addr,
		Desc: "Monero primary address + view/spend keys",
	}
}

// A list of WIF private keys with their addresses — the "exported keys" file.
func genWIFPrivKeys(seed string) Wallet {
	var b strings.Builder
	b.WriteString("# address,private_key(WIF)\n")
	for i := 0; i < 8; i++ {
		lbl := fmt.Sprintf("wif%d", i)
		b.WriteString(btcP2PKH(seed, lbl) + "," + wifKey(seed, lbl) + "\n")
	}
	return Wallet{
		Kind: "wif-privkeys", Filename: "private_keys.csv", MIME: "text/csv",
		Content: []byte(b.String()), Canary: wifKey(seed, "wif0"),
		Desc: "Exported Bitcoin private keys (WIF) with addresses",
	}
}

// Solana CLI keypair id.json — a JSON array of 64 bytes (secret+public).
func genSolanaKeypair(seed string) Wallet {
	kp := derive(seed, "sol:kp", 64)
	parts := make([]string, 64)
	for i, by := range kp {
		parts[i] = fmt.Sprintf("%d", by)
	}
	js := "[" + strings.Join(parts, ",") + "]"
	return Wallet{
		Kind: "solana-keypair", Filename: "id.json", MIME: "application/json",
		Content: []byte(js), Canary: base58Encode(kp[32:]),
		Desc: "Solana CLI keypair (id.json, 64-byte array)",
	}
}

// A paper wallet: a single address + its WIF, the classic printable backup.
func genPaperWallet(seed string) Wallet {
	addr := btcP2PKH(seed, "paper")
	wif := wifKey(seed, "paper")
	body := "BITCOIN PAPER WALLET\n====================\nDEPOSIT ADDRESS:\n  " + addr +
		"\n\nPRIVATE KEY (WIF) — KEEP SECRET:\n  " + wif + "\n\nBIP38: no\n"
	return Wallet{
		Kind: "paper-wallet", Filename: "paper_wallet.txt", MIME: "text/plain",
		Content: []byte(body), Canary: wif,
		Desc: "Bitcoin paper wallet (address + WIF private key)",
	}
}

// Ledger/Trezor-style recovery sheet (24 words).
func genLedgerRecovery(seed string) Wallet {
	words := mnemonic(seed, "ledger", 24)
	var b strings.Builder
	b.WriteString("RECOVERY SHEET — Ledger Nano\n")
	for i, w := range words {
		b.WriteString(fmt.Sprintf("%2d. %s\n", i+1, w))
	}
	return Wallet{
		Kind: "ledger-recovery", Filename: "recovery_sheet.txt", MIME: "text/plain",
		Content: []byte(b.String()), Canary: strings.Join(words, " "),
		Desc: "Hardware-wallet (Ledger) 24-word recovery sheet",
	}
}

// Exodus desktop wallet seed file (seed.seco-style opaque blob).
func genExodus(seed string) Wallet {
	blob := derive(seed, "exodus:seco", 512)
	content := append([]byte("SECO\x00\x01"), blob...)
	return Wallet{
		Kind: "exodus", Filename: "seed.seco", MIME: "application/octet-stream",
		Content: content, Canary: hex.EncodeToString(blob[:16]),
		Desc: "Exodus wallet encrypted seed (seed.seco)",
	}
}

// ---- helpers ---------------------------------------------------------------

func uuidFrom(b []byte) string {
	if len(b) < 16 {
		b = append(b, make([]byte, 16-len(b))...)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:16])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// base58Pad returns n base58 characters derived from (seed,label) — used to pad
// an xprv/xpub to its real length without implying a real key.
func base58Pad(seed, label string, n int) string {
	s := base58Encode(derive(seed, label, n))
	if len(s) >= n {
		return s[:n]
	}
	return s + strings.Repeat("1", n-len(s))
}

// moneroAddress returns a Monero-shaped primary address (starts with 4, ~95
// base58 chars) derived deterministically — correct shape, decoy bytes.
func moneroAddress(seed, label string) string {
	s := base58Encode(derive(seed, label+":addr", 69))
	s = "4" + strings.TrimLeft(s, "1")
	for len(s) < 95 {
		s += "A"
	}
	return s[:95]
}

// mnemonic returns n words drawn from the BIP39 English vocabulary (a curated
// subset — every word is a genuine BIP39 word, so each validates individually;
// a decoy phrase needs the right shape, not a valid overall checksum).
func mnemonic(seed, label string, n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		idx := binary.BigEndian.Uint32(derive(seed, fmt.Sprintf("%s:w%d", label, i), 4))
		out[i] = bip39Words[int(idx)%len(bip39Words)]
	}
	return out
}
