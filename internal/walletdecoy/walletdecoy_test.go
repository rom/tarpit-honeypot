package walletdecoy

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

const testSeed = "deployment-A"

func TestAllKindsGenerate(t *testing.T) {
	ws := All(testSeed)
	if len(ws) < 5 {
		t.Fatalf("want >=5 wallet kinds, got %d", len(ws))
	}
	seenKind := map[string]bool{}
	seenCanary := map[string]bool{}
	for _, w := range ws {
		if w.Kind == "" || w.Filename == "" || len(w.Content) == 0 || w.Canary == "" {
			t.Errorf("%s: incomplete wallet %+v", w.Kind, w)
		}
		if seenKind[w.Kind] {
			t.Errorf("duplicate kind %q", w.Kind)
		}
		seenKind[w.Kind] = true
		if seenCanary[w.Canary] {
			t.Errorf("%s: canary value collides with another wallet", w.Kind)
		}
		seenCanary[w.Canary] = true
	}
}

func TestDeterministic(t *testing.T) {
	a := All(testSeed)
	b := All(testSeed)
	for i := range a {
		if string(a[i].Content) != string(b[i].Content) || a[i].Canary != b[i].Canary {
			t.Errorf("%s: not deterministic for the same seed", a[i].Kind)
		}
	}
	// A different seed yields different content.
	c := All("deployment-B")
	if string(c[0].Content) == string(a[0].Content) {
		t.Error("different seeds produced identical content")
	}
}

// b58decode decodes a Bitcoin-base58 string back to bytes (for checksum checks).
func b58decode(s string) []byte {
	var num []byte // big-endian base-256 accumulator
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(b58, s[i])
		if v < 0 {
			return nil
		}
		// num = num*58 + v
		carry := v
		for j := len(num) - 1; j >= 0; j-- {
			acc := int(num[j])*58 + carry
			num[j] = byte(acc & 0xff)
			carry = acc >> 8
		}
		for carry > 0 {
			num = append([]byte{byte(carry & 0xff)}, num...)
			carry >>= 8
		}
	}
	// restore leading zero bytes for leading '1's
	for i := 0; i < len(s) && s[i] == '1'; i++ {
		num = append([]byte{0}, num...)
	}
	return num
}

func validBase58Check(s string) bool {
	raw := b58decode(s)
	if len(raw) < 5 {
		return false
	}
	payload, sum := raw[:len(raw)-4], raw[len(raw)-4:]
	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])
	for i := 0; i < 4; i++ {
		if h2[i] != sum[i] {
			return false
		}
	}
	return true
}

func TestBitcoinFormatsValid(t *testing.T) {
	// A P2PKH address and a WIF key must carry a valid base58check checksum.
	addr := btcP2PKH(testSeed, "x")
	if !strings.HasPrefix(addr, "1") || !validBase58Check(addr) {
		t.Errorf("P2PKH address not valid base58check: %s", addr)
	}
	wif := wifKey(testSeed, "x")
	if !(strings.HasPrefix(wif, "K") || strings.HasPrefix(wif, "L")) || !validBase58Check(wif) {
		t.Errorf("WIF key not valid base58check: %s", wif)
	}
}

func TestEthKeystoreValidJSON(t *testing.T) {
	w, _ := Generate("ethereum-keystore", testSeed)
	var ks struct {
		Address string `json:"address"`
		Version int    `json:"version"`
		Crypto  struct {
			Cipher string `json:"cipher"`
			KDF    string `json:"kdf"`
			MAC    string `json:"mac"`
		} `json:"crypto"`
	}
	if err := json.Unmarshal(w.Content, &ks); err != nil {
		t.Fatalf("keystore not valid JSON: %v", err)
	}
	if ks.Version != 3 || ks.Crypto.Cipher != "aes-128-ctr" || ks.Crypto.KDF != "scrypt" || len(ks.Address) != 40 {
		t.Errorf("keystore v3 fields wrong: %+v", ks)
	}
	if !strings.HasPrefix(w.Filename, "UTC--") {
		t.Errorf("keystore filename not UTC--...: %s", w.Filename)
	}
}

func TestSolanaKeypairValid(t *testing.T) {
	w, _ := Generate("solana-keypair", testSeed)
	var arr []int
	if err := json.Unmarshal(w.Content, &arr); err != nil {
		t.Fatalf("id.json not valid JSON array: %v", err)
	}
	if len(arr) != 64 {
		t.Errorf("solana keypair has %d bytes, want 64", len(arr))
	}
	for _, v := range arr {
		if v < 0 || v > 255 {
			t.Errorf("byte out of range: %d", v)
		}
	}
}

func TestBitcoinCoreMagic(t *testing.T) {
	w, _ := Generate("bitcoin-core", testSeed)
	// Berkeley DB metadata magic 0x00053162 (little-endian) at offset 12.
	if len(w.Content) < 16 || w.Content[12] != 0x62 || w.Content[13] != 0x31 || w.Content[14] != 0x05 || w.Content[15] != 0x00 {
		t.Errorf("wallet.dat missing Berkeley DB magic at offset 12")
	}
}

func TestMnemonicShapeAndVocab(t *testing.T) {
	vocab := map[string]bool{}
	for _, w := range bip39Words {
		vocab[w] = true
	}
	words := mnemonic(testSeed, "bip39", 24)
	if len(words) != 24 {
		t.Fatalf("want 24 words, got %d", len(words))
	}
	for _, w := range words {
		if !vocab[w] {
			t.Errorf("mnemonic word %q not in the BIP39 vocabulary", w)
		}
	}
}

func TestMoneroShape(t *testing.T) {
	w, _ := Generate("monero", testSeed)
	if !strings.HasPrefix(w.Canary, "4") || len(w.Canary) != 95 {
		t.Errorf("monero address shape wrong: %q (len %d)", w.Canary, len(w.Canary))
	}
}
