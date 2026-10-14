package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// authData construit un authenticatorData d'enregistrement avec une clé ES256 valide.
func authData(t *testing.T, rpID string, flags byte, credID []byte) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := k.X.FillBytes(make([]byte, 32)), k.Y.FillBytes(make([]byte, 32))
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	out = append(out, 0, 0, 0, 0)          // signCount
	out = append(out, make([]byte, 16)...) // AAGUID
	out = binary.BigEndian.AppendUint16(out, uint16(len(credID)))
	out = append(out, credID...)
	return append(out, cose...)
}

func importJSON(t *testing.T, name, rpID string, flags byte) []byte {
	t.Helper()
	cid := []byte("credential-id-1")
	f := importFile{Version: 1, RPID: rpID}
	f.User.Name, f.User.ID = name, b64.EncodeToString(userIDFor(name))
	f.Credential.ID = b64.EncodeToString(cid)
	f.Credential.AuthenticatorData = b64.EncodeToString(authData(t, rpID, flags, cid))
	f.Credential.Transports = []string{"internal"}
	b, _ := json.Marshal(f)
	return b
}

const flagsUPUVAT = 0x01 | 0x04 | 0x40 // UP | UV | AT

func TestParseImportOK(t *testing.T) {
	u, c, err := parseImport(importJSON(t, "remi", "example.com", flagsUPUVAT), "example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "remi" || string(c.ID) != "credential-id-1" || len(c.PublicKey) == 0 || !c.Flags.UserVerified {
		t.Fatalf("résultat inattendu: %+v %+v", u, c)
	}
}

func TestParseImportRejects(t *testing.T) {
	good := importJSON(t, "remi", "example.com", flagsUPUVAT)
	cases := map[string]struct {
		raw   []byte
		rpID  string
		reqUV bool
	}{
		"mauvais domaine":      {good, "autre.com", true},
		"sans UV exigée":       {importJSON(t, "remi", "example.com", 0x01|0x40), "example.com", true},
		"sans clé (pas de AT)": {importJSON(t, "remi", "example.com", 0x01|0x04), "example.com", true},
		"JSON invalide":        {[]byte("{"), "example.com", true},
	}
	for name, c := range cases {
		if _, _, err := parseImport(c.raw, c.rpID, c.reqUV); err == nil {
			t.Errorf("%s: accepté à tort", name)
		}
	}
	// identifiant utilisateur incohérent avec le nom
	var f importFile
	_ = json.Unmarshal(good, &f)
	f.User.Name = "autre"
	bad, _ := json.Marshal(f)
	if _, _, err := parseImport(bad, "example.com", true); err == nil {
		t.Error("identifiant utilisateur incohérent accepté")
	}
}

func TestImportDirRenamesAndDedups(t *testing.T) {
	dir, data := t.TempDir(), t.TempDir()
	store, _ := OpenStore(data)
	write := func(name string, b []byte) { _ = writeFile(dir+"/"+name, b) }
	write("a.json", importJSON(t, "remi", "example.com", flagsUPUVAT))
	write("b.json", importJSON(t, "remi", "example.com", flagsUPUVAT)) // même credential -> doublon
	write("c.json", []byte("pas du json"))
	importDir(store, dir, "example.com", true)
	if store.CredentialCount() != 1 {
		t.Fatalf("attendu 1 passkey, obtenu %d", store.CredentialCount())
	}
	for _, n := range []string{"a.json.imported", "b.json.rejected", "c.json.rejected"} {
		if !fileExists(dir + "/" + n) {
			t.Errorf("%s manquant", n)
		}
	}
}
