package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	importVersion = 1
	maxImportSize = 64 << 10
)

// importFile is the format produced by the static enrollment tool (web/tool.html).
type importFile struct {
	Version int    `json:"version"`
	RPID    string `json:"rpId"`
	User    struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"user"`
	Credential struct {
		ID                string   `json:"id"`
		AuthenticatorData string   `json:"authenticatorData"`
		Transports        []string `json:"transports"`
	} `json:"credential"`
}

// parseImport validates an import file and builds the matching user and passkey.
// authenticatorData carries the public key (COSE) and the flags: everything is re-read and
// verified here, nothing is taken on trust (domain, user ID, key, user verification).
func parseImport(raw []byte, rpID string, requireUV bool) (*User, *webauthn.Credential, error) {
	var f importFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if f.Version != importVersion {
		return nil, nil, fmt.Errorf("unsupported version %d", f.Version)
	}
	name := strings.TrimSpace(f.User.Name)
	if name == "" || len(name) > 64 || name != f.User.Name {
		return nil, nil, errors.New("invalid user name (1 to 64 characters, no surrounding spaces)")
	}
	uid, err := b64.DecodeString(f.User.ID)
	if err != nil || string(uid) != string(userIDFor(name)) {
		return nil, nil, errors.New("user ID inconsistent with the name")
	}
	credID, err := b64.DecodeString(f.Credential.ID)
	if err != nil || len(credID) == 0 {
		return nil, nil, errors.New("invalid passkey ID")
	}
	ad, err := b64.DecodeString(f.Credential.AuthenticatorData)
	if err != nil {
		return nil, nil, errors.New("invalid authenticatorData")
	}
	var data protocol.AuthenticatorData
	if err := data.Unmarshal(ad); err != nil {
		return nil, nil, fmt.Errorf("unreadable authenticatorData: %w", err)
	}
	want := sha256.Sum256([]byte(rpID))
	if string(data.RPIDHash) != string(want[:]) {
		return nil, nil, fmt.Errorf("the passkey was not created for domain %q (the proxy's RP_ID)", rpID)
	}
	if !data.Flags.HasUserPresent() || !data.Flags.HasAttestedCredentialData() {
		return nil, nil, errors.New("authenticatorData does not contain a passkey")
	}
	if requireUV && !data.Flags.HasUserVerified() {
		return nil, nil, errors.New("user verification missing (USER_VERIFICATION=required)")
	}
	if string(data.AttData.CredentialID) != string(credID) {
		return nil, nil, errors.New("passkey ID inconsistent with authenticatorData")
	}
	if _, err := webauthncose.ParsePublicKey(data.AttData.CredentialPublicKey); err != nil {
		return nil, nil, fmt.Errorf("invalid public key: %w", err)
	}
	var transports []protocol.AuthenticatorTransport
	for _, t := range f.Credential.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	cred := &webauthn.Credential{
		ID:              credID,
		PublicKey:       data.AttData.CredentialPublicKey,
		AttestationType: "none",
		Transport:       transports,
		Flags:           webauthn.NewCredentialFlags(data.Flags),
		Authenticator:   webauthn.Authenticator{AAGUID: data.AttData.AAGUID, SignCount: data.Counter},
	}
	return &User{ID: uid, Name: name}, cred, nil
}

// importDir processes the *.json files dropped into dir: an accepted file is renamed to
// .imported, a refused one to .rejected (the reason is in the logs).
func importDir(store *Store, dir, rpID string, requireUV bool) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		err := importOne(store, p, rpID, requireUV)
		suffix := ".imported"
		if err != nil {
			suffix = ".rejected"
			log.Printf("import %s rejected: %v", e.Name(), err)
		} else {
			log.Printf("import %s: passkey added", e.Name())
		}
		if err := os.Rename(p, p+suffix); err != nil {
			log.Printf("import %s: cannot rename: %v", e.Name(), err)
		}
	}
}

func importOne(store *Store, path, rpID string, requireUV bool) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Size() > maxImportSize {
		return errors.New("file too large")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	user, cred, err := parseImport(raw, rpID, requireUV)
	if err != nil {
		return err
	}
	return store.AddCredential(store.GetOrNew(user.Name), cred)
}

// watchImports polls the import folder (at startup, then every 5 s).
func watchImports(store *Store, dir, rpID string, requireUV bool) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	go func() {
		for {
			importDir(store, dir, rpID, requireUV)
			time.Sleep(5 * time.Second)
		}
	}()
	return nil
}
