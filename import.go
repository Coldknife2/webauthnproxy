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

// importFile est le format produit par l'outil d'enrôlement statique (web/tool.html).
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

// parseImport valide un fichier d'import et construit l'utilisateur et la passkey correspondants.
// authenticatorData contient la clé publique (COSE) et les drapeaux : tout est relu et vérifié ici,
// rien n'est pris sur parole (domaine, identifiant utilisateur, clé, vérification utilisateur).
func parseImport(raw []byte, rpID string, requireUV bool) (*User, *webauthn.Credential, error) {
	var f importFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, nil, fmt.Errorf("JSON invalide: %w", err)
	}
	if f.Version != importVersion {
		return nil, nil, fmt.Errorf("version %d non supportée", f.Version)
	}
	name := strings.TrimSpace(f.User.Name)
	if name == "" || len(name) > 64 || name != f.User.Name {
		return nil, nil, errors.New("nom d'utilisateur invalide (1 à 64 caractères, sans espaces autour)")
	}
	uid, err := b64.DecodeString(f.User.ID)
	if err != nil || string(uid) != string(userIDFor(name)) {
		return nil, nil, errors.New("identifiant utilisateur incohérent avec le nom")
	}
	credID, err := b64.DecodeString(f.Credential.ID)
	if err != nil || len(credID) == 0 {
		return nil, nil, errors.New("identifiant de passkey invalide")
	}
	ad, err := b64.DecodeString(f.Credential.AuthenticatorData)
	if err != nil {
		return nil, nil, errors.New("authenticatorData invalide")
	}
	var data protocol.AuthenticatorData
	if err := data.Unmarshal(ad); err != nil {
		return nil, nil, fmt.Errorf("authenticatorData illisible: %w", err)
	}
	want := sha256.Sum256([]byte(rpID))
	if string(data.RPIDHash) != string(want[:]) {
		return nil, nil, fmt.Errorf("la passkey n'a pas été créée pour le domaine %q (RP_ID du proxy)", rpID)
	}
	if !data.Flags.HasUserPresent() || !data.Flags.HasAttestedCredentialData() {
		return nil, nil, errors.New("authenticatorData ne contient pas de passkey")
	}
	if requireUV && !data.Flags.HasUserVerified() {
		return nil, nil, errors.New("vérification utilisateur absente (USER_VERIFICATION=required)")
	}
	if string(data.AttData.CredentialID) != string(credID) {
		return nil, nil, errors.New("identifiant de passkey incohérent avec authenticatorData")
	}
	if _, err := webauthncose.ParsePublicKey(data.AttData.CredentialPublicKey); err != nil {
		return nil, nil, fmt.Errorf("clé publique invalide: %w", err)
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

// importDir traite les fichiers *.json déposés dans dir : un fichier accepté est renommé en
// .imported, un fichier refusé en .rejected (la raison est dans les logs).
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
			log.Printf("import %s refusé: %v", e.Name(), err)
		} else {
			log.Printf("import %s: passkey ajoutée", e.Name())
		}
		if err := os.Rename(p, p+suffix); err != nil {
			log.Printf("import %s: renommage impossible: %v", e.Name(), err)
		}
	}
}

func importOne(store *Store, path, rpID string, requireUV bool) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Size() > maxImportSize {
		return errors.New("fichier trop volumineux")
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

// watchImports scrute le dossier d'import (démarrage puis toutes les 5 s).
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
