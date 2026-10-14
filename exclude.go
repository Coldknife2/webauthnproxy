package main

import "github.com/go-webauthn/webauthn/protocol"

// excludeList empêche d'enrôler deux fois le même authenticator pour un utilisateur.
func excludeList(u *User) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(u.Credentials))
	for i := range u.Credentials {
		out = append(out, u.Credentials[i].Descriptor())
	}
	return out
}
