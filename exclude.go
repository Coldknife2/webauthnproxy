package main

import "github.com/go-webauthn/webauthn/protocol"

// excludeList prevents enrolling the same authenticator twice for a user.
func excludeList(u *User) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(u.Credentials))
	for i := range u.Credentials {
		out = append(out, u.Credentials[i].Descriptor())
	}
	return out
}
