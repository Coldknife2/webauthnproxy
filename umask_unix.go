//go:build unix

package main

import "syscall"

// umaskRestrictive makes files created next (the admin socket) private from the start; the returned func restores the mask.
func umaskRestrictive() func() {
	old := syscall.Umask(0o177)
	return func() { syscall.Umask(old) }
}
